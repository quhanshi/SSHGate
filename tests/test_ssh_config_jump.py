from __future__ import annotations

import os
import json
import select
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import paramiko

from ssh_gate.config import Config, Server
from ssh_gate.ssh import SSHRunner, SSHSettings, resolve_settings, config_profiles
from ssh_gate.prompts import PromptCancelled
from test_ssh_login import SSHFixture, PasswordServer

SAMPLE = '''Host 181
 HostName jump.example
 Port 2201
 User jumpuser
 IdentityFile ~/.ssh/jump_key
 IdentitiesOnly yes
Host 10.208.88.202
 HostName 10.208.88.202
 Port 11135
 User quhanshi
 IdentityFile ~/.ssh/id_ed25519
 IdentitiesOnly yes
 ProxyJump 181
Host 10.208.88.201
 HostName 10.208.88.201
 Port 12138
 User quhanshi
 IdentityFile ~/.ssh/id_ed25519
 IdentitiesOnly yes
 ProxyJump 181
Host 10.208.88.201-Direct
 HostName 10.208.88.201
 Port 12138
 User quhanshi
 IdentityFile ~/.ssh/id_ed25519
 IdentitiesOnly yes
Host 10.208.88.190
 HostName 10.208.88.190
 Port 11135
 User zhangshaobo
 ProxyJump 181
'''

class SSHConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);(self.home/'.ssh').mkdir()
        self.path=self.home/'.ssh/config';self.path.write_text(SAMPLE)
        self.cfg=Config(self.home,18765,10,60,4096,'',())
        self.patch=patch('pathlib.Path.home',return_value=self.home);self.patch.start();self.addCleanup(self.patch.stop)
        original=os.path.expanduser
        expanded=patch('os.path.expanduser',side_effect=lambda v: str(self.home / v[2:]) if v.startswith('~/') else str(self.home) if v=='~' else original(v))
        expanded.start();self.addCleanup(expanded.stop)
    def resolve(self,target,**kwargs):return resolve_settings(self.cfg,Server('s','S',target,**kwargs))
    def test_user_sample_resolves_hop_and_preserves_direct_alias(self):
        for target,user,port in [('10.208.88.202','quhanshi',11135),('10.208.88.201','quhanshi',12138),('10.208.88.190','zhangshaobo',11135)]:
            with self.subTest(target=target):
                settings=self.resolve(target)
                self.assertEqual((target,user,port),(settings.hostname,settings.username,settings.port))
                hop,=settings.jump_hosts
                self.assertEqual(('181','jump.example','jumpuser',2201),(hop.host_alias,hop.hostname,hop.username,hop.port))
                self.assertEqual((str(self.home/'.ssh/jump_key'),),hop.identity_files)
                self.assertTrue(hop.identities_only);self.assertFalse(settings.proxy_command)
        direct=self.resolve('10.208.88.201-Direct')
        self.assertEqual('10.208.88.201',direct.hostname);self.assertEqual((),direct.jump_hosts)
        self.assertTrue(direct.identities_only)
    def test_include_and_first_value_defaults_and_profile_order(self):
        (self.home/'.ssh/hosts').mkdir();(self.home/'.ssh/hosts/one.conf').write_text(SAMPLE)
        self.path.write_text('Include hosts/*.conf\nHost * !excluded\n Port 9999\n User fallback\n')
        profiles=config_profiles()['profiles']
        self.assertEqual(['181','10.208.88.202','10.208.88.201','10.208.88.201-Direct','10.208.88.190'],[p['alias'] for p in profiles])
        self.assertEqual(12138,self.resolve('10.208.88.201').port)
        self.assertEqual(9999,self.resolve('unspecified').port)
        from ssh_gate.ssh_config import _config_words
        self.assertEqual([r'C:\Users\User Name\config.d\*.conf',r'C:\Users\plain\extra.conf'],_config_words(r'"C:\Users\User Name\config.d\*.conf" C:\Users\plain\extra.conf # comment',windows=True))
    def test_explicit_target_overrides_do_not_override_jump_credentials(self):
        settings=self.resolve('other@10.208.88.202',port=2323,identity_file=str(self.home/'chosen'))
        self.assertEqual(('other',2323,(str(self.home/'chosen'),)),(settings.username,settings.port,settings.identity_files))
        self.assertEqual(('jumpuser',2201),(settings.jump_hosts[0].username,settings.jump_hosts[0].port))
    def test_multiple_hops_and_nested_first_hop(self):
        self.path.write_text('Host a\n HostName first.example\nHost b\n HostName second.example\n ProxyJump a\nHost final\n ProxyJump b,worker@last:2222\n')
        settings=self.resolve('final')
        self.assertEqual(['a','b','last'],[n.host_alias for n in settings.jump_hosts])
        self.assertEqual(('worker',2222),(settings.jump_hosts[-1].username,settings.jump_hosts[-1].port))
    def test_ipv6_and_uri_jump(self):
        self.path.write_text('Host final\n ProxyJump user@[2001:db8::1]:2222,ssh://other@last:3333\n')
        settings=self.resolve('final')
        self.assertEqual(('2001:db8::1','user',2222),(settings.jump_hosts[0].hostname,settings.jump_hosts[0].username,settings.jump_hosts[0].port))
        self.assertEqual(('last','other',3333),(settings.jump_hosts[1].hostname,settings.jump_hosts[1].username,settings.jump_hosts[1].port))
    def test_jump_cycles_duplicates_and_include_cycles_refused(self):
        for text in ['Host a\n ProxyJump b\nHost b\n ProxyJump a\n','Host a\n ProxyJump b,b\n']:
            self.path.write_text(text)
            with self.assertRaisesRegex(ValueError,'循环|重复'):self.resolve('a')
        self.path.write_text('Include config\n')
        with self.assertRaisesRegex(ValueError,'循环'):config_profiles()
    def test_proxy_precedence_and_tokens(self):
        self.path.write_text('Host a\n HostName actual.example\n User user\n Port 2222\n ProxyCommand /usr/bin/proxy %h %p %r\n ProxyJump b\nHost b\n')
        settings=self.resolve('a')
        self.assertEqual('/usr/bin/proxy actual.example 2222 user',settings.proxy_command)
        self.assertEqual((),settings.jump_hosts)
        self.path.write_text('Host a\n ProxyJump none\n ProxyCommand /usr/bin/ignored\n')
        self.assertFalse(self.resolve('a').proxy_command)
    def test_empty_config_and_discovery_does_not_execute_match(self):
        self.path.write_text('Host listed\nMatch exec "touch should-not-exist"\n User ignored\n')
        self.assertEqual('listed',config_profiles()['profiles'][0]['alias'])
        with self.assertRaisesRegex(ValueError,'OpenSSH'):self.resolve('listed')
        self.path.unlink();self.assertFalse(config_profiles()['exists'])
        self.assertEqual('manual',self.resolve('user@manual').hostname)
    @unittest.skipUnless(shutil.which('ssh'), 'OpenSSH -G unavailable')
    def test_native_openssh_resolves_same_sample_and_include(self):
        from dataclasses import replace
        self.cfg=replace(self.cfg,ssh_executable=shutil.which('ssh'))
        included=self.home/'included hosts.conf';included.write_text(SAMPLE)
        self.path.write_text(f'Include "{included}"\nHost wildcard-*\n User globuser\n')
        settings=self.resolve('10.208.88.201')
        self.assertEqual(('quhanshi',12138),(settings.username,settings.port))
        self.assertEqual('jumpuser',settings.jump_hosts[0].username)
        self.assertTrue(settings.identities_only)
        self.assertEqual('globuser',self.resolve('wildcard-new').username)

class ForwardServer(PasswordServer):
    def __init__(self,fixture):super().__init__(fixture);self.destinations={}
    def check_auth_password(self,username,password):
        if username=='jumper' and password=='fixture-jump-password':
            self.fixture.authentications+=1;return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_channel_direct_tcpip_request(self,chanid,origin,destination):
        self.destinations[chanid]=destination;self.fixture.forwarded.append(destination)
        return paramiko.OPEN_SUCCEEDED
    def forward(self,channel):
        destination=self.destinations.get(channel.get_id())
        if not destination:channel.close();return
        def relay():
            peer=None
            try:
                peer=socket.create_connection(self.fixture.addresses.get(destination,destination),timeout=3)
                while not self.fixture.stop.is_set():
                    readable,_,_=select.select([peer,channel],[],[],.1)
                    if peer in readable:
                        data=peer.recv(65536)
                        if not data:break
                        channel.sendall(data)
                    if channel in readable:
                        data=channel.recv(65536)
                        if not data:break
                        peer.sendall(data)
            except (OSError,EOFError,paramiko.SSHException):pass
            finally:
                if peer:peer.close()
                channel.close()
        threading.Thread(target=relay,daemon=True).start()

class RoutedPrompts:
    def __init__(self,cancel_jump=False):self.calls=[];self.cancel_jump=cancel_jump
    def ask(self,kind,data,stop,timeout=120):
        self.calls.append((kind,dict(data)))
        if self.cancel_jump and data.get('role')=='jump':raise PromptCancelled('fixture cancel jump')
        if kind=='host_key':return 'save'
        return {'mode':'password','secret':'fixture-jump-password' if data['username']=='jumper' else 'fixture-only-password'}
    def close(self):pass

class JumpProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.known=str(Path(self.temp.name)/'known_hosts')
        self.target=SSHFixture();self.addCleanup(self.target.close)
        self.first=SSHFixture(ForwardServer);self.first.forwarded=[];self.first.addresses={};self.addCleanup(self.first.close)
        self.prompts=RoutedPrompts();self.runner=SSHRunner(self.prompts);self.addCleanup(self.runner.close)
    def settings(self,hops=None):
        first=SSHSettings('127.0.0.1','jumper',self.first.port,(),(self.known,),connection_id='route',host_alias='181')
        self.first.addresses[('internal-target.invalid',self.target.port)]=('127.0.0.1',self.target.port)
        return SSHSettings('internal-target.invalid','fixture',self.target.port,(),(self.known,),connection_id='route',host_alias='target',jump_hosts=tuple(hops or [first]))
    def run_command(self,settings):
        payload=SimpleNamespace(ssh_settings=settings,remote_command='pwd',timeout_seconds=3)
        events=[];out=[]
        result=self.runner.execute(payload,lambda n,b:out.append((n,b)),threading.Event(),lambda **v:events.append(v))
        return result,events,out
    def test_password_hop_and_target_forward_and_reuse_without_local_target_dns(self):
        settings=self.settings();original=socket.getaddrinfo
        def local_dns(host,*args,**kwargs):
            if host=='internal-target.invalid':raise AssertionError('Target DNS must occur at jump host')
            return original(host,*args,**kwargs)
        with patch('socket.getaddrinfo',side_effect=local_dns):
            one,events,out=self.run_command(settings);two,reused,_=self.run_command(settings)
        self.assertEqual(0,one.exit_code,one.error);self.assertEqual(0,two.exit_code,two.error)
        self.assertEqual(['jumper','fixture'],[d['username'] for k,d in self.prompts.calls if k=='credentials'])
        self.assertEqual(['jump','target'],[d['role'] for k,d in self.prompts.calls if k=='host_key'])
        self.assertEqual(1,self.first.authentications);self.assertEqual(1,self.target.authentications)
        self.assertEqual([],self.first.commands);self.assertEqual(['pwd','pwd'],self.target.commands)
        self.assertIn('opening_jump_channel',[e.get('phase') for e in events])
        trace=[e for e in events if 'connection_event' in e]
        connected=[e for e in trace if e['connection_event']['event']=='connected']
        self.assertEqual(['jump','target'],[e['connection_context']['role'] for e in connected])
        self.assertEqual([1,2],[e['connection_context']['hop_index'] for e in connected])
        target_trace=[e['connection_event']['event'] for e in trace if e['connection_context']['role']=='target']
        self.assertIn('jump_channel_opened',target_trace)
        self.assertNotIn('dns_started',target_trace)
        self.assertNotIn('tcp_connected',target_trace)
        reuse_events=[e['connection_event']['event'] for e in reused if 'connection_event' in e]
        self.assertEqual(2,reuse_events.count('connection_reused'))
        self.assertNotIn('ssh_handshake_started',reuse_events)
        self.assertNotIn('fixture-jump-password',json.dumps(trace))
        self.assertIn(('internal-target.invalid',self.target.port),self.first.forwarded)
        self.assertTrue(any('完成'.encode() in b for n,b in out))
        self.assertNotIn('fixture-jump-password',Path(self.known).read_text())
        self.runner.close_connection('route')
        self.assertFalse(self.runner.connection_states())
    def test_two_hop_forwarding_with_independent_authentication(self):
        second=SSHFixture(ForwardServer);second.forwarded=[];second.addresses={};self.addCleanup(second.close)
        settings=self.settings()
        second.addresses[('internal-target.invalid',self.target.port)]=('127.0.0.1',self.target.port)
        node=SSHSettings('127.0.0.1','jumper',second.port,(),(self.known,),connection_id='route',host_alias='second')
        from dataclasses import replace
        settings=replace(settings,jump_hosts=(*settings.jump_hosts,node))
        result,events,_=self.run_command(settings)
        self.assertEqual(0,result.exit_code,result.error);self.assertEqual(1,second.authentications)
        self.assertEqual(['181','second','target'],[d['host_alias'] for k,d in self.prompts.calls if k=='credentials'])
        self.assertEqual(['pwd'],self.target.commands);self.assertFalse(second.commands)
    def test_cancelled_jump_never_authenticates_or_executes_target(self):
        self.prompts.cancel_jump=True
        result,_,_=self.run_command(self.settings())
        self.assertTrue(result.disconnected);self.assertFalse(self.target.authentications);self.assertFalse(self.target.commands)
        self.assertIn('181',result.error)
    def test_target_cancellation_does_not_report_jump_as_target_connected(self):
        original=self.prompts.ask
        def ask(kind,data,stop,timeout=120):
            if kind=='credentials' and data.get('role')=='target':raise PromptCancelled('cancel target')
            return original(kind,data,stop,timeout)
        self.prompts.ask=ask
        result,events,_=self.run_command(self.settings())
        self.assertTrue(result.disconnected);self.assertEqual(1,self.first.authentications)
        self.assertFalse(self.runner.connection_states().get('route',False))
        self.assertFalse(self.target.authentications);self.assertFalse(self.target.commands)
        trace=[e for e in events if 'connection_event' in e]
        self.assertEqual('target',trace[-1]['connection_context']['role'])
        self.assertEqual('connection_cancelled',trace[-1]['connection_event']['event'])
        self.assertFalse(any(e['connection_context']['role']=='target' and
                             e['connection_event']['event']=='connected' for e in trace))

    def test_wrong_jump_fingerprint_never_prompts_password_or_contacts_target(self):
        key=paramiko.RSAKey.generate(2048)
        Path(self.known).write_text(f'[127.0.0.1]:{self.first.port} {key.get_name()} {key.get_base64()}\n')
        result,_,_=self.run_command(self.settings())
        self.assertIn('指纹',result.error);self.assertIn('181',result.error)
        self.assertFalse(self.prompts.calls);self.assertFalse(self.target.authentications)

class IdentitiesOnlyProtocolTests(unittest.TestCase):
    def test_unconfigured_agent_key_is_not_offered_to_server(self):
        accepted=[]
        class KeyServer(PasswordServer):
            def get_allowed_auths(self,username):return 'publickey,password'
            def check_auth_publickey(self,username,key):
                accepted.append(key.asbytes());return paramiko.AUTH_SUCCESSFUL
        fixture=SSHFixture(KeyServer);self.addCleanup(fixture.close)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);allowed=paramiko.RSAKey.generate(2048);unrelated=paramiko.RSAKey.generate(2048)
            pub=root/'configured.pub';pub.write_text(allowed.get_name()+' '+allowed.get_base64())
            class Agent:
                def get_keys(self):return [unrelated,allowed]
                def close(self):pass
            settings=SSHSettings('127.0.0.1','fixture',fixture.port,(str(pub),),(str(root/'known_hosts'),),identities_only=True)
            runner=SSHRunner(RoutedPrompts());self.addCleanup(runner.close)
            payload=SimpleNamespace(ssh_settings=settings,remote_command='pwd',timeout_seconds=3)
            with patch('paramiko.client.Agent',Agent):
                result=runner(payload,lambda *a:None,threading.Event())
            self.assertEqual(0,result.exit_code,result.error)
            self.assertEqual([allowed.asbytes()],accepted)

    def test_encrypted_configured_private_key_prompts_for_local_passphrase(self):
        offered=[]
        class KeyServer(PasswordServer):
            def get_allowed_auths(self,username):return 'publickey,password'
            def check_auth_publickey(self,username,key):
                offered.append(key.asbytes());return paramiko.AUTH_SUCCESSFUL
        fixture=SSHFixture(KeyServer);self.addCleanup(fixture.close)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);key=paramiko.RSAKey.generate(2048);filename=root/'private'
            key.write_private_key_file(str(filename),password='fixture-key-passphrase')
            class Prompts(RoutedPrompts):
                def ask(self,kind,data,stop,timeout=120):
                    if kind=='credentials':
                        self.calls.append((kind,dict(data)))
                        return {'mode':'passphrase','secret':'fixture-key-passphrase'}
                    return super().ask(kind,data,stop,timeout)
            prompts=Prompts();runner=SSHRunner(prompts);self.addCleanup(runner.close)
            settings=SSHSettings('127.0.0.1','fixture',fixture.port,(str(filename),),(str(root/'known_hosts'),),identities_only=True)
            payload=SimpleNamespace(ssh_settings=settings,remote_command='pwd',timeout_seconds=3)
            events=[]
            result=runner.execute(payload,lambda *a:None,threading.Event(),lambda **v:events.append(v))
            self.assertEqual(0,result.exit_code,result.error);self.assertEqual([key.asbytes()],offered)
            self.assertEqual(1,sum(k=='credentials' for k,d in prompts.calls))
            trace=[e['connection_event'] for e in events if 'connection_event' in e]
            self.assertEqual('publickey',trace[-1]['data']['auth_method'])
            self.assertNotIn('fixture-key-passphrase',json.dumps(trace))

if __name__=='__main__':unittest.main()
