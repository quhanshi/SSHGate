"""Real loopback SSH/SFTP protocol, isolated local directories and fixture-only credentials."""
from __future__ import annotations
import errno
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
import json
import paramiko
from ssh_gate.ssh import SSHRunner,SSHSettings
from ssh_gate.transfers import TransferStore

class FixturePrompts:
    def ask(self,kind,data,stop,timeout=120):
        return 'once' if kind=='host_key' else {'secret':'sftp-fixture-password','mode':'password'}
    def close(self): pass

class Auth(paramiko.ServerInterface):
    def get_allowed_auths(self,user): return 'password'
    def check_auth_password(self,user,password):
        return paramiko.AUTH_SUCCESSFUL if user=='fixture' and password=='sftp-fixture-password' else paramiko.AUTH_FAILED
    def check_channel_request(self,kind,chanid):return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class FileServer(paramiko.SFTPServerInterface):
    def __init__(self,server,*args,root,**kwargs):super().__init__(server,*args,**kwargs);self.root=root
    def canonicalize(self,path):return os.path.realpath(os.path.join(self.root,path) if not path.startswith('/') else path)
    def checked(self,path):
        full=os.path.abspath(os.path.join(self.root,path) if not path.startswith('/') else path)
        if os.path.commonpath([full,self.root])!=self.root:raise PermissionError(errno.EACCES,'fixture path outside root')
        return full
    def list_folder(self,path):
        try:
            p=self.checked(path);rows=[]
            for name in os.listdir(p):
                a=paramiko.SFTPAttributes.from_stat(os.lstat(os.path.join(p,name)));a.filename=name;rows.append(a)
            return rows
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def stat(self,path):
        try:return paramiko.SFTPAttributes.from_stat(os.stat(self.checked(path)))
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def lstat(self,path):
        try:return paramiko.SFTPAttributes.from_stat(os.lstat(self.checked(path)))
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def open(self,path,flags,attr):
        try:
            full=self.checked(path);fd=os.open(full,flags,0o600)
            mode='r+b' if flags & os.O_RDWR else 'wb' if flags & os.O_WRONLY else 'rb'
            f=os.fdopen(fd,mode);handle=paramiko.SFTPHandle(flags)
            if flags & os.O_RDWR:handle.readfile=handle.writefile=f
            elif flags & os.O_WRONLY:handle.writefile=f
            else:handle.readfile=f
            return handle
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def mkdir(self,path,attr):
        try:os.mkdir(self.checked(path),attr.st_mode or 0o777);return paramiko.SFTP_OK
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def remove(self,path):
        try:os.unlink(self.checked(path));return paramiko.SFTP_OK
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def rename(self,a,b):
        try:
            if os.path.exists(self.checked(b)):return paramiko.SFTP_FAILURE
            os.rename(self.checked(a),self.checked(b));return paramiko.SFTP_OK
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def posix_rename(self,a,b):
        try:os.replace(self.checked(a),self.checked(b));return paramiko.SFTP_OK
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)
    def chattr(self,path,attr):
        try:
            if attr.st_mode is not None:os.chmod(self.checked(path),attr.st_mode)
            return paramiko.SFTP_OK
        except OSError as e:return paramiko.SFTPServer.convert_errno(e.errno)

class SFTPProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.remote=self.root/'remote';self.remote.mkdir()
        self.stop=threading.Event();self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(5);self.listener.settimeout(.2)
        self.key=paramiko.RSAKey.generate(2048);self.transports=[];self.channels=[]
        self.port=self.listener.getsockname()[1]
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
        known=self.root/'known_hosts';known.write_text(f'[127.0.0.1]:{self.port} {self.key.get_name()} {self.key.get_base64()}\n')
        self.settings=SSHSettings('127.0.0.1','fixture',self.port,(),(str(known),),connection_id='fixture')
        self.runner=SSHRunner(FixturePrompts());self.store=TransferStore(self.root);self.runner.transfers=self.store;self.phases=[]
    def serve(self):
        while not self.stop.is_set():
            try:conn,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            t=paramiko.Transport(conn);t.add_server_key(self.key);self.transports.append(t)
            t.set_subsystem_handler('sftp',paramiko.SFTPServer,FileServer,root=str(self.remote))
            def handle(t=t):
                try:
                    t.start_server(server=Auth())
                    while t.is_active() and not self.stop.is_set():
                        c=t.accept(.2)
                        if c:self.channels.append(c)
                except (EOFError,OSError,paramiko.SSHException):pass
            threading.Thread(target=handle,daemon=True).start()
    def tearDown(self):
        self.runner.close();self.stop.set();self.listener.close()
        for t in self.transports:t.close()
        self.thread.join(2);self.tmp.cleanup()
    def run_operation(self,kind,args,roots=()):
        payload=SimpleNamespace(ssh_settings=self.settings,job_token='',operation=kind,arguments=json.dumps(args),cwd=str(self.remote),timeout_seconds=10,policy_roots=roots)
        return self.runner.execute(payload,lambda *a:None,threading.Event(),lambda **v:self.phases.append(v))
    def test_real_sftp_directory_read_download_upload_and_connection_phases(self):
        data=bytes(range(256))*100;(self.remote/'source.bin').write_bytes(data)
        result=self.run_operation('list_directory',{'path':str(self.remote),'limit':20,'offset':0})
        self.assertEqual(0,result.exit_code,result.error);self.assertEqual('source.bin',result.result['entries'][0]['name'])
        phases=[p['phase'] for p in self.phases if 'phase' in p]
        for phase in ['resolving_dns','connecting_tcp','handshaking_ssh','authenticating','opening_sftp','executing']:self.assertIn(phase,phases)
        result=self.run_operation('read_file',{'path':str(self.remote/'source.bin'),'offset':256,'limit':100})
        self.assertEqual(0,result.exit_code,result.error);self.assertEqual(356,result.result['next_offset'])
        item=self.store.reserve_download('source.bin');result=self.run_operation('download_file',{'path':str(self.remote/'source.bin'),'transfer_id':item['transfer_id']})
        self.assertEqual(0,result.exit_code,result.error);self.assertEqual(data,self.store.path(item['transfer_id']).read_bytes())
        local=self.root/'copy.bin';local.write_bytes(data);up=self.store.import_local(local)
        result=self.run_operation('upload_file',{'path':str(self.remote/'copy.bin'),'transfer_id':up['transfer_id'],'overwrite':False})
        self.assertEqual(0,result.exit_code,result.error);self.assertEqual(data,(self.remote/'copy.bin').read_bytes())
        retry=self.run_operation('upload_file',{'path':str(self.remote/'copy.bin'),'transfer_id':up['transfer_id'],'overwrite':False})
        self.assertIsNone(retry.exit_code);self.assertIn('目标已存在',retry.error)
        result=self.run_operation('upload_file',{'path':str(self.remote/'copy.bin'),'transfer_id':up['transfer_id'],'overwrite':True})
        self.assertEqual(0,result.exit_code,result.error)
    def test_default_cwd_failure_reports_diagnostic_phase(self):
        result=self.run_operation('test_connection',{'path':str(self.remote/'missing')})
        self.assertIsNone(result.exit_code);self.assertIn('checking_default_cwd',result.error)
    def test_auto_policy_resolves_symlink_before_read(self):
        outside=self.root/'outside';outside.write_text('private');(self.remote/'link').symlink_to(outside)
        result=self.run_operation('read_file',{'path':str(self.remote/'link')},roots=(str(self.remote),))
        self.assertIsNone(result.exit_code);self.assertIn('不在本地自动授权范围',result.error)

if __name__=='__main__':unittest.main()
