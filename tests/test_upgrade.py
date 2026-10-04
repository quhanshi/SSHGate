from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import paramiko

from ssh_gate.config import Config,Server,load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.filesystem import operation
from ssh_gate.readonly import readonly_command
from ssh_gate.ssh import SSHRunner,RunResult,SSHSettings,build_remote_command
from ssh_gate.transfers import TransferStore,zip_members,MAX_TRANSFER_BYTES

class LocalSFTP:
    def __init__(self,root): self.root=Path(root)
    def normalize(self,p): return str((self.root/p if not p.startswith('/') else Path(p)).resolve())
    def stat(self,p): return paramiko.SFTPAttributes.from_stat(os.stat(p))
    def lstat(self,p): return paramiko.SFTPAttributes.from_stat(os.lstat(p))
    def open(self,p,mode):
        if 'x' in mode: mode='xb'
        return open(p,mode if 'b' in mode else mode+'b')
    def listdir_iter(self,p,read_aheads=2):
        for name in sorted(os.listdir(p)):
            a=self.lstat(str(Path(p)/name));a.filename=name;yield a
    def mkdir(self,p,mode=0o777): os.mkdir(p,mode)
    def chmod(self,p,mode): os.chmod(p,mode)
    def remove(self,p): os.unlink(p)
    def rename(self,a,b):
        if Path(b).exists(): raise FileExistsError(b)
        os.rename(a,b)
    def posix_rename(self,a,b): os.replace(a,b)

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.store=TransferStore(self.root);self.sftp=LocalSFTP(self.root)
        self.events=[]
    def op(self,kind,args,stop=None):
        return operation(self.sftp,SimpleNamespace(arguments=json.dumps(args),operation=kind,cwd=str(self.root),timeout_seconds=10),self.store,stop or threading.Event(),lambda **v:self.events.append(v))
    def stage(self,name,data):
        item=self.store.begin(name,len(data),hashlib.sha256(data).hexdigest())
        for offset in range(0,len(data),32768):
            chunk=data[offset:offset+32768];self.store.append(item['transfer_id'],offset,base64.b64encode(chunk).decode(),offset+len(chunk)==len(data))
        if not data:self.store.append(item['transfer_id'],0,'',True)
        return self.store.info(item['transfer_id'])
    @unittest.skipUnless(Path('/usr/bin/setsid').exists(), 'Linux tracked command wrapper')
    def test_tracked_wrapper_executes_exact_script_and_cleans_control_directory(self):
        token=os.urandom(16).hex()
        wrapper=build_remote_command("printf '%s\\n' 'literal $HOME'; pwd",str(self.root),3,token)
        result=subprocess.run(['/bin/sh','-c',wrapper],capture_output=True,text=True,timeout=8)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(['literal $HOME',str(self.root)],result.stdout.splitlines())
        self.assertFalse(Path('/tmp/wassh-'+token).exists())
    def test_new_readonly_parameter_rules(self):
        for c in ('find /tmp -maxdepth 3 -type f -name \'*.log\'','stat /tmp','du -sh /tmp','df -h','ps aux','ps -eo pid,ppid,cmd','free -h','uname -a','git status --short','git log --oneline -n 5','git diff --stat','docker ps -a','docker logs --tail 50 app','docker inspect app'):
            with self.subTest(c=c):self.assertTrue(readonly_command(c).allowed,c)
        for c in ('find /tmp -delete','find /tmp -exec touch x +','find /tmp -fprint /tmp/file','git diff --ext-diff','git log --show-signature','git -c core.pager=sh status','git reset --hard','docker restart app','docker cp a b','ls --unknown','ps --unknown','du --files0-from=x'):
            with self.subTest(c=c):self.assertFalse(readonly_command(c).allowed,c)
        self.assertIn('GIT_OPTIONAL_LOCKS=0',readonly_command('git status').executable_command)
        self.assertIn('--no-ext-diff --no-textconv',readonly_command('git diff').executable_command)
    def test_chunk_retry_and_integrity(self):
        data=b'abc'*12000;item=self.stage('payload.bin',data);tid=item['transfer_id']
        replay=self.store.append(tid,0,base64.b64encode(data[:32768]).decode())
        self.assertTrue(replay['complete'])
        with self.assertRaises(ValueError):self.store.append(tid,0,base64.b64encode(b'bad').decode())
        bad=self.store.begin('bad',3,'0'*64)
        with self.assertRaises(ValueError):self.store.append(bad['transfer_id'],0,'YWJj',True)
        with self.assertRaises(ValueError):self.store.info(bad['transfer_id'])
    def test_zero_upload_retry(self):
        item=self.stage('empty',b'')
        self.assertTrue(self.store.append(item['transfer_id'],0,'',True)['complete'])
    def test_completed_cache_survives_restart_without_replaying_approval(self):
        item=self.stage('persisted.bin',b'persist me')
        restored=TransferStore(self.root)
        self.assertEqual(item,restored.info(item['transfer_id']))
        self.assertEqual(b'persist me',restored.path(item['transfer_id'],complete=True).read_bytes())
        restored.remove(item['transfer_id'])
        self.assertEqual([],TransferStore(self.root).list())
    def test_incomplete_staging_is_removed_after_restart(self):
        item=self.store.begin('partial.bin',3,hashlib.sha256(b'abc').hexdigest())
        self.store.append(item['transfer_id'],0,'YQ==',False)
        restored=TransferStore(self.root)
        self.assertEqual([],restored.list());self.assertFalse((self.store.root/(item['transfer_id']+'.data')).exists())
    def test_transfer_limits_and_names(self):
        for name in ('../outside','C:secret','a/b','a\\b','..'):
            with self.assertRaises(ValueError):self.store.begin(name,1,'0'*64)
        with self.assertRaises(ValueError):self.store.begin('x',MAX_TRANSFER_BYTES+1,'0'*64)
        item=self.store.reserve_download('x')
        with self.assertRaises(ValueError):self.store.remove(item['transfer_id'])
    def test_fs_read_search_symlink_and_byte_offsets(self):
        (self.root/'a.log').write_bytes('中文abc'.encode());(self.root/'nested').mkdir();(self.root/'nested'/'data-evaluation').mkdir()
        (self.root/'link').symlink_to(self.root/'nested',target_is_directory=True)
        result=self.op('read_file',{'path':str(self.root/'a.log'),'offset':6,'limit':2})
        self.assertEqual('ab',result['text']);self.assertEqual(8,result['next_offset'])
        listing=self.op('list_directory',{'path':str(self.root),'offset':0,'limit':2})
        self.assertEqual(2,len(listing['entries']));self.assertTrue(listing['has_more'])
        result=self.op('find_files',{'path':str(self.root),'pattern':'*data-eval*','max_depth':4,'limit':100})
        self.assertEqual(1,len(result['matches']));self.assertFalse(result['follow_symlinks'])
    def test_download_and_upload_exact_binary(self):
        data=bytes(range(256))*500;(self.root/'original.bin').write_bytes(data)
        item=self.store.reserve_download('original.bin');tid=item['transfer_id']
        done=self.op('download_file',{'path':str(self.root/'original.bin'),'transfer_id':tid})
        self.assertEqual(hashlib.sha256(data).hexdigest(),done['sha256'])
        collected=b'';offset=0
        while True:
            chunk=self.store.read(tid,offset,10000);collected+=base64.b64decode(chunk['data_base64']);offset=chunk['next_offset']
            if chunk['eof']:break
        self.assertEqual(data,collected)
        up=self.stage('copy.bin',data);target=self.root/'uploaded.bin'
        self.op('upload_file',{'path':str(target),'transfer_id':up['transfer_id'],'overwrite':False})
        self.assertEqual(data,target.read_bytes());self.assertEqual(0o600,stat.S_IMODE(target.stat().st_mode))
        with self.assertRaises(ValueError):self.op('upload_file',{'path':str(target),'transfer_id':up['transfer_id'],'overwrite':False})
        self.op('upload_file',{'path':str(target),'transfer_id':up['transfer_id'],'overwrite':True})
        self.assertEqual(data,target.read_bytes())
    def test_upload_cancel_does_not_commit_or_leave_temporary_file(self):
        up=self.stage('x',b'abc');stop=threading.Event();stop.set();target=self.root/'should-not-exist'
        with self.assertRaises(InterruptedError):self.op('upload_file',{'path':str(target),'transfer_id':up['transfer_id']},stop)
        self.assertFalse(target.exists());self.assertFalse(list(self.root.glob('.wassh-*.part')))
    def test_zip_roundtrip_and_no_existing_directory_replacement(self):
        src=self.root/'src';src.mkdir();(src/'nested').mkdir();(src/'nested'/'a.txt').write_text('data');(src/'empty').mkdir();(src/'link').symlink_to(src/'nested')
        item=self.store.reserve_download('src.zip');down=self.op('download_directory',{'path':str(src),'transfer_id':item['transfer_id']})
        self.assertEqual(1,down['skipped_links_or_special_files'])
        up=self.stage('src.zip',self.store.path(item['transfer_id']).read_bytes())
        dest=self.root/'dest';done=self.op('upload_directory',{'path':str(dest),'transfer_id':up['transfer_id']})
        self.assertTrue(done['complete']);self.assertEqual('data',(dest/'nested'/'a.txt').read_text());self.assertTrue((dest/'empty').is_dir())
        with self.assertRaises(FileExistsError):self.op('upload_directory',{'path':str(dest),'transfer_id':up['transfer_id']})
    def test_zip_traversal_duplicate_and_link_refused(self):
        for name in ('../evil','/absolute','a/../../evil','C:/evil','a\\evil'):
            with self.subTest(name=name):
                buf=io.BytesIO()
                with zipfile.ZipFile(buf,'w') as z:z.writestr(name,b'evil')
                item=self.stage('bad.zip',buf.getvalue())
                with self.assertRaises(ValueError):zip_members(self.store.path(item['transfer_id']))
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            entry=zipfile.ZipInfo('link');entry.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(entry,b'/etc/passwd')
        item=self.stage('link.zip',buf.getvalue())
        with self.assertRaises(ValueError):zip_members(self.store.path(item['transfer_id']))
    def test_manager_operations_idempotency_upload_approval_and_cache_lease(self):
        cfg=Config(self.root,18765,600,300,4096,'',(Server('s','S','u@localhost',str(self.root)),),auto_allow_readonly=True)
        manager=ApprovalManager(cfg,runner=lambda *a:RunResult(0,result={'ok':True}));self.addCleanup(manager.close);manager.local_gui_heartbeat()
        item=manager.transfers.import_local(self._local_file('up.txt',b'abc'))
        args={'path':str(self.root/'target'),'transfer_id':item['transfer_id'],'overwrite':False}
        view=manager.submit_operation('s','upload_file',args,'write','key')
        self.assertEqual('pending_approval',view['status'])
        self.assertEqual(view['request_id'],manager.submit_operation('s','upload_file',args,'write','key')['request_id'])
        with self.assertRaises(ValueError):manager.transfers.remove(item['transfer_id'])
        manager.reject(view['request_id']);manager.transfers.remove(item['transfer_id'])
        down=manager.submit_operation('s','download_file',{'path':str(self.root/'up.txt')},'read','down')
        retry=manager.submit_operation('s','download_file',{'path':str(self.root/'up.txt')},'read','down')
        self.assertEqual(down['request_id'],retry['request_id'])
        with self.assertRaises(ValueError):manager.submit_operation('s','download_file',{'path':'/another'},'read','down')
    def _local_file(self,name,data):
        path=self.root/name;path.write_bytes(data);return path
    def test_parameter_validation_cannot_be_bypassed_by_direct_manager(self):
        cfg=Config(self.root,18765,600,300,4096,'',(Server('s','S','u@localhost'),))
        manager=ApprovalManager(cfg);self.addCleanup(manager.close);manager.local_gui_heartbeat()
        for op,args in [('read_file',{'path':'/tmp/a','limit':1000000}),('find_files',{'path':'/tmp','pattern':'*','max_depth':10000}),('list_directory',{'path':'/tmp','offset':-1}),('stat_path',{'path':'/tmp','arbitrary':'x'})]:
            with self.assertRaises(ValueError):manager.submit_operation('s',op,args,'test','bad')
    def test_incremental_unicode_cursors_and_running_termination(self):
        release=threading.Event();first=threading.Event()
        def run(payload,emit,stop):
            raw='中'.encode();emit('stdout',raw[:1]);first.set();release.wait(2);emit('stdout',raw[1:]);emit('stderr',b'error')
            stop.wait(2);return RunResult(None,disconnected=True,termination={'remote_group_terminated':True})
        cfg=Config(self.root,18765,600,300,4096,'',(Server('s','S','u@localhost'),))
        manager=ApprovalManager(cfg,runner=run);self.addCleanup(manager.close);manager.local_gui_heartbeat()
        view=manager.submit('s','sleep 10','test','unicode');manager.local_approve(view['request_id'],view['digest']);first.wait(1)
        self.assertEqual('',manager.read_output(view['request_id'])['stdout']);release.set()
        deadline=time.monotonic()+2
        while not manager.read_output(view['request_id'])['stdout'] and time.monotonic()<deadline:time.sleep(.01)
        page=manager.read_output(view['request_id'],0,0,1);self.assertEqual('中',page['stdout']);self.assertEqual('e',page['stderr'])
        next_page=manager.read_output(view['request_id'],page['next_stdout_cursor'],page['next_stderr_cursor'],10)
        self.assertEqual('',next_page['stdout']);self.assertEqual('rror',next_page['stderr'])
        manager.terminate(view['request_id']);manager.terminate(view['request_id'])
        self.wait_manager(manager,view['request_id'])
        self.assertEqual('terminated',manager.get(view['request_id'])['status'])
    @staticmethod
    def wait_manager(manager,rid):
        deadline=time.monotonic()+5
        while manager.get(rid)['status']=='running' and time.monotonic()<deadline:time.sleep(.01)
        return manager.get(rid)
    def test_sessions_approval_context_snapshot_and_revision(self):
        seen=[]
        def run(payload,emit,stop):
            seen.append(payload)
            return RunResult(0,result={'cwd':str(self.root)} if payload.operation!='command' else {})
        cfg=Config(self.root,18765,600,300,4096,'',(Server('s','S','u@localhost',str(self.root)),))
        manager=ApprovalManager(cfg,runner=run);self.addCleanup(manager.close);manager.local_gui_heartbeat()
        v=manager.create_session('s',str(self.root),{'NOTE':"literal $(touch NO)"},'session','create')
        self.assertEqual('pending_approval',v['status']);manager.local_approve(v['request_id'],v['digest']);done=self.wait_manager(manager,v['request_id']);sid=done['result']['session_id']
        view=manager.exec_in_session(sid,'printf "%s" "$NOTE"','show','exec')
        self.assertIn("export NOTE='literal $(touch NO)'",view['command'])
        manager.close_session(sid)
        manager.local_approve(view['request_id'],view['digest']);self.wait_manager(manager,view['request_id'])
        self.assertEqual(view['command'],seen[-1].command)
        with self.assertRaises(ValueError):manager.exec_in_session(sid,'pwd','bad','closed')
    def test_server_scoped_policy_and_tests_are_explicitly_trusted(self):
        path=self.root/'config.json';path.write_text(json.dumps({'auto_allow_readonly':True,'servers':[{'id':'s','label':'S','ssh_target':'u@localhost','default_cwd':'/allowed','auto_categories':['git_read','python_tests'],'auto_roots':['/allowed']}]}))
        manager=ApprovalManager(load_config(path),runner=lambda *a:RunResult(0));self.addCleanup(manager.close);manager.local_gui_heartbeat()
        for command,cwd,eligible in [('git status','/allowed',True),('git status','/outside',False),('cat /allowed/file','/allowed',False),('pytest -q tests','/allowed',True),('pytest ../outside','/allowed',False),('pytest --override-ini x=y','/allowed',False)]:
            view=manager.submit('s',command,'policy','id'+str(len(manager._requests)),cwd)
            self.assertEqual(eligible,view['readonly_eligible'])
        self.assertFalse(readonly_command('pytest -q').allowed)

# The following cancellation tests run actual shell children, including TERM-ignoring work.
class LocalCommandClient:
    def exec_command(self,command,timeout=8):
        result=subprocess.run(['/bin/sh','-c',command],capture_output=True,timeout=timeout)
        channel=SimpleNamespace(recv_exit_status=lambda:result.returncode,close=lambda:None)
        out=io.BytesIO(result.stdout);out.channel=channel
        return None,out,io.BytesIO(result.stderr)

@unittest.skipUnless(Path('/usr/bin/setsid').exists() and Path('/usr/bin/ps').exists(),'Linux process group tests')
class ProcessTerminationTests(unittest.TestCase):
    def setUp(self):
        if int(Path('/proc/self/stat').read_text().split()[0]) != os.getpid():
            self.skipTest('Execution sandbox PID namespace differs from /proc; run these two tests on a normal Linux host')
    def test_term_then_kill_stops_actual_child_group(self):
        token=os.urandom(16).hex();control=Path('/tmp/wassh-'+token)
        wrapper=build_remote_command("trap '' TERM; /bin/sh -c 'trap \\\"\\\" TERM; sleep 60' & wait",'/tmp',30,token)
        process=subprocess.Popen(['/bin/sh','-c',wrapper],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+3
            while not (control/'pid').exists() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue((control/'pid').exists())
            leader=int((control/'pid').read_text().split()[0]);self.assertEqual(leader,os.getpgid(leader))
            result=SSHRunner()._terminate_job(LocalCommandClient(),token)
            self.assertTrue(result['remote_group_terminated'],result)
            process.communicate(timeout=5)
            live=subprocess.run(['/usr/bin/ps','-eo','pgid=,stat='],capture_output=True,text=True).stdout.splitlines()
            self.assertFalse(any(line.split()[0]==str(leader) and not line.split()[1].startswith('Z') for line in live if line.split()))
        finally:
            if process.poll() is None:process.kill();process.communicate()
            shutil.rmtree(control,ignore_errors=True)
    def test_stale_pid_start_time_does_not_signal_unrelated_process(self):
        token=os.urandom(16).hex();control=Path('/tmp/wassh-'+token);control.mkdir()
        innocent=subprocess.Popen(['sleep','20'],start_new_session=True)
        try:
            (control/'pid').write_text(f'{innocent.pid} 0\n')
            result=SSHRunner()._terminate_job(LocalCommandClient(),token)
            self.assertFalse(result['remote_group_terminated']);self.assertEqual('stale',result['state']);self.assertIsNone(innocent.poll())
        finally:
            innocent.terminate();innocent.wait();shutil.rmtree(control)

if __name__=='__main__':unittest.main()
