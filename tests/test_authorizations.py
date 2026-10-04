from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from ssh_gate.authorizations import grant_arguments, git_workflow_args
from ssh_gate.config import Config, Server, load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.ssh import RunResult
from ssh_gate.readonly import scoped_read_paths


class AuthorizationTests(unittest.TestCase):
    def test_path_options_and_recursive_links_cannot_bypass_scoped_reads(self):
        self.assertEqual(['/etc/patterns', 'file.log'], scoped_read_paths('grep --file=/etc/patterns file.log'))
        self.assertEqual(['/etc/patterns', 'file.log'], scoped_read_paths('grep -if/etc/patterns file.log'))
        self.assertEqual(['file.log'], scoped_read_paths('grep -e pattern file.log'))
        self.assertEqual(['file.log'], scoped_read_paths('grep pattern file.log'))
        self.assertEqual(['/outside'], scoped_read_paths('find -P /outside -name x'))
        self.assertEqual(['.', '/outside/ref'], scoped_read_paths('find . -newer /outside/ref'))
        for command in ['find -L .', 'find -H .', 'grep -iR pattern .', 'du -L .', 'du --dereference-args .']:
            with self.subTest(command=command), self.assertRaises(ValueError):
                scoped_read_paths(command)
        for args in [['rebase', '-xecho'], ['rebase', '-ixecho'], ['rebase', '--exec=echo'],
                     ['branch', '-Dfeature'], ['checkout', '-Bfeature'], ['push', 'origin', '+main']]:
            self.assertFalse(git_workflow_args(args, 'origin'))

    def test_execution_checks_authority_again_after_opening_the_channel(self):
        from types import SimpleNamespace
        from ssh_gate.ssh import SSHRunner
        calls = []; opened = [False]
        channel = SimpleNamespace(settimeout=lambda _: None, close=lambda: None,
                                  exec_command=lambda command: calls.append(command))
        def open_channel(**_):
            opened[0] = True
            return channel
        client = SimpleNamespace(get_transport=lambda: SimpleNamespace(open_session=open_channel))
        runner = SSHRunner()
        runner._connect = lambda *_: client
        def authorize(_):
            if opened[0]: raise ValueError('grant revoked during channel opening')
        runner.execution_authorizer = authorize
        payload = SimpleNamespace(command='pwd', operation='command', policy_roots=(),
                                  ssh_settings=SimpleNamespace(hostname='fixture'), remote_command='pwd')
        result = runner.execute(payload, lambda *_: None, threading.Event(), lambda **_: None)
        self.assertIn('grant revoked', result.error)
        self.assertFalse(calls)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = Config(self.root, 18765, 60, 3600, 4096, '',
                             (Server('s', 'Test', 'u@host.example', '/srv/project'),), auto_allow_readonly=True)
        (self.root / 'config.json').write_text(json.dumps({'servers': [{'id': 's', 'ssh_target': 'u@host.example',
                                                                       'default_cwd': '/srv/project'}]}))
        self.clock = [0.0]
        self.calls = []
        self.release = threading.Event()
        self.release.set()
        def runner(payload, emit, stop):
            self.calls.append(payload)
            while not self.release.wait(.01):
                if stop.is_set():
                    return RunResult(None, disconnected=True)
            return RunResult(0)
        self.manager = ApprovalManager(self.config, runner=runner, clock=lambda: self.clock[0])
        self.addCleanup(self.manager.close)
        self.manager.local_gui_heartbeat()

    def request(self, capabilities=None, commands=None, key='grant', **kwargs):
        return self.manager.request_auto_approval('s', '/srv/project', capabilities or ['exact_commands'],
            'Run project checks', key, exact_commands=commands if commands is not None else ['printf hello'], **kwargs)

    def approve(self, proposal):
        request = self.manager.get(proposal['request_id'])
        self.manager.local_approve(request['request_id'], request['digest'])
        return self.manager.get_auto_approval_status(request['request_id'])['authorization']['grant_id']

    def wait(self, view):
        deadline = time.monotonic() + 2
        while self.manager.get(view['request_id'])['status'] == 'running' and time.monotonic() < deadline:
            time.sleep(.005)
        return self.manager.get(view['request_id'])

    def test_application_is_not_execution_and_needs_local_approval(self):
        proposal = self.request()
        self.assertEqual('pending_approval', proposal['status'])
        self.assertFalse(self.calls)
        grant = self.approve(proposal)
        self.assertEqual('granted', self.manager.get_auto_approval_status(proposal['request_id'])['status'])
        self.assertFalse(self.calls)
        with self.assertRaises(ValueError):
            self.approve(proposal)
        self.assertIn(grant, self.manager.grants)

    def test_read_scope_is_preapproved_but_tests_are_not_implicit(self):
        result = self.request(['read_fs'], [], key='reads')
        self.assertEqual('granted', result['status'])
        tests = self.request(['python_tests'], [], key='tests')
        self.assertEqual('pending_approval', tests['status'])
        self.assertFalse(self.calls)

    def test_local_preauthorization_has_directory_time_count_and_branch_bounds(self):
        server = replace(self.config.servers[0], auto_roots=('/srv/project',),
                         auto_grant_capabilities=('git_deploy_pull', 'python_tests'))
        self.manager.config = replace(self.config, servers=(server,))
        self.assertEqual('granted', self.request(['git_deploy_pull'], [], key='deploy')['status'])
        self.assertEqual('pending_approval', self.request(['git_deploy_pull'], [], key='other-branch', git_branch='feature')['status'])
        self.assertEqual('pending_approval', self.request(['python_tests'], [], key='long', ttl_seconds=1801)['status'])
        self.assertEqual('pending_approval', self.request(['python_tests'], [], key='many', max_uses=51)['status'])
        self.assertEqual('pending_approval', self.manager.request_auto_approval('s', '/srv/other', ['python_tests'],
            'test', 'outside')['status'])
        self.manager.config = replace(self.manager.config, servers=(replace(server, auto_categories=('manual_only',)),))
        self.assertEqual('pending_approval', self.request(['git_deploy_pull'], [], key='manual-only')['status'])

    def test_exact_commands_are_frozen_and_retries_do_not_spend_twice(self):
        grant = self.approve(self.request(max_uses=1))
        view = self.manager.submit('s', 'printf hello', 'test', 'one', '/srv/project', grant_id=grant)
        self.assertEqual('succeeded', self.wait(view)['status'])
        again = self.manager.submit('s', 'printf hello', 'test', 'one', '/srv/project', grant_id=grant)
        self.assertEqual(view['request_id'], again['request_id'])
        self.assertEqual(1, len(self.calls))
        self.assertEqual(1, self.manager.grants[grant].uses)
        with self.assertRaises(ValueError):
            self.manager.submit('s', 'printf hello', 'test', 'two', '/srv/project', grant_id=grant)
        self.assertEqual('exhausted', self.manager.list_auto_approvals()['authorizations'][0]['status'])

    def test_changed_command_path_timeout_or_target_does_not_execute(self):
        grant = self.approve(self.request())
        for command, cwd, timeout in [('printf hello world', '/srv/project', 300),
                                      ('printf hello', '/srv/project-other', 300),
                                      ('printf hello', '/srv/project', 301)]:
            with self.subTest(command=command, cwd=cwd, timeout=timeout), self.assertRaises(ValueError):
                self.manager.submit('s', command, 'test', 'bad', cwd, timeout, grant_id=grant)
        self.manager.config = replace(self.config, servers=(*self.config.servers, Server('other', 'Other', 'u@host.example')))
        with self.assertRaises(ValueError):
            self.manager.submit('other', 'printf hello', 'test', 'wrong-server', '/srv/project', grant_id=grant)
        self.assertFalse(self.calls)

    def test_retries_cannot_change_parameters(self):
        first = self.request()
        self.assertEqual(first['request_id'], self.request()['request_id'])
        with self.assertRaises(ValueError):
            self.request(commands=['printf changed'])
        grant = self.approve(first)
        view = self.manager.submit('s', 'printf hello', 'test', 'command', '/srv/project', grant_id=grant)
        self.wait(view)
        with self.assertRaises(ValueError):
            self.manager.submit('s', 'printf hello', 'changed reason', 'command', '/srv/project', grant_id=grant)

    def test_grant_expires_and_request_approval_is_at_most_one_minute(self):
        grant = self.approve(self.request(ttl_seconds=2))
        self.clock[0] = 2
        with self.assertRaises(ValueError):
            self.manager.submit('s', 'printf hello', 'test', 'expired', '/srv/project', grant_id=grant)
        self.manager.local_gui_heartbeat()
        self.manager.config = replace(self.config, approval_timeout_seconds=600)
        pending = self.request(key='expiry')
        self.assertLessEqual(pending['approval_expires_in_seconds'], 60)
        self.clock[0] += 60
        self.manager.local_gui_heartbeat()
        self.assertEqual('expired', self.manager.get_auto_approval_status(pending['request_id'])['status'])
        with self.assertRaises(ValueError):
            self.approve(pending)

    def test_revocation_cancels_queued_authorized_work(self):
        grant = self.approve(self.request(max_uses=2))
        self.release.clear()
        first = self.manager.submit('s', 'printf hello', 'test', 'first', '/srv/project', grant_id=grant)
        deadline = time.monotonic() + 1
        while not self.calls and time.monotonic() < deadline:
            time.sleep(.005)
        second = self.manager.submit('s', 'printf hello', 'test', 'second', '/srv/project', grant_id=grant)
        self.assertEqual('queued_authorized', second['status'])
        self.manager.revoke_auto_approval(grant)
        self.release.set()
        self.wait(first)
        self.assertEqual('denied', self.manager.get(second['request_id'])['status'])
        self.assertEqual(1, len(self.calls))
        with self.assertRaises(ValueError):
            self.manager.submit('s', 'printf hello', 'test', 'third', '/srv/project', grant_id=grant)

    def test_queue_rechecks_expiry_before_execution(self):
        grant = self.approve(self.request(ttl_seconds=2))
        self.release.clear()
        first = self.manager.submit('s', 'printf hello', 'test', 'first', '/srv/project', grant_id=grant)
        deadline = time.monotonic() + 1
        while not self.calls and time.monotonic() < deadline:
            time.sleep(.005)
        second = self.manager.submit('s', 'printf hello', 'test', 'second', '/srv/project', grant_id=grant)
        self.clock[0] = 2
        self.manager.local_gui_heartbeat()
        self.release.set()
        self.wait(first)
        deadline = time.monotonic() + 1
        while self.manager.get(second['request_id'])['status'] == 'queued_authorized' and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual('denied', self.manager.get(second['request_id'])['status'])
        self.assertLessEqual(len(self.calls), 1)

    def test_server_changes_and_switch_off_revoke_authority(self):
        grant = self.approve(self.request())
        self.manager.config = replace(self.config, servers=(replace(self.config.servers[0], ssh_target='u@changed.example'),))
        with self.assertRaises(ValueError):
            self.manager.submit('s', 'printf hello', 'test', 'changed', '/srv/project', grant_id=grant)
        self.manager.config = self.config
        self.manager.local_set_readonly(False)
        self.assertTrue(self.manager.grants[grant].revoked)

    def test_audit_failure_cannot_grant_authority(self):
        proposal = self.request()
        self.manager.audit_path.unlink()
        self.manager.audit_path.mkdir()
        with self.assertRaises(OSError):
            self.approve(proposal)
        self.assertFalse(self.manager.grants)

    def test_restart_does_not_recover_grants(self):
        grant = self.approve(self.request())
        replacement = ApprovalManager(self.config, runner=lambda *a: self.fail('must not run'))
        self.addCleanup(replacement.close)
        replacement.local_gui_heartbeat()
        with self.assertRaises(ValueError):
            replacement.submit('s', 'printf hello', 'test', 'old', '/srv/project', grant_id=grant)

    def test_shell_wrappers_inline_programs_and_git_are_not_exact_grants(self):
        for command in ['printf ok; rm x', 'printf ok | cat', 'printf $(id)', 'bash -c pwd',
                        'sudo ls', 'rm -rf /srv/project', 'python -c print(1)', 'git push origin main']:
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.request(commands=[command])

    def test_authorized_tests_and_git_parameters_are_bounded(self):
        grant = self.approve(self.request(['python_tests', 'git_deploy_pull'], []))
        for command in ['pytest -q tests', 'git fetch origin', 'git pull --ff-only origin main']:
            self.assertTrue(self.manager.grants[grant].command_decision(command, '/srv/project', 300).allowed)
        for command in ['pytest /etc', 'git pull origin main', 'git pull --ff-only origin other', 'git push origin main']:
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.manager.grants[grant].command_decision(command, '/srv/project', 300)

    def test_legacy_long_approval_config_is_capped(self):
        path = self.root / 'config.json'
        data = json.loads(path.read_text())
        data['approval_timeout_seconds'] = 600
        data['servers'][0]['github_hosts'] = ['GitHub.Corp.Example.']
        path.write_text(json.dumps(data))
        self.assertEqual(60, load_config(path).approval_timeout_seconds)
        self.assertEqual(('github.corp.example',), load_config(path).server('s').github_hosts)


if __name__ == '__main__':
    unittest.main()
