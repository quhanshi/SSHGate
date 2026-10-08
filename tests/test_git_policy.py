from __future__ import annotations

import io
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from ssh_gate.git_policy import (capture, check_git_command, inspect_repository,
                                 provider_for_urls, ssh_aliases, validate_git_operation)


def context(provider='github', remote_provider=None):
    return {'repo_path': '/srv/project', 'provider': provider,
            'remotes': [{'name': 'origin', 'provider': remote_provider or provider, 'hosts': []}]}


class GitPolicyTests(unittest.TestCase):
    def test_provider_uses_host_not_substring_or_credentials(self):
        self.assertEqual('github', provider_for_urls(['git@github.com:owner/repo.git'])[0])
        self.assertEqual('github', provider_for_urls(['https://user:secret@github.com/owner/repo.git'])[0])
        self.assertEqual('other', provider_for_urls(['https://github.com.evil.example/owner/repo'])[0])
        self.assertEqual('other', provider_for_urls(['https://gitee.com/owner/github.com'])[0])
        self.assertEqual('github', provider_for_urls(['git@corp-github:o/r'], {'*': ''}, ['corp-github'])[0])
        self.assertEqual('unknown', provider_for_urls(['ext::evil command'])[0])
        self.assertEqual('unknown', provider_for_urls(['/tmp/local.git'])[0])

    def test_ssh_alias_enterprise_and_mixed_remotes(self):
        aliases = ssh_aliases('Host github-work\n HostName github.com\n')
        self.assertEqual('github', provider_for_urls(['git@github-work:owner/repo'], aliases)[0])
        self.assertEqual('github', provider_for_urls(['https://github.company.example/o/r'], github_hosts=('github.company.example',))[0])
        self.assertEqual('github', provider_for_urls(['https://company.ghe.com/o/r'])[0])
        self.assertEqual('mixed', provider_for_urls(['https://github.com/o/r', 'https://gitee.com/o/r'])[0])
        self.assertEqual('unknown', provider_for_urls(['git@unresolved-alias:o/r'])[0])

    def test_github_deployment_only_even_after_local_approval(self):
        for command in ['git status', 'git log --oneline', 'git diff --stat', 'git fetch origin',
                        'git pull --ff-only origin main']:
            validate_git_operation(command, context(), '')
        for command in ['git push origin main', 'git commit -m message', 'git reset --hard',
                        'git checkout feature', 'git pull origin main', 'git config user.name name', 'git stash']:
            with self.subTest(command=command), self.assertRaises(ValueError):
                validate_git_operation(command, context(), '')

    def test_non_github_workflow_and_unknown_fail_closed(self):
        validate_git_operation('git commit -m message', context('other'), 'git_full')
        for provider in ['github', 'unknown', 'mixed']:
            with self.subTest(provider=provider), self.assertRaises(ValueError):
                validate_git_operation('git push origin main', context(provider), 'git_full')
        with self.assertRaises(ValueError):
            validate_git_operation('git fetch origin', context('mixed', 'mixed'), '')

    def test_locally_approved_git_is_not_blocked_by_mixed_remotes(self):
        for command in ("git worktree repair /srv/moved",
                        "git push github feature",
                        "git -C /srv/moved worktree list"):
            self.assertEqual(
                "locally_approved",
                check_git_command(None, None, command, "/srv/project",
                                  threading.Event(), category="git_manual")["workflow"])

    def test_alternate_git_binary_global_options_and_shell_wrappers_are_rejected(self):
        for command in ['/tmp/git push origin main', 'git -C /other push origin main',
                        'git -c alias.x=push x', 'git status && git push origin main']:
            with self.subTest(command=command), self.assertRaises(ValueError):
                check_git_command(None, None, command, '/srv/project', threading.Event())


class LocalChannel:
    """SSH-shaped channel that only executes the fixed inspection script on a local fixture repo."""
    def exec_command(self, script):
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, timeout=10)
        self.out, self.err, self.code = result.stdout, result.stderr, result.returncode
    def shutdown_write(self): pass
    def recv_ready(self): return bool(self.out)
    def recv_stderr_ready(self): return bool(self.err)
    def recv(self, count):
        data, self.out = self.out[:count], self.out[count:]
        return data
    def recv_stderr(self, count):
        data, self.err = self.err[:count], self.err[count:]
        return data
    def exit_status_ready(self): return True
    def recv_exit_status(self): return self.code
    def close(self): pass


class GitInspectionTests(unittest.TestCase):
    def test_effective_url_rewrites_push_urls_and_ssh_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            def config(key, value):
                subprocess.run(['git', '-C', str(root), 'config', key, value], check=True)
            config('remote.origin.url', 'short:owner/repo.git')
            config('url.https://github.com/.insteadOf', 'short:')
            class Client:
                def get_transport(self): return self
                def open_session(self, timeout): return LocalChannel()
            class SFTP:
                def normalize(self, path): return str(root)
                def open(self, path, mode): return io.BytesIO(b'Host enterprise-alias\n HostName github.company.example\n')
            result = inspect_repository(Client(), SFTP(), str(root), threading.Event())
            self.assertEqual('github', result['provider'])
            self.assertEqual(str(root), result['repo_path'])
            self.assertNotIn('secret', json.dumps(result))
            config('remote.origin.pushurl', 'git@enterprise-alias:owner/repo.git')
            result = inspect_repository(Client(), SFTP(), str(root), threading.Event(), ('github.company.example',))
            self.assertEqual('github', result['provider'])
            config('remote.origin.pushurl', 'https://gitee.com/owner/repo.git')
            result = inspect_repository(Client(), SFTP(), str(root), threading.Event())
            self.assertEqual('mixed', result['provider'])
            with self.assertRaises(ValueError):
                validate_git_operation('git push origin main', result, 'git_full')

    def test_capture_bounds_output(self):
        class Client:
            def get_transport(self): return self
            def open_session(self, timeout): return LocalChannel()
        with self.assertRaises(ValueError):
            capture(Client(), 'printf 12345', threading.Event(), limit=4)


if __name__ == '__main__':
    unittest.main()
