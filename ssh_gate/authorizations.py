"""Bounded, in-memory grants. Only local approval or local policy can create authority."""
from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass

from .config import checked_text, integer
from .policies import python_test_command, scope_contains
from .readonly import FORBIDDEN, ReadOnlyDecision, readonly_command


READ_CAPABILITIES = frozenset({'read_fs', 'diagnostics', 'git_read', 'docker_read'})
CAPABILITIES = READ_CAPABILITIES | {'python_tests', 'git_deploy_pull', 'git_full', 'exact_commands'}
CAPABILITY_LABELS = {
    'read_fs': '文件读取', 'diagnostics': '系统诊断', 'git_read': 'Git 状态检查',
    'docker_read': 'Docker 状态检查', 'python_tests': '受信任 pytest',
    'git_deploy_pull': 'Git 部署拉取', 'git_full': '非 GitHub 仓库开发',
    'exact_commands': '固定命令执行',
}
GIT_PREFIX = ('exec /usr/bin/env GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_COUNT=0 '
              'GIT_CONFIG_NOSYSTEM=1 /usr/bin/git --no-pager '
              '-c core.fsmonitor=false -c core.hooksPath=/dev/null '
              '-c core.pager=cat -c log.showSignature=false')


def literal_argv(command: str) -> list[str]:
    checked_text(command, '固定命令')
    if len(command.encode('utf-8')) > 8192 or any(c in command for c in FORBIDDEN):
        raise ValueError('自动授权仅接受单条字面命令；管道、重定向、替换和多行脚本需逐次审批')
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError('命令引号不完整') from exc
    if not argv or '=' in argv[0] or not re.fullmatch(r'[A-Za-z0-9_./+-]+', argv[0]):
        raise ValueError('固定命令必须明确指定可执行文件，不接受环境赋值或 shell 包装')
    if '/' in argv[0] and not argv[0].startswith('/'):
        raise ValueError('可执行文件必须是系统命令名称或绝对路径')
    return argv


def git_argv(command: str) -> list[str] | None:
    try:
        argv = literal_argv(command)
    except ValueError:
        return None
    return argv[1:] if argv[0] in {'git', '/usr/bin/git', '/bin/git'} else None


def git_deployment_args(args: list[str], remote: str, branch: str) -> bool:
    return args in (['fetch', remote], ['pull', '--ff-only', remote, branch])


def git_workflow_args(args: list[str], remote: str) -> bool:
    """Ordinary repository work; destructive/global/exec/config modes remain per-call approval."""
    if not args or args[0] not in {'add', 'commit', 'push', 'branch', 'checkout', 'switch', 'merge', 'rebase', 'tag'}:
        return False
    if any(a in {'-f', '--force', '--force-with-lease', '--mirror', '--delete', '-D', '-d',
                 '-x', '--exec', '--config-env', '--output', '-o', '--amend', '-B', '--discard-changes'} or
           a.startswith(('--force=', '--force-with-lease=', '--exec=', '--output=',
                         '--git-dir', '--work-tree', '--config-env', '-x', '-f', '-D', '-d', '-B', '-o')) for a in args[1:]):
        return False
    if args[0] == 'rebase' and any(a.startswith('-') and not a.startswith('--') and 'x' in a[1:] for a in args[1:]):
        return False
    if args[0] == 'push':
        # Fixed registered remote; never accept an alternate URL or implicit destination.
        return len(args) >= 2 and args[1] == remote and all(
            re.fullmatch(r'[A-Za-z0-9_./:-]+', a) and not a.startswith(('-', '+')) for a in args[2:])
    return True


def grant_arguments(repo_path, capabilities, exact_commands, ttl_seconds, max_uses,
                    max_timeout_seconds, git_remote, git_branch) -> dict:
    path = checked_text(repo_path, '授权目录')
    if not path.startswith('/') or '..' in path.split('/') or len(path) > 4096:
        raise ValueError('授权目录必须是不含 .. 的绝对路径')
    if (not isinstance(capabilities, (list, tuple)) or not capabilities or
            len(capabilities) > len(CAPABILITIES) or any(not isinstance(c, str) or c not in CAPABILITIES for c in capabilities)):
        raise ValueError('请选择支持的授权能力')
    if not isinstance(exact_commands, (list, tuple)) or len(exact_commands) > 20:
        raise ValueError('固定命令最多 20 条')
    commands = list(exact_commands)
    if bool(commands) != ('exact_commands' in capabilities):
        raise ValueError('固定命令列表与 exact_commands 能力必须同时指定')
    for command in commands:
        argv = literal_argv(command)
        name = posixpath.basename(argv[0])
        if name in {'git', 'sudo', 'su', 'sh', 'bash', 'dash', 'zsh', 'fish', 'env',
                    'eval', 'exec', 'xargs', 'ssh', 'scp', 'sftp', 'rm', 'dd', 'mkfs', 'reboot', 'shutdown'}:
            raise ValueError('Git、提权、shell 包装、删除和系统关机命令需使用专门能力或逐次审批')
        if name.startswith('mkfs.') or (name.startswith(('python', 'node', 'perl', 'ruby')) and
                                       any(a.startswith(('-c', '-e', '--eval', '-p', '--print')) for a in argv[1:])):
            raise ValueError('内联程序执行需逐次审批')
    if sum(len(c.encode('utf-8')) for c in commands) > 32768:
        raise ValueError('固定命令总长度最多 32 KiB')
    integer(ttl_seconds, 1, 3600, '授权期限')
    integer(max_uses, 1, 100, '授权次数')
    integer(max_timeout_seconds, 1, 86400, '单次执行时限')
    if not isinstance(git_remote, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', git_remote):
        raise ValueError('Git 远端必须是已登记的名称')
    if (not isinstance(git_branch, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}', git_branch)
            or '..' in git_branch or git_branch.endswith(('/', '.')) or '//' in git_branch):
        raise ValueError('Git 分支名称无效')
    return {'repo_path': posixpath.normpath(path), 'capabilities': sorted(set(capabilities)),
            'exact_commands': commands, 'ttl_seconds': ttl_seconds, 'max_uses': max_uses,
            'max_timeout_seconds': max_timeout_seconds, 'git_remote': git_remote, 'git_branch': git_branch}


@dataclass
class Grant:
    id: str
    request_id: str
    server_id: str
    server_binding: str
    arguments: dict
    expires_monotonic: float
    uses: int = 0
    revoked: bool = False

    def available(self, now: float) -> bool:
        return not self.revoked and now < self.expires_monotonic and self.uses < self.arguments['max_uses']

    def view(self, now: float) -> dict:
        state = ('revoked' if self.revoked else 'expired' if now >= self.expires_monotonic else
                 'exhausted' if self.uses >= self.arguments['max_uses'] else 'granted')
        return {'grant_id': self.id, 'request_id': self.request_id, 'server_id': self.server_id,
                **self.arguments, 'status': state, 'remaining_uses': max(0, self.arguments['max_uses'] - self.uses),
                'expires_in_seconds': max(0, int(self.expires_monotonic - now)),
                'scope': 'current_sshgate_process'}

    def command_decision(self, command: str, cwd: str, timeout: int) -> ReadOnlyDecision:
        if not scope_contains(cwd, (self.arguments['repo_path'],)):
            raise ValueError('工作目录不在此授权范围内')
        if timeout > self.arguments['max_timeout_seconds']:
            raise ValueError('执行时限超过此授权的单次上限')
        caps = self.arguments['capabilities']
        decision = readonly_command(command)
        if decision.allowed and decision.category in caps:
            return decision
        if 'python_tests' in caps:
            decision = python_test_command(command)
            if decision.allowed:
                return decision
        args = git_argv(command)
        if args is not None:
            category = ('git_deploy_pull' if 'git_deploy_pull' in caps and git_deployment_args(
                args, self.arguments['git_remote'], self.arguments['git_branch']) else
                'git_full' if 'git_full' in caps and (git_workflow_args(args, self.arguments['git_remote']) or
                    git_deployment_args(args, self.arguments['git_remote'], self.arguments['git_branch'])) else '')
            if category:
                return ReadOnlyDecision(True, GIT_PREFIX + ' ' + shlex.join(args),
                                        '临时授权；执行前核验实际 Git 远端', category)
        if 'exact_commands' in caps and command in self.arguments['exact_commands']:
            argv = literal_argv(command)
            # Bare names resolve only against fixed system paths, without user PATH/aliases.
            executable = argv[0] if argv[0].startswith('/') else '/usr/bin/' + argv[0]
            return ReadOnlyDecision(True, 'exec ' + shlex.join([executable, *argv[1:]]),
                                    '本地批准的固定命令；程序及项目代码可能修改目录外资源', 'exact_commands')
        raise ValueError('命令或参数不匹配此授权；请逐次提交审批或申请新的明确范围')


def preauthorized(server, config, arguments: dict) -> bool:
    if ('manual_only' in server.auto_categories or not config.auto_allow_readonly
            or arguments['ttl_seconds'] > 1800 or arguments['max_uses'] > 50):
        return False
    if arguments['max_timeout_seconds'] > min(300, config.max_command_timeout_seconds):
        return False
    caps = set(arguments['capabilities'])
    allowed = set(server.auto_categories) if server.auto_categories else set(READ_CAPABILITIES)
    allowed |= set(server.auto_grant_capabilities)
    if not caps <= allowed or caps & {'git_full', 'exact_commands'}:
        return False
    if server.auto_roots and not scope_contains(arguments['repo_path'], server.auto_roots):
        return False
    if caps - READ_CAPABILITIES and not server.auto_roots:
        return False
    return 'git_deploy_pull' not in caps or (arguments['git_remote'], arguments['git_branch']) == ('origin', 'main')
