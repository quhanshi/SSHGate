"""Bounded, in-memory grants. Only local approval or local policy can create authority."""
from __future__ import annotations

import ntpath
import posixpath
import re
import shlex
from dataclasses import dataclass

from .config import checked_text, integer
from .policies import python_test_command, scope_contains
from .readonly import FORBIDDEN, ReadOnlyDecision, readonly_command
from .winpath import ps_quote, windows_path, within


READ_CAPABILITIES = frozenset({'read_fs', 'diagnostics', 'git_read', 'docker_read'})
CAPABILITIES = READ_CAPABILITIES | {'python_tests', 'git_deploy_pull', 'git_full', 'exact_commands', 'command_patterns'}
CAPABILITY_LABELS = {
    'read_fs': '文件读取', 'diagnostics': '系统诊断', 'git_read': 'Git 状态检查',
    'docker_read': 'Docker 状态检查', 'python_tests': '受信任 pytest',
    'git_deploy_pull': 'Git 部署拉取', 'git_full': '非 GitHub 仓库开发',
    'exact_commands': '固定命令执行', 'command_patterns': '命令模式执行',
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


BLOCKED_PROGRAMS = {'git', 'sudo', 'su', 'sh', 'bash', 'dash', 'zsh', 'fish', 'env', 'eval', 'exec', 'xargs',
                    'ssh', 'scp', 'sftp', 'rm', 'dd', 'mkfs', 'reboot', 'shutdown'}
# Their arguments are another command: with a wildcard they would admit anything.
WRAPPER_PROGRAMS = {'nohup', 'timeout', 'nice', 'ionice', 'watch', 'doas', 'chroot', 'setsid', 'stdbuf', 'strace',
                    'ltrace', 'script', 'busybox', 'command', 'builtin', 'time', 'flock', 'run-parts', 'parallel',
                    'unbuffer', 'systemd-run', 'runuser', 'pkexec', 'chrt', 'taskset', 'numactl', 'firejail',
                    'bwrap', 'sg', 'newgrp', 'expect', 'npx', 'pnpx', 'bunx', 'uvx', 'pipx'}
# Their first operand is program text (sed's e command, awk/ed/vi shell escapes, ...).
SCRIPT_PROGRAMS = {'sed', 'awk', 'gawk', 'mawk', 'nawk', 'ed', 'ex', 'vi', 'vim', 'nvim', 'emacs', 'tclsh',
                   'wish', 'gdb', 'm4', 'dc'}
PATTERN_SYNTAX = ('* 匹配不含 / 的字符，** 可跨目录，? 匹配一个字符，末尾 ... 匹配其余参数；'
                  '通配部分不能是选项、绝对路径或 ..；裸命令名按 /usr/bin/名称 执行')
PS_PATTERN_SYNTAX = ('PowerShell：* 匹配不含 \\ / : 的字符，** 可跨目录，? 匹配一个字符，末尾 ... 匹配其余参数；'
                     '通配部分不能是选项、绝对路径、盘符、.. 或 ~；命令名不区分大小写，参数加单引号后用 & 调用，不再展开')
_WILDCARD = re.compile(r'\*\*|\*|\?')
_WILDCARD_CLASSES = {'posix': {'**': '.*', '*': '[^/]*', '?': '[^/]'},
                     # No drive or provider (C:, env:, HKLM:) and no cmdlet-side globbing from a wildcard.
                     'powershell': {'**': r'[^:*?]*', '*': r'[^\\/:*?]*', '?': r'[^\\/:*?]'}}

# PowerShell: one literal command. Variables, subexpressions, script blocks, arrays, splatting,
# comments, redirection and double quotes (which expand) are refused; single quotes wrap whole arguments.
# % and ^ are refused too: npm, yarn and other .cmd shims pass arguments through cmd.exe, which expands them.
PS_FORBIDDEN = set(';|&<>`$(){}[]@#,"%^\n\r') | set('‘’‚‛“”„‟')
PS_OPTION = re.compile(r'--?[A-Za-z][A-Za-z0-9-]*')
PS_EXTENSIONS = ('.exe', '.cmd', '.bat', '.com', '.ps1')
PS_BLOCKED = {
    # run another command or code, other shells and launchers
    'invoke-expression', 'iex', 'invoke-command', 'icm', 'start-process', 'saps', 'start', 'invoke-item', 'ii',
    'start-job', 'sajb', 'start-threadjob', 'invoke-history', 'ihy', 'r', 'add-type', 'new-object', 'foreach-object',
    'foreach', 'where-object', 'where', 'invoke-wmimethod', 'invoke-cimmethod', 'enter-pssession', 'etsn',
    'new-pssession', 'nsn', 'import-module', 'ipmo', 'powershell', 'pwsh', 'powershell_ise', 'cmd', 'wsl', 'wt',
    'conhost', 'mshta', 'wscript', 'cscript', 'rundll32', 'regsvr32', 'msiexec', 'installutil', 'forfiles',
    'runas', 'gsudo', 'psexec', 'schtasks', 'at',
    # definitions that change later commands, and system state
    'set-alias', 'sal', 'new-alias', 'nal', 'set-item', 'si', 'new-item', 'ni', 'set-variable', 'sv', 'set',
    'new-variable', 'nv', 'set-executionpolicy', 'set-itemproperty', 'sp', 'new-itemproperty', 'remove-itemproperty',
    'rp', 'reg', 'regedit', 'register-scheduledtask', 'register-objectevent', 'register-engineevent',
    'register-wmievent', 'bcdedit', 'diskpart', 'format', 'format-volume', 'clear-disk', 'initialize-disk',
    'stop-computer', 'restart-computer', 'takeown', 'icacls', 'cacls', 'set-acl', 'certutil', 'bitsadmin',
    'start-bitstransfer',
    # deletion
    'remove-item', 'del', 'erase', 'rd', 'rmdir', 'ri', 'clear-content', 'clc', 'clear-item', 'cli',
    'remove-variable', 'rv',
}


def _ps_absolute(program: str) -> bool:
    try:
        return ntpath.splitdrive(program)[0] != '' and windows_path(program) == ntpath.normpath(program)
    except ValueError:
        return False


def ps_literal_argv(command: str) -> list[str]:
    """Tokens of one literal PowerShell command line; quoting rules are a strict subset of PowerShell's."""
    checked_text(command, '命令')
    if len(command.encode('utf-8')) > 8192 or any(c in PS_FORBIDDEN for c in command):
        raise ValueError('PowerShell 授权只接受单条字面命令；管道、变量、子表达式、脚本块、数组、注释、重定向和双引号需逐次审批')
    argv, i, n = [], 0, len(command)
    while i < n:
        if command[i] in ' \t':
            i += 1
            continue
        if command[i] == "'":
            token, i = '', i + 1
            while True:
                if i >= n:
                    raise ValueError('命令引号不完整')
                if command[i] == "'":
                    if command[i + 1:i + 2] == "'":
                        token, i = token + "'", i + 2
                        continue
                    i += 1
                    break
                token, i = token + command[i], i + 1
            if i < n and command[i] not in ' \t':
                raise ValueError('单引号必须包住整个参数')
        else:
            start = i
            while i < n and command[i] not in ' \t':
                i += 1
            token = command[start:i]
            if "'" in token:
                raise ValueError('单引号必须包住整个参数')
            if token == '--%':
                raise ValueError('不接受 --% 停止解析标记')
        argv.append(token)
    if not argv:
        raise ValueError('空命令')
    if not (re.fullmatch(r'[A-Za-z0-9_.+-]+', argv[0]) or _ps_absolute(argv[0])) or argv[0].startswith('.'):
        raise ValueError('程序必须是命令名称或带盘符的绝对路径')
    return argv


def ps_render(argv: list[str]) -> str:
    """Call operator with single-quoted strings. Literal -Name switches stay bare so cmdlets still bind them."""
    return '& ' + ' '.join([ps_quote(argv[0]), *(a if PS_OPTION.fullmatch(a) else ps_quote(a) for a in argv[1:])])


def program_name(program: str, shell: str = 'posix') -> str:
    if shell != 'powershell':
        return posixpath.basename(program)
    name = ntpath.basename(program).lower()
    return next((name[:-len(e)] for e in PS_EXTENSIONS if name.endswith(e)), name)


def check_program(argv: list[str], shell: str = 'posix') -> str:
    name = program_name(argv[0], shell)
    if name in BLOCKED_PROGRAMS or (shell == 'powershell' and name in PS_BLOCKED):
        raise ValueError('Git、提权、shell 包装、执行其他命令、删除和系统级命令需使用专门工具或逐次审批')
    if name.startswith('mkfs.') or (name.startswith(('python', 'node', 'perl', 'ruby')) and
                                   any(a.startswith(('-c', '-e', '--eval', '-p', '--print')) for a in argv[1:])):
        raise ValueError('内联程序执行需逐次审批')
    return name


def _token_regex(token: str, shell: str = 'posix'):
    parts, pos = [], 0
    for m in _WILDCARD.finditer(token):
        parts += [re.escape(token[pos:m.start()]), _WILDCARD_CLASSES[shell][m.group()]]
        pos = m.end()
    return re.compile(''.join(parts) + re.escape(token[pos:]), re.DOTALL)


def _wildcard_arg_ok(arg: str, literal: str = '', shell: str = 'posix') -> bool:
    """A wildcard-produced argument stays a relative operand: no option, no absolute or home path, no .."""
    lead, roots = ('-+', '/~') if shell == 'posix' else ('-+/\\', '/\\~')
    if not arg or (not literal and arg[0] in lead):
        return False
    if '..' in re.split(r'[/\\=:,]', arg):
        return False
    starts = [0] + [i + 1 for i, c in enumerate(arg) if c in '=:,']
    return all(s < len(literal) or s >= len(arg) or arg[s] not in roots for s in starts)


def check_pattern(pattern: str, shell: str = 'posix') -> list[str]:
    if not isinstance(pattern, str) or len(pattern.encode('utf-8')) > 1024:
        raise ValueError('每条命令模式最多 1 KiB')
    tokens = ps_literal_argv(pattern) if shell == 'powershell' else literal_argv(pattern)
    name = check_program(tokens, shell)
    wild = [t for t in tokens[1:] if t == '...' or _WILDCARD.search(t)]
    if len(tokens) > 64 or _WILDCARD.search(tokens[0]) or tokens[0] == '...':
        raise ValueError('命令模式最多 64 个参数，程序名称必须是字面值')
    if '...' in tokens[1:-1]:
        raise ValueError('... 只能作为命令模式的最后一个参数')
    if any('..' in re.split(r'[/\\=:,]', t) for t in tokens[1:] if t != '...'):
        raise ValueError('命令模式参数不能包含 .. 路径')
    options = '-+' if shell == 'posix' else '-+/'
    for token in tokens[1:]:
        hit = _WILDCARD.search(token)
        if token and token[0] in options and hit and ('=' not in token or token.index('=') > hit.start()):
            raise ValueError(f'选项名称不能使用通配符：{token}；可写成 --name=* 只通配取值')
    if name in WRAPPER_PROGRAMS:
        raise ValueError(f'{name} 会执行其参数中的命令，不能使用模式授权；请改用固定命令')
    if wild and name in SCRIPT_PROGRAMS:
        raise ValueError(f'{name} 把参数当作脚本执行，通配参数需逐次审批或改用固定命令')
    return tokens


def pattern_matches(pattern: str, argv: list[str], shell: str = 'posix') -> bool:
    powershell = shell == 'powershell'
    tokens = ps_literal_argv(pattern) if powershell else shlex.split(pattern)
    rest, args = tokens[1:], argv[1:]
    tail = bool(rest) and rest[-1] == '...'
    if tail:
        rest = rest[:-1]
    # PowerShell resolves command names case-insensitively; arguments still match exactly.
    same = argv[0].lower() == tokens[0].lower() if powershell else argv[0] == tokens[0]
    if not same or len(args) < len(rest) or (not tail and len(args) != len(rest)):
        return False
    for token, arg in zip(rest, args):
        hit = _WILDCARD.search(token)
        if not hit:
            if arg != token:
                return False
        elif not _token_regex(token, shell).fullmatch(arg) or not _wildcard_arg_ok(arg, token[:hit.start()], shell):
            return False
    return all(_wildcard_arg_ok(a, '', shell) and not (powershell and set(a) & set(':*?')) for a in args[len(rest):])


def git_argv(command: str) -> list[str] | None:
    # A canonical shlex.join() line (as request_git_command renders it) quotes every shell
    # metacharacter, so commit messages such as 'fix(ui): x' stay one literal command.
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if not (argv and shlex.join(argv) == command):
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
                    max_timeout_seconds, git_remote, git_branch, command_patterns=(), shell='posix') -> dict:
    if shell == 'powershell':
        path = windows_path(repo_path, label='授权目录')
        if list(capabilities) != ['command_patterns']:
            raise ValueError('本机工作区只支持命令模式授权（request_pattern_approval）；其他命令逐条审批')
    else:
        path = checked_text(repo_path, '授权目录')
        if not path.startswith('/') or '..' in path.split('/') or len(path) > 4096:
            raise ValueError('授权目录必须是不含 .. 的绝对路径')
        path = posixpath.normpath(path)
    if (not isinstance(capabilities, (list, tuple)) or not capabilities or
            len(capabilities) > len(CAPABILITIES) or any(not isinstance(c, str) or c not in CAPABILITIES for c in capabilities)):
        raise ValueError('请选择支持的授权能力')
    if not isinstance(exact_commands, (list, tuple)) or len(exact_commands) > 20:
        raise ValueError('固定命令最多 20 条')
    commands = list(exact_commands)
    if bool(commands) != ('exact_commands' in capabilities):
        raise ValueError('固定命令列表与 exact_commands 能力必须同时指定')
    for command in commands:
        check_program(literal_argv(command))
    if sum(len(c.encode('utf-8')) for c in commands) > 32768:
        raise ValueError('固定命令总长度最多 32 KiB')
    if not isinstance(command_patterns, (list, tuple)) or len(command_patterns) > 20:
        raise ValueError('命令模式最多 20 条')
    patterns = list(dict.fromkeys(command_patterns))
    if bool(patterns) != ('command_patterns' in capabilities):
        raise ValueError('命令模式请使用 request_pattern_approval 申请')
    for pattern in patterns:
        check_pattern(pattern, shell)
    integer(ttl_seconds, 1, 3600, '授权期限')
    integer(max_uses, 1, 100, '授权次数')
    integer(max_timeout_seconds, 1, 86400, '单次执行时限')
    if not isinstance(git_remote, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', git_remote):
        raise ValueError('Git 远端必须是已登记的名称')
    if (not isinstance(git_branch, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}', git_branch)
            or '..' in git_branch or git_branch.endswith(('/', '.')) or '//' in git_branch):
        raise ValueError('Git 分支名称无效')
    return {'repo_path': path, 'shell': shell, 'capabilities': sorted(set(capabilities)),
            'exact_commands': commands, 'command_patterns': patterns, 'ttl_seconds': ttl_seconds, 'max_uses': max_uses,
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
        powershell = self.arguments.get('shell') == 'powershell'
        inside = within if powershell else scope_contains
        if not inside(cwd, (self.arguments['repo_path'],)):
            raise ValueError('工作目录不在此授权范围内')
        if timeout > self.arguments['max_timeout_seconds']:
            raise ValueError('执行时限超过此授权的单次上限')
        if powershell:
            return self._powershell_decision(command)
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
        if 'command_patterns' in caps:
            try:
                argv = literal_argv(command)
            except ValueError:
                argv = None
            matched = next((p for p in self.arguments.get('command_patterns', []) if argv and pattern_matches(p, argv)), None)
            if matched:
                # Arguments are quoted: the shell never expands globs, variables or operators in them.
                executable = argv[0] if argv[0].startswith('/') else '/usr/bin/' + argv[0]
                return ReadOnlyDecision(True, 'exec ' + shlex.join([executable, *argv[1:]]),
                                        f'匹配本地批准的命令模式 {matched}；程序及项目代码可能修改目录外资源', 'command_patterns')
        raise ValueError('命令或参数不匹配此授权；请逐次提交审批或申请新的明确范围')

    def _powershell_decision(self, command: str) -> ReadOnlyDecision:
        try:
            argv = ps_literal_argv(command)
        except ValueError:
            argv = None
        matched = next((p for p in self.arguments.get('command_patterns', [])
                        if argv and pattern_matches(p, argv, 'powershell')), None)
        if matched:
            return ReadOnlyDecision(True, ps_render(argv),
                                    f'匹配本地批准的 PowerShell 命令模式 {matched}；程序以当前 Windows 用户权限运行，可能修改工作区外资源',
                                    'command_patterns')
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
    if not caps <= allowed or caps & {'git_full', 'exact_commands', 'command_patterns'}:
        return False
    if server.auto_roots and not scope_contains(arguments['repo_path'], server.auto_roots):
        return False
    if caps - READ_CAPABILITIES and not server.auto_roots:
        return False
    return 'git_deploy_pull' not in caps or (arguments['git_remote'], arguments['git_branch']) == ('origin', 'main')
