"""Inspect effective Git remotes before supported direct Git operations."""
from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
import time
from urllib.parse import urlsplit

from .authorizations import GIT_PREFIX, git_argv
from .readonly import readonly_command


def remote_host(url: str) -> tuple[str, bool]:
    """No substring matching, local/ext transports, credentials or query data in results."""
    if '://' in url:
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {'https', 'http', 'ssh', 'git'} or not parsed.hostname:
                return '', False
            return parsed.hostname.lower().rstrip('.'), parsed.scheme == 'ssh'
        except ValueError:
            return '', False
    match = re.fullmatch(r'(?:[^/@:\s]+@)?([^/:\s]+):[^\s]+', url)
    return (match.group(1).lower().rstrip('.'), True) if match else ('', False)


def ssh_aliases(text: str) -> dict[str, str]:
    """Bounded static Host/HostName resolution. Includes/Match require explicit local host mapping."""
    aliases = {}
    patterns = []
    for line in text.splitlines():
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            return {'*': ''}
        if not parts:
            continue
        key = parts[0].lower()
        if key in {'include', 'match'}:
            return {'*': ''}
        if key == 'host':
            patterns = parts[1:]
        elif key == 'hostname' and len(parts) == 2:
            for pattern in patterns:
                if pattern.startswith('!'):
                    return {'*': ''}
                aliases.setdefault(pattern.lower(), parts[1].lower().rstrip('.'))
    return aliases


def provider_for_urls(urls, aliases=None, github_hosts=()) -> tuple[str, list[str]]:
    aliases = aliases or {}
    providers, hosts = set(), []
    trusted_github = {'github.com', 'ssh.github.com', *github_hosts}
    for url in urls:
        host, ssh = remote_host(url)
        if ssh and host not in github_hosts:
            host = next((target for pattern, target in aliases.items() if fnmatch.fnmatchcase(host, pattern)), host)
        hosts.append(host)
        if host in trusted_github or host.endswith('.ghe.com'):
            providers.add('github')
        elif not host or (ssh and '.' not in host):
            providers.add('unknown')
        else:
            providers.add('other')
    provider = next(iter(providers)) if len(providers) == 1 else 'mixed' if providers else 'unknown'
    return provider, sorted(set(hosts))


def capture(client, script: str, stop, limit=32768, deadline=None) -> str:
    channel = client.get_transport().open_session(timeout=5)
    out, err = bytearray(), bytearray()
    deadline = min(deadline or float('inf'), time.monotonic() + 10)
    try:
        channel.exec_command(script)
        channel.shutdown_write()
        while True:
            while channel.recv_ready():
                out.extend(channel.recv(4096))
                if len(out) + len(err) > limit or stop.is_set() or time.monotonic() >= deadline:
                    raise ValueError('Git 元数据超过读取上限，或核验被取消或超时')
            while channel.recv_stderr_ready():
                err.extend(channel.recv_stderr(4096))
                if len(out) + len(err) > limit or stop.is_set() or time.monotonic() >= deadline:
                    raise ValueError('Git 元数据超过读取上限，或核验被取消或超时')
            if len(out) + len(err) > limit:
                raise ValueError('Git 元数据超过读取上限')
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                if channel.recv_exit_status() != 0:
                    raise ValueError('无法核验 Git 仓库或实际远端；请先检查仓库路径和配置')
                return out.decode('utf-8', errors='strict').strip()
            if stop.wait(.02) or time.monotonic() >= deadline:
                raise ValueError('Git 远端核验被取消或超时')
    finally:
        channel.close()


def inspect_repository(client, sftp, cwd, stop, github_hosts=()) -> dict:
    deadline = time.monotonic() + 20
    def read(script):
        if stop.is_set() or time.monotonic() >= deadline:
            raise ValueError('Git 远端核验被取消或超时')
        return capture(client, script, stop, deadline=deadline)
    prefix = GIT_PREFIX.replace('exec ', 'exec /usr/bin/timeout 8s ', 1) + ' -C ' + shlex.quote(cwd)
    root = read(prefix + ' rev-parse --show-toplevel')
    names = read(prefix + ' remote').splitlines()
    if len(names) > 20 or any(not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', n) for n in names):
        raise ValueError('Git 远端列表无法安全解析')
    aliases = {}
    try:
        home = sftp.normalize('.')
        with sftp.open(posixpath.join(home, '.ssh/config'), 'rb') as source:
            text = source.read(32769)
        if len(text) <= 32768:
            aliases = ssh_aliases(text.decode('utf-8', errors='replace'))
    except OSError:
        pass
    remotes, all_urls = [], []
    for name in names:
        quoted = shlex.quote(name)
        fetch = read(prefix + ' remote get-url --all ' + quoted).splitlines()
        push = read(prefix + ' remote get-url --push --all ' + quoted).splitlines()
        provider, hosts = provider_for_urls([*fetch, *push], aliases, github_hosts)
        all_urls.extend([*fetch, *push])
        remotes.append({'name': name, 'provider': provider, 'hosts': hosts})
    provider, _ = provider_for_urls(all_urls, aliases, github_hosts)
    return {'repo_path': root, 'provider': provider, 'remotes': remotes,
            'workflow': 'deployment_only' if provider == 'github' else 'full_git' if provider == 'other' else 'verify_remotes'}


def validate_git_operation(command: str, context: dict, category: str) -> None:
    args = git_argv(command)
    if not args or args[0].startswith('-'):
        raise ValueError('请用明确的工作目录和单条 Git 命令；组合脚本及 Git 全局选项需逐次核对')
    if readonly_command(command).allowed:
        return
    remotes = {r['name']: r for r in context['remotes']}
    fetch = len(args) == 2 and args[0] == 'fetch' and args[1] in remotes
    pull = (len(args) == 4 and args[:2] == ['pull', '--ff-only'] and args[2] in remotes
            and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}', args[3]) and '..' not in args[3])
    if context['provider'] in {'unknown', 'mixed'} and not (fetch or pull):
        raise ValueError('Git 远端类型未知或混合，未执行完整 Git 操作；先核对实际远端')
    if context['provider'] == 'github' and not (fetch or pull):
        raise ValueError('GitHub 仓库在服务器上仅拉取部署和检查状态；代码修改、提交、推送和分支操作请使用 GitHub 工具')
    if category == 'git_full' and context['provider'] != 'other':
        raise ValueError('git_full 授权只适用于已确认的非 GitHub 远端')
    if fetch or pull:
        remote = remotes[args[1] if fetch else args[2]]
        if remote['provider'] in {'unknown', 'mixed'}:
            raise ValueError('指定远端无法确认，未拉取代码')


def check_git_command(client, sftp, command, cwd, stop, category='', github_hosts=()) -> dict | None:
    # Scripts have separate literal human approval; no automatic Git grants accept shell wrappers.
    try:
        first = shlex.split(command)[0]
    except (ValueError, IndexError):
        return None
    if posixpath.basename(first) != 'git':
        return None
    args = git_argv(command)
    if not args or args[0].startswith('-'):
        raise ValueError('Git 必须通过单条命令与 cwd 参数执行，不能嵌入 shell 组合或使用全局路径选项')
    if args[0] == 'clone':
        if category == 'git_full' or len(args) not in {2, 3} or args[1].startswith('-'):
            raise ValueError('首次部署请单独审批 git clone URL [目录]，不适用已有仓库的临时授权')
        provider, _ = provider_for_urls([args[1]], github_hosts=github_hosts)
        if provider == 'unknown':
            raise ValueError('无法确认 clone 远端；请使用明确的 Git URL')
        return {'provider': provider, 'workflow': 'initial_clone'}
    context = inspect_repository(client, sftp, cwd, stop, github_hosts)
    validate_git_operation(command, context, category)
    return context
