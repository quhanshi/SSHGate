"""Local OpenSSH configuration discovery and immutable, fully resolved SSH routes."""
from __future__ import annotations

import getpass
import glob
import hashlib
import io
import os
import re
import shlex
import socket
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

import paramiko

from .config import Config, Server, checked_text, integer

MAX_HOPS = 8
HOST_NAME = re.compile(r'[a-zA-Z0-9_][a-zA-Z0-9_.:\[\]-]{0,253}')


@dataclass(frozen=True)
class SSHSettings:
    hostname: str
    username: str
    port: int
    identity_files: tuple[str, ...]
    known_hosts_files: tuple[str, ...]
    proxy_command: str = ''
    host_key_alias: str = ''
    connection_id: str = ''
    host_alias: str = ''
    identities_only: bool = False
    jump_hosts: tuple[SSHSettings, ...] = ()
    config_source: str = ''

    @property
    def verification_name(self) -> str:
        host = self.host_key_alias or self.hostname
        return host if self.port == 22 else f'[{host}]:{self.port}'


def _expand_path(value: str) -> str:
    # Path.home is also used by local config/known_hosts discovery.
    value = os.path.expandvars(value)
    if value == '~': return str(Path.home())
    if value.startswith(('~/', '~\\')): return str(Path.home() / value[2:])
    return str(Path(value).expanduser())


def _config_words(value: str, *, windows=None):
    if windows is None: windows = os.name == 'nt'
    words = shlex.split(value, comments=True, posix=not windows)
    return [word[1:-1] if len(word)>1 and word[0]==word[-1] and word[0] in {'"', "'"} else word for word in words]


def config_path(value: str = '') -> Path:
    return Path(_expand_path(value)) if value else Path.home() / '.ssh/config'


def config_lines(path: Path, stack=(), budget=None):
    """Expand lexical Includes; matching Host/Match context remains in the flattened text."""
    if budget is None: budget = [0, 0]
    path = path.resolve()
    if path in stack or len(stack) >= 16: raise ValueError('SSH config Include 循环或层级过深')
    budget[0] += 1
    if budget[0] > 128: raise ValueError('SSH config Include 文件过多')
    text = path.read_text(encoding='utf-8-sig')
    budget[1] += len(text.encode('utf-8'))
    if budget[1] > 2 * 1024 * 1024: raise ValueError('SSH config 总大小超过 2 MiB')
    for line in text.splitlines():
        match = re.match(r'^\s*([\w]+)(?:\s*=\s*|\s+)(.*)$', line)
        if not match or match[1].lower() != 'include':
            yield line; continue
        try: patterns = _config_words(match[2])
        except ValueError as exc: raise ValueError('SSH config Include 引号不完整') from exc
        for pattern in patterns:
            expanded = Path(_expand_path(pattern))
            if not expanded.is_absolute(): expanded = Path.home() / '.ssh' / expanded
            for filename in sorted(glob.glob(str(expanded))):
                yield from config_lines(Path(filename), (*stack, path), budget)


def config_profiles(value: str = '') -> dict:
    """List literal Host names only. Discovery never executes Match exec or logs in."""
    path = config_path(value)
    profiles = []
    if path.is_file():
        seen = set()
        for line in config_lines(path):
            match = re.match(r'^\s*Host(?:\s*=\s*|\s+)(.*)$', line, re.I)
            if not match: continue
            for alias in shlex.split(match[1], comments=True):
                if any(c in alias for c in '*?![]') or not HOST_NAME.fullmatch(alias) or alias in seen: continue
                seen.add(alias); profiles.append({'alias': alias, 'config_path': str(path)})
    return {'config_path': str(path), 'exists': path.is_file(), 'profiles': profiles}


def _options(config: Config, path: Path, host: str, user: str = '', port=None) -> dict:
    if not path.is_file(): return {}
    if config.ssh_executable and Path(config.ssh_executable).is_file():
        argv = [config.ssh_executable, '-F', str(path), '-G', '-o', 'PermitLocalCommand=no']
        if user: argv += ['-l', user]
        if port is not None: argv += ['-p', str(port)]
        argv += ['--', host]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8',
                errors='replace', timeout=10, shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError('本地 OpenSSH 配置解析失败或超时') from exc
        if result.returncode: raise ValueError('本地 OpenSSH 无法解析 config，请检查 Host / Include / Match')
        options = {}
        for line in result.stdout.splitlines():
            key, _, value = line.partition(' ')
            if key in {'identityfile', 'certificatefile'}: options.setdefault(key, []).append(value)
            else: options[key] = value
        return options
    # Preserve first-value precedence between ProxyJump and ProxyCommand as one option.
    lines = []
    for line in config_lines(path):
        match = re.match(r'^(\s*)(ProxyJump|ProxyCommand)(?:\s*=\s*|\s+)(.*)$', line, re.I)
        if match: line = f'{match[1]}wasshproxy {match[2].lower()} {match[3]}'
        if re.match(r'^\s*Match\s+.*\bexec\b', line, re.I):
            raise ValueError('Match exec 需要本地 OpenSSH；此解析器不会替代执行')
        lines.append(line)
    parser = paramiko.SSHConfig()
    try:
        parser.parse(io.StringIO('\n'.join(lines)))
        options = parser.lookup(host)
    except Exception as exc: raise ValueError('SSH config 解析失败；复杂配置请启用本地 OpenSSH') from exc
    route = options.pop('wasshproxy', '')
    if route:
        kind, _, value = route.partition(' ')
        options[kind] = value.strip().strip('"')
    return options


def _target(target: str):
    user, sep, host = target.rpartition('@')
    if not sep: host, user = target, ''
    if not HOST_NAME.fullmatch(host) or (user and not re.fullmatch(r'[\w.-]+', user)):
        raise ValueError('SSH 主机/用户名无效')
    return host.removeprefix('[').removesuffix(']'), user


def _jump_target(value: str):
    if value.startswith('ssh://'):
        parsed = urlsplit(value)
        if parsed.password or parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
            raise ValueError('ProxyJump URI 不支持密码或路径')
        if not parsed.hostname: raise ValueError('ProxyJump 缺少主机')
        target = (parsed.username + '@' if parsed.username else '') + parsed.hostname
        return target, parsed.port
    user, sep, host = value.rpartition('@')
    if not sep: host, user = value, ''
    port = None
    if host.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::(\d+))?', host)
        if not match: raise ValueError('ProxyJump IPv6 格式无效')
        host = match[1]; port = int(match[2]) if match[2] else None
    elif host.count(':') == 1:
        host, raw = host.rsplit(':', 1)
        if not raw.isdigit(): raise ValueError('ProxyJump 端口无效')
        port = int(raw)
    if port is not None: integer(port, 1, 65535, '跳板端口')
    target = (user + '@' if user else '') + host
    _target(target)
    return target, port


def _tokens(value: str, *, host: str, alias: str, user: str, port: int) -> str:
    local = socket.gethostname()
    values = {'%': '%', 'h': host, 'n': alias, 'r': user, 'p': str(port),
              'd': str(Path.home()), 'u': getpass.getuser(), 'l': local, 'L': local.split('.')[0],
              'C': hashlib.sha1((local+host+str(port)+user).encode()).hexdigest()}
    def substitute(match):
        if match[1] not in values: raise ValueError(f'SSH 配置中不支持的路径/代理 token %{match[1]}')
        return values[match[1]]
    return re.sub(r'%(.)', substitute, value)


def resolve_settings(config: Config, server: Server) -> SSHSettings:
    path = config_path(server.ssh_config_file)
    def resolve(target, port=None, identity='', trail=(), follow=True):
        alias, override_user = _target(target)
        marker = (alias, override_user, port)
        if marker in trail or len(trail) > MAX_HOPS: raise ValueError('ProxyJump 路由循环或超过 8 跳')
        options = _options(config, path, alias, override_user, port)
        host = checked_text(options.get('hostname', alias), 'SSH HostName')
        user = override_user or options.get('user', getpass.getuser())
        checked_text(user, 'SSH User')
        resolved_port = integer(port if port is not None else int(options.get('port', 22)), 1, 65535, 'SSH 端口')
        def expand(value): return _tokens(value, host=host, alias=alias, user=user, port=resolved_port)
        keys = [identity] if identity else options.get('identityfile', [])
        if isinstance(keys, str): keys = [keys]
        if not keys and options.get('identitiesonly', 'no').lower() == 'yes':
            keys = ['~/.ssh/id_rsa', '~/.ssh/id_ecdsa', '~/.ssh/id_ed25519']
        identities = tuple(dict.fromkeys(_expand_path(expand(k)) for k in keys if k and k.lower() != 'none'))
        known = [str(Path.home() / '.ssh/known_hosts')]
        extra = options.get('userknownhostsfile', [])
        if isinstance(extra, str): extra = [extra]
        for line in extra:
            # Windows OpenSSH commonly emits forward-slash paths. Preserve quoted paths.
            for value in _config_words(line):
                if value.lower() != 'none':
                    expanded = _expand_path(expand(value))
                    if expanded not in known: known.append(expanded)
        proxy = options.get('proxycommand') or ''
        if proxy.lower() == 'none': proxy = ''
        jump = options.get('proxyjump') or ''
        alias_key = options.get('hostkeyalias', '')
        if alias_key.lower() == 'none': alias_key = ''
        node = SSHSettings(host, user, resolved_port, identities, tuple(known), expand(proxy), alias_key,
                           server.id, alias, options.get('identitiesonly', 'no').lower() == 'yes',
                           config_source=str(path) if path.is_file() else '')
        hops = []
        if follow and jump and jump.lower() != 'none' and not proxy:
            for index, entry in enumerate(jump.split(',')):
                jt, jp = _jump_target(entry.strip())
                hop = resolve(jt, jp, trail=(*trail, marker), follow=index == 0)
                hops.extend(hop.jump_hosts)
                hops.append(replace(hop, jump_hosts=()))
        if len(hops) > MAX_HOPS: raise ValueError('ProxyJump 超过 8 跳')
        endpoints = [(n.hostname, n.username, n.port) for n in [*hops, node]]
        if len(set(endpoints)) != len(endpoints): raise ValueError('ProxyJump 路由重复节点/循环')
        if any(n.proxy_command for n in [*hops[1:], node] if hops):
            raise ValueError('ProxyJump 链后续节点不能再使用 ProxyCommand')
        return replace(node, jump_hosts=tuple(hops))
    return resolve(server.ssh_target, server.port, server.identity_file)
