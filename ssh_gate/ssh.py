from __future__ import annotations

import base64
import errno
import hashlib
import os
import re
import shlex
import socket
import select
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import paramiko

from .ssh_config import SSHSettings, resolve_settings, config_profiles
from .service_ops import OPS as SERVICE_OPS
from .prompts import LocalPrompts, PromptCancelled
from .credentials import CredentialStore
from .ssh_trace import ConnectionTrace, HostKeyRejected, ObservedSSHClient, ObservedTransport, failure_code


def cwd_expression(cwd: str) -> str:
    if cwd in {".", "~"}:
        return '"$HOME"'
    if cwd.startswith("~/"):
        return '"$HOME"/' + shlex.quote(cwd[2:])
    return shlex.quote(cwd)


def build_remote_command(command: str, cwd: str, timeout_seconds: int, job_token: str = "") -> str:
    script = f"cd {cwd_expression(cwd)} || exit 125\n{command}\n"
    inner = f"exec /usr/bin/timeout --signal=TERM --kill-after=5s {timeout_seconds}s /bin/sh -c {shlex.quote(script)}"
    if not job_token: return inner
    if not re.fullmatch(r"[0-9a-f]{32}",job_token): raise ValueError("任务标识无效")
    control="/tmp/wassh-"+job_token
    job=(f"printf '%s %s\\n' \"$$\" \"$(/usr/bin/awk '{{print $22}}' /proc/$$/stat)\" > {control}/pid\n"+inner)
    outer=(f"test -x /usr/bin/setsid -a -x /usr/bin/timeout -a -x /usr/bin/awk || exit 126\n"
           f"umask 077\n/bin/mkdir {control} || exit 126\n"
           f"trap '/bin/rm -f {control}/pid; /bin/rmdir {control} 2>/dev/null' EXIT\n"
           f"/usr/bin/setsid /bin/sh -c {shlex.quote(job)}\n")
    return "/bin/sh -c "+shlex.quote(outer)


def known_host_candidates(path: Path | None = None) -> tuple[tuple[str, int | None], ...]:
    """List readable addresses locally; hashed entries still work for verification."""
    path = path or Path.home() / ".ssh/known_hosts"
    if not path.is_file():
        return ()
    candidates = []
    seen = set()
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[0].startswith(("#", "@", "|")):
            continue
        for address in fields[0].split(","):
            port = None
            match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", address)
            if match:
                address, port = match[1], int(match[2])
                if not 1 <= port <= 65535:
                    continue
            if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,253}", address):
                continue
            candidate = (address, port)
            if candidate not in seen:
                candidates.append(candidate)
                seen.add(candidate)
    return tuple(candidates)


@dataclass(frozen=True)
class RunResult:
    exit_code: int | None
    timed_out: bool = False
    disconnected: bool = False
    error: str = ""
    result: dict = field(default_factory=dict)
    termination: dict = field(default_factory=dict)


class LocalHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, settings: SSHSettings, prompts: LocalPrompts, stop: threading.Event, trace=None):
        self.settings, self.prompts, self.stop = settings, prompts, stop
        self.context = {}
        self.trace = trace

    def missing_host_key(self, client, hostname, key):
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if self.trace:
            self.trace.emit("host_key_confirmation_required", stage="host_key",
                            key_type=key.get_name(), fingerprint=fingerprint)
        response = self.prompts.ask("host_key", {
            "hostname": self.settings.hostname, "port": self.settings.port,
            "verification_name": self.settings.verification_name,
            "key_type": key.get_name(), "fingerprint": fingerprint,
            "known_hosts_file": self.settings.known_hosts_files[0],
            **self.context,
        }, self.stop)
        if response not in {"once", "save"}:
            raise HostKeyRejected("用户未接受主机指纹")
        client.get_host_keys().add(hostname, key.get_name(), key)
        if response == "save":
            target = Path(self.settings.known_hosts_files[0])
            target.parent.mkdir(parents=True, exist_ok=True)
            existing = target.read_bytes() if target.exists() else b""
            with target.open("ab") as out:
                if existing and not existing.endswith(b"\n"):
                    out.write(b"\n")
                line = f"{self.settings.verification_name} {key.get_name()} {key.get_base64()}\n"
                out.write(line.encode("ascii"))
                out.flush()
                os.fsync(out.fileno())
        if self.trace:
            self.trace.trust_source = "user_saved" if response == "save" else "user_once"


def load_preferred_host_keys(client: paramiko.SSHClient, settings: SSHSettings) -> None:
    """Prefer ~/.ssh/known_hosts entries over additional locally configured files."""
    remote_name = settings.hostname if settings.port == 22 else f"[{settings.hostname}]:{settings.port}"
    found = None
    for path in settings.known_hosts_files:
        if not Path(path).is_file():
            continue
        keys = paramiko.HostKeys(path)
        candidates = keys.lookup(settings.verification_name)
        if candidates:
            found = candidates
            break
    if found:
        for algorithm, key in found.items():
            client.get_host_keys().add(remote_name, algorithm, key)


class SSHRunner:
    """Key/agent first, local password fallback, retained authenticated connections."""
    def __init__(self, prompts: LocalPrompts | None = None, credentials: CredentialStore | None = None):
        self.prompts = prompts or LocalPrompts()
        self.credentials = credentials
        self._clients: dict[SSHSettings, paramiko.SSHClient] = {}
        self._trusted_keys: dict[SSHSettings, dict] = {}
        self._parents: dict[SSHSettings, paramiko.SSHClient | None] = {}
        self._targets: dict[str, SSHSettings] = {}
        self._lock = threading.Lock()
        self._closed = False

    def close_connections(self):
        with self._lock:
            clients, self._clients = list(self._clients.values()), {}
            self._trusted_keys.clear()
            self._parents.clear()
            self._targets.clear()
        for client in reversed(clients):
            client.close()

    def close_connection(self, server_id: str):
        with self._lock:
            matches = [s for s in self._clients if s.connection_id == server_id]
            clients = [self._clients.pop(s) for s in matches]
            for s in matches: self._parents.pop(s, None)
            self._targets.pop(server_id, None)
            for settings in list(self._trusted_keys):
                if settings.connection_id == server_id:
                    self._trusted_keys.pop(settings, None)
        for client in reversed(clients):
            client.close()

    def connection_states(self) -> dict:
        with self._lock:
            def active(settings):
                client = self._clients.get(settings)
                return bool(client and client.get_transport() and client.get_transport().is_active())
            return {sid: all(active(node) for node in [*target.jump_hosts, target])
                    for sid, target in self._targets.items() if sid}

    def close(self):
        with self._lock:
            self._closed = True
        self.prompts.close()
        self.close_connections()

    def _connect(self, settings: SSHSettings, stop: threading.Event, progress=None):
        progress = progress or (lambda **values: None)
        route = [*settings.jump_hosts, settings]
        route_started = time.monotonic()
        parent = None
        for index, node in enumerate(route):
            context = {"host_alias": node.host_alias or node.hostname, "hostname": node.hostname,
                       "port": node.port, "role": "jump" if index < len(route)-1 else "target",
                       "hop_index": index+1, "hop_count": len(route),
                       "via_host_alias": (route[index-1].host_alias or route[index-1].hostname) if index else None}
            def report(_context=context, **values):
                progress(connection_context=_context, **values)
            parent = self._connect_one(node, stop, report, via=parent, context=context,
                                       route_started=route_started)
        with self._lock: self._targets[settings.connection_id] = settings
        return parent

    @staticmethod
    def _identity_public_keys(settings, passphrase=None):
        allowed = set()
        for filename in settings.identity_files:
            path = Path(filename)
            pub = path if path.name.endswith('.pub') else Path(filename+'.pub')
            if pub.is_file():
                try:
                    words = pub.read_text(encoding='utf-8').strip().split()
                    key = paramiko.PKey.from_type_string(words[0], base64.b64decode(words[1], validate=True))
                    allowed.add(key.asbytes())
                except (ValueError, IndexError, OSError, paramiko.SSHException): pass
            if path.is_file() and not path.name.endswith('.pub'):
                try: allowed.add(paramiko.PKey.from_path(path, passphrase=passphrase.encode("utf-8") if isinstance(passphrase,str) else passphrase).asbytes())
                except (ValueError, TypeError, OSError, paramiko.SSHException, paramiko.UnknownKeyType): pass
        return allowed

    def _connect_one(self, settings: SSHSettings, stop: threading.Event, progress, *, via=None,
                     context=None, route_started=None):
        trace = ConnectionTrace(progress, route_started if route_started is not None else time.monotonic())
        trace.emit("connection_started")
        try:
            return self._connect_one_traced(settings, stop, progress, trace, via=via, context=context)
        except Exception as exc:
            trace.fail(exc, stop)
            raise
        finally:
            trace.close()

    def _connect_one_traced(self, settings, stop, progress, trace, *, via=None, context=None):
        context = context or {}
        with self._lock:
            if self._closed or stop.is_set(): raise PromptCancelled("后端已关闭或连接已取消")
            existing = self._clients.get(settings)
            same_parent = self._parents.get(settings) is via
        if (existing and same_parent and existing.get_transport() and existing.get_transport().is_active()
                and existing.get_transport().is_authenticated()):
            progress(phase="connected")
            transport = existing.get_transport()
            summary = transport.public_summary() if isinstance(transport, ObservedTransport) else {}
            trace.emit("connection_reused", stage="connected", **summary)
            return existing
        if existing: existing.close()

        credential_ref = (self.credentials.reference(settings.connection_id, settings.username, settings.hostname, settings.port)
                          if self.credentials and settings.connection_id else "")
        saved_tried = False
        prompt_attempt = 0
        initial_key_attempt = True
        while True:
            if stop.is_set():
                raise PromptCancelled("已取消连接")
            trace.attempt += 1
            trace.emit("attempt_started", stage="connecting")
            secret = None
            mode = "key"
            source = "key"
            remember = False
            if initial_key_attempt:
                initial_key_attempt = False
            else:
                saved = None
                if credential_ref and not saved_tried:
                    saved_tried = True
                    saved = self.credentials.get(credential_ref) if self.credentials else None
                if saved:
                    secret, mode, source = saved["secret"], saved["mode"], "saved"
                    progress(phase="authenticating_saved_credential")
                    trace.emit("saved_credential_selected", stage="authentication", mode=mode)
                else:
                    if prompt_attempt >= 3:
                        raise paramiko.AuthenticationException("本地密码/私钥口令认证失败，请重新申请连接")
                    prompt_attempt += 1
                    progress(phase="awaiting_local_credentials")
                    trace.emit("credentials_required", stage="authentication", prompt_attempt=prompt_attempt)
                    answer = self.prompts.ask("credentials", {
                        "hostname": settings.hostname, "username": settings.username,
                        "port": settings.port, "attempt": prompt_attempt,
                        "saved_available": bool(credential_ref), **context,
                    }, stop)
                    secret, mode = answer["secret"], answer.get("mode", "password")
                    remember = bool(answer.get("remember", False))
                    source = "prompt"
                    answer.clear()
            client = ObservedSSHClient(trace, progress)
            load_preferred_host_keys(client, settings)
            trace.trust_source = "known_hosts"
            actual_name = settings.hostname if settings.port == 22 else f"[{settings.hostname}]:{settings.port}"
            if not client.get_host_keys().lookup(actual_name):
                for algorithm, key in self._trusted_keys.get(settings, {}).items():
                    client.get_host_keys().add(actual_name, algorithm, key)
                    trace.trust_source = "session"
            policy = LocalHostKeyPolicy(settings, self.prompts, stop, trace)
            policy.context = context
            client.set_missing_host_key_policy(policy)
            proxy = None
            network = None
            try:
                if via:
                    progress(phase="opening_jump_channel")
                    trace.emit("jump_channel_started", stage="tcp")
                    if not via.get_transport() or not via.get_transport().is_active():
                        raise paramiko.SSHException("上游跳板连接已经断开")
                    network = via.get_transport().open_channel('direct-tcpip',
                        (settings.hostname, settings.port), ('127.0.0.1', 0), timeout=15)
                    trace.emit("jump_channel_opened", stage="tcp")
                elif settings.proxy_command:
                    progress(phase="starting_proxy")
                    trace.emit("proxy_started", stage="proxy")
                    proxy = paramiko.ProxyCommand(settings.proxy_command)
                    trace.emit("proxy_process_started", stage="proxy")
                else:
                    progress(phase="resolving_dns")
                    trace.emit("dns_started", stage="dns")
                    addresses=socket.getaddrinfo(settings.hostname,settings.port,type=socket.SOCK_STREAM)
                    trace.emit("dns_resolved", stage="dns", address_count=len(addresses))
                    progress(phase="connecting_tcp")
                    errors=[]
                    for family, socktype, proto, _name, address in addresses:
                        if stop.is_set(): raise PromptCancelled("已取消连接")
                        trace.emit("tcp_started", stage="tcp", address=address[0], port=address[1])
                        network=socket.socket(family,socktype,proto)
                        network.setblocking(False)
                        code=network.connect_ex(address)
                        deadline=time.monotonic()+15
                        pending_codes = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                                         errno.EINTR, 10035, 10036, 10037}
                        while code in pending_codes and not stop.is_set() and time.monotonic()<deadline:
                            _read,writable,_error=select.select([], [network], [network], .1)
                            if writable or _error:
                                code=network.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
                                break
                        if stop.is_set(): network.close(); raise PromptCancelled("已取消连接")
                        if not code:
                            network.setblocking(True); network.settimeout(15)
                            trace.emit("tcp_connected", stage="tcp", address=address[0], port=address[1])
                            break
                        failure = (TimeoutError("TCP 连接超时") if code in pending_codes or code in {errno.ETIMEDOUT, 10060}
                                   else OSError(code, "TCP 连接失败"))
                        trace.emit("tcp_address_failed", stage="tcp", address=address[0], port=address[1],
                                   code=failure_code(failure, "tcp"))
                        errors.append(failure); network.close(); network=None
                    if network is None:
                        if errors: raise errors[-1]
                        raise OSError("DNS 未返回可连接的地址")
                progress(phase="handshaking_ssh")
                trace.emit("ssh_handshake_started", stage="ssh_banner")
                allowed_keys = self._identity_public_keys(settings, secret if mode == 'passphrase' else None) if settings.identities_only else set()
                def transport_factory(*args, **kwargs):
                    return ObservedTransport(*args, trace=trace,
                                             allowed_keys=allowed_keys if settings.identities_only else None, **kwargs)
                client.connect(
                    settings.hostname, port=settings.port, username=settings.username,
                    key_filename=([p for p in settings.identity_files if Path(p).is_file()] or None) if mode != "password" else None,
                    password=secret if mode == "password" else None,
                    passphrase=secret if mode == "passphrase" else None,
                    allow_agent=(mode != "password"), look_for_keys=(mode != "password" and not settings.identities_only),
                    timeout=15, banner_timeout=15, auth_timeout=15, channel_timeout=15, sock=proxy or network, transport_factory=transport_factory,
                )
                client.get_transport().set_keepalive(15)
                with self._lock:
                    if self._closed or stop.is_set():
                        client.close()
                        raise PromptCancelled("已取消连接")
                    self._clients[settings] = client
                    self._parents[settings] = via
                if source == "prompt" and remember and credential_ref and self.credentials:
                    self.credentials.save(credential_ref, mode, secret)
                progress(phase="connected")
                trace.emit("connected", stage="connected", **client.get_transport().public_summary())
                return client
            except (paramiko.AuthenticationException, paramiko.PasswordRequiredException):
                self._trusted_keys[settings] = dict(client.get_host_keys().lookup(actual_name) or {})
                client.close()
                if proxy:
                    proxy.close()
                if source == "saved" and credential_ref and self.credentials:
                    self.credentials.delete(credential_ref)
                if source == "prompt" and prompt_attempt >= 3:
                    raise paramiko.AuthenticationException("本地密码/私钥口令认证失败，请重新申请连接")
                trace.emit("authentication_retry", stage="authentication", source=source)
                # key/agent failure, stale saved credential, or a retryable prompted credential
                continue
            except paramiko.SSHException as exc:
                transport = client.get_transport()
                # Paramiko can replace an encrypted-key exception with a later key-format
                # exception. An active, unauthenticated transport may still use local credentials.
                if isinstance(exc, paramiko.BadHostKeyException) or not (transport and transport.is_active() and not transport.is_authenticated()):
                    client.close()
                    if proxy:
                        proxy.close()
                    raise
                self._trusted_keys[settings] = dict(client.get_host_keys().lookup(actual_name) or {})
                client.close()
                if proxy:
                    proxy.close()
                if source == "saved" and credential_ref and self.credentials:
                    self.credentials.delete(credential_ref)
                if source == "prompt" and prompt_attempt >= 3:
                    raise paramiko.AuthenticationException("没有可用的认证方式")
                trace.emit("authentication_retry", stage="authentication", source=source)
                continue
            except BaseException:
                client.close()
                if proxy:
                    proxy.close()
                raise
            finally:
                client.detach_trace()
                policy.trace = None
                secret = None
                if network and not client.get_transport(): network.close()

    def __call__(self, payload, emit: Callable[[str, bytes], None], stop: threading.Event) -> RunResult:
        return self.execute(payload,emit,stop,lambda **values: None)

    @staticmethod
    def _control_read(client, token):
        if not re.fullmatch(r"[0-9a-f]{32}",token): raise ValueError("任务标识无效")
        _stdin,out,_err=client.exec_command("/usr/bin/cat -- /tmp/wassh-"+token+"/pid",timeout=3)
        try:
            value=out.read(100).decode("ascii",errors="replace").strip().split()
            if len(value)==2 and all(v.isdigit() for v in value) and int(value[0])>1:
                return int(value[0]),value[1]
        finally: out.channel.close()
        return None

    def _terminate_job(self,client,token):
        if not token: return {"state":"untracked","remote_group_terminated":False}
        # Read the private control file, verify the PID start time, then signal its process group.
        control="/tmp/wassh-"+token
        script=f"""read p start < {control}/pid || {{ echo UNKNOWN; exit 3; }}
case "$p:$start" in *[!0-9:]*|:*) echo UNKNOWN; exit 3;; esac
test "$p" -gt 1 -a -n "$start" || exit 3
actual=$(/usr/bin/awk '{{print $22}}' /proc/$p/stat 2>/dev/null)
test "$actual" = "$start" || {{ echo STALE; exit 3; }}
pg=$(/usr/bin/ps -o pgid= -p "$p" | /usr/bin/tr -d ' ')
test "$pg" = "$p" || {{ echo STALE; exit 3; }}
alive() {{
 table=$(/usr/bin/ps -eo pgid=,stat=) || {{ echo ERROR; return; }}
 printf '%s\\n' "$table" | /usr/bin/awk -v g="$p" '$1==g && $2 !~ /^Z/ {{found=1}} END {{if(found) print "YES"; else print "NO"}}'
}}
/bin/kill -TERM -- -"$p" 2>/dev/null
n=0; state=$(alive)
while test "$state" = YES && test "$n" -lt 20; do /bin/sleep .1; n=$((n+1)); state=$(alive); done
if test "$state" = ERROR; then echo UNCONFIRMED; exit 4; fi
if test "$state" = YES; then /bin/kill -KILL -- -"$p" 2>/dev/null; fi
n=0; state=$(alive)
while test "$state" = YES && test "$n" -lt 20; do /bin/sleep .1; n=$((n+1)); state=$(alive); done
if test "$state" = NO; then echo STOPPED; else echo UNCONFIRMED; exit 4; fi
"""
        try:
            _stdin,out,err=client.exec_command("/bin/sh -c "+shlex.quote(script),timeout=8)
            try:
                text=out.read(128).decode("ascii",errors="replace").strip()
                code=out.channel.recv_exit_status()
            finally: out.channel.close()
            return {"state":"process_group_stopped" if code==0 and text=="STOPPED" else text.lower() or "unconfirmed",
                    "remote_group_terminated":code==0 and text=="STOPPED",
                    "scope":"original_process_group", "escaped_processes_guaranteed":False}
        except Exception as exc:
            return {"state":"connection_failed","remote_group_terminated":False,"error":type(exc).__name__}

    def execute(self,payload,emit,stop,progress):
        channel=None; sftp=None; client=None; token=getattr(payload,"job_token","")
        phase="connecting"; launched=False
        connection_context={}
        def observe(**values):
            nonlocal phase, connection_context
            phase=values.get("phase",phase)
            connection_context=values.get("connection_context",connection_context)
            progress(**values)
        try:
            if stop.is_set(): return RunResult(None,disconnected=True,termination={"state":"not_started","remote_group_terminated":True})
            client=self._connect(payload.ssh_settings,stop,observe)
            if stop.is_set(): return RunResult(None,disconnected=True,termination={"state":"not_started","remote_group_terminated":True})
            operation=getattr(payload,"operation","command")
            roots=getattr(payload,"policy_roots",())
            try:
                first = shlex.split(getattr(payload, "command", ""))[0]
            except (ValueError, IndexError):
                first = ""
            direct_git = operation == "command" and first.rsplit('/', 1)[-1] == 'git'
            if (operation!="command" and operation not in SERVICE_OPS) or roots or direct_git:
                from .filesystem import resolve_path, operation as file_operation
                from .policies import scope_contains
                observe(phase="opening_sftp")
                sftp=client.open_sftp(); sftp.get_channel().settimeout(5)
                observe(phase="checking_cwd")
                if roots:
                    args=json.loads(payload.arguments)
                    target=resolve_path(sftp,args.get("path",payload.cwd),payload.cwd)
                    canonical=sftp.normalize(target)
                    if not scope_contains(canonical,roots): raise ValueError("实际目标目录不在本地自动授权范围内")
                    if operation=="command" and payload.policy_category=="read_fs":
                        from .readonly import scoped_read_paths
                        for arg in scoped_read_paths(payload.command):
                            operand=resolve_path(sftp,arg,payload.cwd)
                            if not scope_contains(operand,roots): raise ValueError("命令参数路径超出自动授权目录")
                            actual=sftp.normalize(operand)
                            if not scope_contains(actual,roots): raise ValueError("命令参数路径超出自动授权目录")
                if operation == "inspect_repository":
                    from .git_policy import inspect_repository
                    result = inspect_repository(client, sftp, args["path"] if roots else json.loads(payload.arguments)["path"],
                                                stop, payload.github_hosts)
                    return RunResult(0, result=result)
                if direct_git:
                    from .git_policy import check_git_command
                    observe(phase="checking_repository")
                    context = check_git_command(client, sftp, payload.command, payload.cwd, stop,
                                                payload.policy_category, payload.github_hosts)
                    if roots and context.get("repo_path") and not scope_contains(context["repo_path"], roots):
                        raise ValueError("实际 Git 仓库根目录超出授权范围")
                if operation!="command" and operation not in SERVICE_OPS:
                    result=file_operation(sftp,payload,self.transfers,stop,observe)
                    return RunResult(0,result=result)
            observe(phase="executing")
            authorizer = getattr(self, "execution_authorizer", None)
            if authorizer:
                authorizer(payload)
            channel=client.get_transport().open_session(timeout=15)
            channel.settimeout(5)
            if stop.is_set(): return RunResult(None,disconnected=True,termination={"state":"not_started","remote_group_terminated":True})
            if authorizer:
                authorizer(payload)
            channel.exec_command(payload.remote_command); launched=True
            channel.shutdown_write()
            deadline=time.monotonic()+payload.timeout_seconds+10
            metadata=None; next_metadata=time.monotonic()+.1
            while True:
                while channel.recv_ready(): emit("stdout",channel.recv(4096))
                while channel.recv_stderr_ready(): emit("stderr",channel.recv_stderr(4096))
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    code=channel.recv_exit_status()
                    return RunResult(code,timed_out=code in {124,137})
                if token and metadata is None and time.monotonic()>=next_metadata:
                    metadata=self._control_read(client,token); next_metadata=time.monotonic()+.5
                    if metadata: observe(pid=metadata[0],pgid=metadata[0])
                if stop.wait(.05):
                    observe(phase="terminating")
                    termination=self._terminate_job(client,token)
                    # Drain any output already delivered; this is independent of stop verification.
                    while channel.recv_ready(): emit("stdout",channel.recv(4096))
                    while channel.recv_stderr_ready(): emit("stderr",channel.recv_stderr(4096))
                    return RunResult(None,disconnected=True,termination=termination)
                if time.monotonic()>=deadline:
                    return RunResult(None,timed_out=True,termination=self._terminate_job(client,token))
        except InterruptedError as exc:
            return RunResult(None,disconnected=True,error=str(exc),termination={"state":"sftp_cancelled","remote_group_terminated":True})
        except TimeoutError as exc:
            return RunResult(None,timed_out=True,error=f"{phase}: [{connection_context.get('role','target')} {connection_context.get('host_alias',payload.ssh_settings.hostname)}] {exc}")
        except PromptCancelled:
            return RunResult(None,disconnected=True,error=f"{phase}: [{connection_context.get('role','target')} {connection_context.get('host_alias',payload.ssh_settings.hostname)}] 本地 SSH 输入已取消或超时",termination={"state":"not_started","remote_group_terminated":True})
        except paramiko.BadHostKeyException:
            return RunResult(None,error=f"handshaking_ssh: [{connection_context.get('role','target')} {connection_context.get('host_alias',payload.ssh_settings.hostname)}] 主机指纹与 ~/.ssh/known_hosts 不符，已拒绝连接")
        except paramiko.AuthenticationException as exc:
            return RunResult(None,timed_out=failure_code(exc, phase)=="timeout",
                             error=f"authenticating: [{connection_context.get('role','target')} {connection_context.get('host_alias',payload.ssh_settings.hostname)}] SSH 认证失败；密码未保存")
        except Exception as exc:
            termination=self._terminate_job(client,token) if client and launched else {}
            if stop.is_set() and not launched:
                return RunResult(None,disconnected=True,error=f"{phase}: [{connection_context.get('role','target')} {connection_context.get('host_alias',payload.ssh_settings.hostname)}] {type(exc).__name__}: {exc}",
                                 termination={"state":"sftp_or_connection_cancelled","remote_group_terminated":True})
            return RunResult(None,timed_out=failure_code(exc, phase)=="timeout",
                             error=f"{phase}: [{connection_context.get('role','target')} {connection_context.get('host_alias',payload.ssh_settings.hostname)}] {type(exc).__name__}: {exc}",termination=termination)
        finally:
            if sftp: sftp.close()
            if channel: channel.close()
