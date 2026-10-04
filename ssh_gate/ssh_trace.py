"""Connection telemetry for the desktop UI (Paramiko 4.x).

Only selected protocol facts are emitted. Never forward Paramiko debug logs,
authentication arguments, private keys, or arbitrary exception messages.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import socket
import threading
import time
from datetime import datetime, timezone

import paramiko

from .prompts import PromptCancelled


MAX_CONNECTION_EVENTS = 256


class HostKeyRejected(PromptCancelled):
    pass


def protocol_text(value: str) -> str:
    # A server controls its version string. Keep only the protocol/software
    # token, not free-form banner comments or terminal control characters.
    return "".join(c for c in str(value).split(" ", 1)[0][:255] if 32 <= ord(c) < 127)


def host_key_info(key) -> dict:
    digest = hashlib.sha256(key.asbytes()).digest()
    return {"key_type": key.get_name(), "key_bits": key.get_bits(),
            "fingerprint": "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")}


def failure_code(exc: Exception, stage: str, stopped: bool = False) -> str:
    if isinstance(exc, HostKeyRejected):
        return "host_key_rejected"
    if stopped or isinstance(exc, PromptCancelled):
        return "cancelled"
    if isinstance(exc, paramiko.BadHostKeyException):
        return "host_key_mismatch"
    if isinstance(exc, paramiko.ssh_exception.IncompatiblePeer):
        return "protocol_mismatch" if stage == "ssh_banner" else "algorithm_mismatch"
    if isinstance(exc, socket.gaierror):
        return "dns_failed"
    if isinstance(exc, TimeoutError):
        return "timeout"
    cause = exc.__cause__ or exc.__context__
    if isinstance(cause, TimeoutError):
        return "timeout"
    if isinstance(exc, OSError) and exc.errno in {errno.ECONNREFUSED, 10061}:
        return "connection_refused"
    if isinstance(exc, (ConnectionResetError, EOFError)):
        return "connection_lost"
    if isinstance(exc, paramiko.ssh_exception.ProxyCommandFailure):
        return "proxy_failed"
    # Paramiko wraps some banner/auth timeouts in SSHException. Inspect only
    # for classification; the original exception text is never put in events.
    if isinstance(exc, paramiko.SSHException):
        if "timeout" in str(exc).lower() or "timed out" in str(exc).lower():
            return "timeout"
        if isinstance(exc, (paramiko.AuthenticationException, paramiko.PasswordRequiredException)):
            return "authentication_failed"
        return "ssh_error"
    return "connection_error"


class ConnectionTrace:
    """One hop, multiple network/authentication attempts, one route clock."""
    def __init__(self, progress, route_started: float):
        self._progress = progress
        self._started = route_started
        self._hop_started = time.monotonic()
        self._lock = threading.RLock()
        self.attempt = 0
        self.stage = "connecting"
        self.trust_source = "known_hosts"

    def emit(self, event: str, *, stage: str | None = None, **data):
        with self._lock:
            if self._progress is None:
                return
            if stage is not None:
                self.stage = stage
            now = time.monotonic()
            self._progress(connection_event={
                "event": event, "stage": self.stage, "attempt": self.attempt,
                "at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "elapsed_ms": round((now - self._started) * 1000, 3),
                "hop_elapsed_ms": round((now - self._hop_started) * 1000, 3),
                "data": data,
            })

    def fail(self, exc: Exception, stop: threading.Event):
        code = failure_code(exc, self.stage, stop.is_set())
        data = {"code": code}
        if isinstance(exc, paramiko.BadHostKeyException):
            data.update(host_key_info(exc.key))
            data["expected_fingerprint"] = host_key_info(exc.expected_key)["fingerprint"]
        self.emit("connection_cancelled" if code == "cancelled" else "connection_failed", **data)

    def close(self):
        with self._lock:
            self._progress = None


class ObservedTransport(paramiko.Transport):
    """Observe completed protocol operations; always delegate validation.

    _check_banner / _parse_kex_init are the only private Transport hooks.
    Keep their coverage against the project's locked Paramiko version.
    """
    def __init__(self, *args, trace: ConnectionTrace, allowed_keys=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_trace = trace
        self.allowed_identity_keys = allowed_keys
        self.negotiated_kex = None
        self.auth_method = None
        self._reported_authentication = False

    def _event(self, event, **data):
        trace = self.connection_trace
        if trace is not None:
            trace.emit(event, **data)

    def _check_banner(self):
        result = super()._check_banner()
        self._event("banner_received", stage="ssh_banner",
                    client_version=protocol_text(self.local_version),
                    server_version=protocol_text(self.remote_version))
        self._event("key_exchange_started", stage="key_exchange")
        return result

    def _parse_kex_init(self, message):
        # Inspect a copy: do not advance or alter Paramiko's original packet.
        offered = paramiko.Message(message.get_remainder())
        offered.get_bytes(16)  # cookie
        kex_names = offered.get_list()
        result = super()._parse_kex_init(message)
        # Selection has succeeded. Use the same client preference order and
        # confirm the selected engine instead of publishing the proposal list.
        selected = next((name for name in self.preferred_kex if name in kex_names), None)
        if selected and type(self.kex_engine) is self._kex_info.get(selected):
            self.negotiated_kex = selected
        self._event("algorithms_negotiated", stage="key_exchange", **self.algorithms())
        return result

    def algorithms(self):
        return {"kex": self.negotiated_kex, "host_key_algorithm": self.host_key_type,
                "cipher_out": self.local_cipher, "cipher_in": self.remote_cipher,
                "mac_out": self.local_mac, "mac_in": self.remote_mac,
                "compression_out": self.local_compression, "compression_in": self.remote_compression}

    def public_summary(self):
        return {"client_version": protocol_text(self.local_version),
                "server_version": protocol_text(self.remote_version),
                **self.algorithms(), **host_key_info(self.get_remote_server_key()),
                "auth_method": self.auth_method}

    def start_client(self, *args, **kwargs):
        result = super().start_client(*args, **kwargs)
        # SSHClient uses the blocking form. Paramiko may return on its deadline
        # while negotiation is still running; that is not a completed handshake.
        if not self.initial_kex_done:
            raise TimeoutError("SSH 握手超时")
        self._event("host_key_received", stage="host_key", **host_key_info(self.get_remote_server_key()))
        return result

    def _authenticate(self, method, callback, *args, **kwargs):
        self._event("authentication_method_started", stage="authentication", method=method)
        try:
            result = callback(*args, **kwargs)
        except paramiko.AuthenticationException:
            self._event("authentication_method_failed", method=method)
            raise
        if self.is_authenticated() and not self._reported_authentication:
            self._reported_authentication = True
            self.auth_method = getattr(self.auth_handler, "auth_method", method)
            self._event("authenticated", method=self.auth_method)
        elif not self.is_authenticated():
            self._event("authentication_partial", method=method)
        return result

    def auth_publickey(self, username, key, *args, **kwargs):
        if self.allowed_identity_keys is not None and key.asbytes() not in self.allowed_identity_keys:
            raise paramiko.AuthenticationException("密钥未在此 Host 的 IdentityFile 中配置")
        return self._authenticate("publickey", super().auth_publickey, username, key, *args, **kwargs)

    def auth_password(self, *args, **kwargs):
        return self._authenticate("password", super().auth_password, *args, **kwargs)

    def auth_interactive(self, *args, **kwargs):
        return self._authenticate("keyboard-interactive", super().auth_interactive, *args, **kwargs)


class ObservedSSHClient(paramiko.SSHClient):
    def __init__(self, trace: ConnectionTrace, progress):
        super().__init__()
        self.connection_trace = trace
        self.connection_progress = progress

    def _auth(self, *args, **kwargs):
        # SSHClient.connect has already checked known_hosts / completed the
        # missing-key policy before invoking this authentication entry point.
        self.connection_trace.emit("host_key_verified", stage="host_key",
                                   source=self.connection_trace.trust_source)
        self.connection_progress(phase="authenticating")
        self.connection_trace.emit("authentication_started", stage="authentication")
        return super()._auth(*args, **kwargs)

    def detach_trace(self):
        self.connection_trace = None
        self.connection_progress = None
        transport = self.get_transport()
        if isinstance(transport, ObservedTransport):
            transport.connection_trace = None
