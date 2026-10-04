from __future__ import annotations

import hashlib
import codecs
from copy import deepcopy
import json
import os
import posixpath
import re
import secrets
import shlex
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Config, Server, checked_text, integer, write_config
from .readonly import readonly_command
from .policies import python_test_command, scope_contains
from .transfers import TransferStore, safe_name, zip_members
from .ssh import SSHRunner, SSHSettings, build_remote_command, resolve_settings
from .credentials import CredentialStore
from .ssh_trace import MAX_CONNECTION_EVENTS


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Payload:
    server_id: str
    server_label: str
    ssh_target: str
    command: str
    cwd: str
    reason: str
    timeout_seconds: int
    remote_command: str
    ssh_settings: SSHSettings
    executed_command: str = ""
    readonly_eligible: bool = False
    readonly_explanation: str = ""
    operation: str = "command"
    arguments: str = "{}"
    job_token: str = ""
    policy_category: str = ""
    policy_roots: tuple[str, ...] = ()
    session_id: str = ""

    def digest(self) -> str:
        raw = json.dumps(asdict(self), ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass
class Request:
    id: str
    client_request_id: str
    payload: Payload
    created_at: str
    expires_monotonic: float
    status: str = "pending_approval"
    approved_at: str | None = None
    approval_kind: str = "none"
    finished_at: str | None = None
    exit_code: int | None = None
    error: str = ""
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    output_truncated: bool = False
    stop: threading.Event = field(default_factory=threading.Event)
    phase: str = "waiting_approval"
    phase_history: list = field(default_factory=list)
    connection_context: dict = field(default_factory=dict)
    connection_events: list = field(default_factory=list)
    connection_event_seq: int = 0
    started_monotonic: float | None = None
    ended_monotonic: float | None = None
    last_output_at: str | None = None
    pid: int | None = None
    pgid: int | None = None
    progress_bytes: int = 0
    total_bytes: int | None = None
    result: dict = field(default_factory=dict)
    termination_requested: bool = False
    termination: dict = field(default_factory=dict)


class ApprovalManager:
    """Admission uses the local policy or a local GUI approval, never a remote approval tool."""

    def __init__(self, config: Config, *, runner=None, audit_path: Path | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.config = config
        self.runner = runner if runner is not None else SSHRunner(credentials=CredentialStore())
        self.audit_path = audit_path or config.root / "logs/audit.jsonl"
        self.clock = clock
        self._lock = threading.RLock()
        self._requests: dict[str, Request] = {}
        self._client_ids: dict[str, str] = {}
        self._workers: list[threading.Thread] = []
        self._closed = False
        self._approval_available = False
        self._approval_heartbeat = 0.0
        self.transfers = TransferStore(config.root)
        self.sessions: dict[str, dict] = {}
        self.server_info: dict[str, dict] = {}
        self._job_secret = secrets.token_bytes(32)
        if isinstance(self.runner, SSHRunner):
            self.runner.transfers = self.transfers

    def local_set_readonly(self, enabled: bool) -> None:
        with self._lock:
            updated = write_config(self.config, auto_allow_readonly=enabled)
            self.config = updated
            if not enabled:
                for request in self._requests.values():
                    if request.status == "queued_readonly":
                        request.status = "pending_approval"
            else:
                # Turning the switch on applies to NEW requests; existing manual requests stay manual.
                self._start_readonly_queue()

    def local_add_server(self, server: Server) -> None:
        with self._lock:
            self.config = write_config(self.config, server=server)

    def local_update_server(self, server: Server) -> None:
        with self._lock:
            self._ensure_server_idle(server.id)
            self.config = write_config(self.config, server=server, replace_server=True)
            if hasattr(self.runner, "close_connection"):
                self.runner.close_connection(server.id)

    def local_remove_server(self, server_id: str) -> None:
        with self._lock:
            self._ensure_server_idle(server_id)
            self.config = write_config(self.config, remove_server_id=server_id)
            if hasattr(self.runner, "close_connection"):
                self.runner.close_connection(server_id)

    def _ensure_server_idle(self, server_id: str) -> None:
        if any(r.payload.server_id == server_id and r.status in {"running", "pending_approval", "queued_readonly"}
               for r in self._requests.values()):
            raise ValueError("此连接还有未完成请求，请先完成、撤回或断开请求")
        if any(s["server_id"] == server_id for s in self.sessions.values()):
            raise ValueError("请先关闭此服务器上的受控会话")

    def local_save_settings(self, settings: dict) -> None:
        with self._lock:
            self.config = write_config(self.config, settings=settings)

    def local_gui_heartbeat(self) -> None:
        with self._lock:
            self._approval_available = True
            self._approval_heartbeat = self.clock()
            try:
                self._start_readonly_queue()
            except OSError:
                pass

    def _audit(self, event: str, request: Request) -> None:
        # Store metadata and a digest, not command contents, credentials or output.
        item = {"time": timestamp(), "event": event, "request_id": request.id,
                "server_id": request.payload.server_id, "digest": request.payload.digest(),
                "status": request.status, "exit_code": request.exit_code,
                "approval_kind": request.approval_kind}
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as out:
            out.write(json.dumps(item, ensure_ascii=False) + "\n")
            out.flush()
            os.fsync(out.fileno())

    def _expire(self) -> None:
        for request in self._requests.values():
            if request.status in {"pending_approval", "queued_readonly"} and self.clock() >= request.expires_monotonic:
                request.status = "expired"
                request.finished_at = timestamp()
                request.phase = "finished"
                self._release_transfer(request)
                try:
                    self._audit("expired", request)
                except OSError:
                    pass  # Expiration is always allowed to prevent execution.

    def _find(self, request_id: str) -> Request:
        if request_id not in self._requests:
            raise ValueError("请求不存在或后端已重启；旧审批不会恢复")
        return self._requests[request_id]

    def submit(self, server_id: str, command: str, reason: str, client_request_id: str,
               cwd: str = "", timeout_seconds: int = 300, *, session_id: str = "", session_revision: int = 0) -> dict:
        server = self.config.server(server_id)
        command = checked_text(command.replace("\r\n", "\n"), "命令", multiline=True)
        reason = checked_text(reason, "执行目的", multiline=True)
        if len(command.encode("utf-8")) > 32768 or len(reason) > 2000:
            raise ValueError("命令最多 32 KiB，执行目的最多 2000 字符")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", client_request_id):
            raise ValueError("client_request_id 需要 1–80 个字母、数字或 . _ : -")
        cwd = checked_text(cwd or server.default_cwd, "工作目录")
        if not (cwd in {".", "~"} or cwd.startswith("~/") or cwd.startswith("/")):
            raise ValueError("工作目录必须是绝对路径、~、~/子目录或 .")
        integer(timeout_seconds, 1, self.config.max_command_timeout_seconds, "执行时限")
        decision = readonly_command(command)
        if not decision.allowed and "python_tests" in server.auto_categories and scope_contains(cwd, server.auto_roots):
            decision = python_test_command(command)
        category = decision.category
        eligible = decision.allowed and (not server.auto_categories or category in server.auto_categories)
        if category == "python_tests" and not server.auto_categories:
            eligible = False
        roots = server.auto_roots if server.auto_categories and eligible else ()
        if roots and not scope_contains(cwd, roots): eligible = False
        if not eligible: roots = ()
        executed = decision.executable_command if decision.allowed else command
        token = hashlib.sha256(self._job_secret + client_request_id.encode()).hexdigest()[:32]
        remote = build_remote_command(executed, cwd, timeout_seconds, token)
        payload = Payload(server_id, server.label, server.ssh_target, command, cwd, reason,
                          timeout_seconds, remote, resolve_settings(self.config, server),
                          executed, eligible, decision.explanation,
                          arguments=json.dumps({"session_revision":session_revision}) if session_id else "{}", job_token=token,
                          policy_category=category, policy_roots=tuple(roots),session_id=session_id)
        return self._admit(payload, client_request_id)

    def _admit(self, payload: Payload, client_request_id: str) -> dict:
        with self._lock:
            self._expire()
            if self._closed:
                raise ValueError("本地审批窗口已关闭，后端不接受命令")
            if not self._approval_available or self.clock() - self._approval_heartbeat > 5:
                raise ValueError("本地审批窗口未运行或未响应；未提交任何远程命令")
            if client_request_id in self._client_ids:
                previous = self._find(self._client_ids[client_request_id])
                if previous.payload != payload:
                    raise ValueError("相同 client_request_id 不可替换命令、目标或执行参数")
                return self._view(previous)
            if sum(r.status in {"pending_approval", "queued_readonly"} for r in self._requests.values()) >= 20:
                raise ValueError("已有 20 条待审批请求，请先处理")
            if len(self._requests) >= 200:
                raise ValueError("本次会话已达 200 条请求上限；处理完后重启后端")
            request = Request(str(uuid.uuid4()), client_request_id, payload, timestamp(),
                              self.clock() + self.config.approval_timeout_seconds)
            if self.config.auto_allow_readonly and payload.readonly_eligible:
                request.status = "queued_readonly"
            self._audit("submitted", request)  # Fail closed if audit cannot be written.
            self._requests[request.id] = request
            self._client_ids[client_request_id] = request.id
            self._start_readonly_queue()
            return self._view(request)

    def submit_operation(self, server_id: str, operation: str, arguments: dict, reason: str,
                         client_request_id: str, timeout_seconds: int = 300) -> dict:
        server = self.config.server(server_id)
        allowed = {"list_directory", "read_file", "stat_path", "find_files", "test_connection",
                   "download_file", "download_directory", "upload_file", "upload_directory",
                   "create_session", "update_session"}
        if operation not in allowed or not isinstance(arguments, dict): raise ValueError("操作类型无效")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", client_request_id): raise ValueError("client_request_id 无效")
        reason=checked_text(reason,"执行目的",multiline=True)
        if len(reason)>2000: raise ValueError("执行目的最多 2000 字符")
        integer(timeout_seconds,1,self.config.max_command_timeout_seconds,"执行时限")
        args=dict(arguments)
        permitted = {
            "list_directory": {"path", "offset", "limit"}, "stat_path": {"path"},
            "read_file": {"path", "offset", "limit"}, "find_files": {"path", "pattern", "max_depth", "limit"},
            "test_connection": {"path"}, "download_file": {"path"}, "download_directory": {"path"},
            "upload_file": {"path", "transfer_id", "overwrite"}, "upload_directory": {"path", "transfer_id"},
            "create_session": {"path", "session_id", "environment"},
            "update_session": {"path", "session_id", "environment", "expected_revision"}}
        if set(args)-permitted[operation]: raise ValueError("包含此操作不支持的参数")
        if operation in {"list_directory", "read_file"}:
            integer(args.get("offset",0),0,1<<50,"文件/目录偏移")
            integer(args.get("limit",200 if operation=="list_directory" else 16384),1,200 if operation=="list_directory" else 16384,"读取数量")
        if operation=="find_files":
            pattern=checked_text(args.get("pattern",""),"搜索模式")
            if len(pattern)>256 or "/" in pattern: raise ValueError("搜索模式最多 256 字符，匹配文件名")
            integer(args.get("max_depth",8),0,32,"搜索深度")
            integer(args.get("limit",100),1,200,"匹配数量")
        if "overwrite" in args and type(args["overwrite"]) is not bool: raise ValueError("覆盖选项必须为布尔值")
        path=checked_text(args.get("path",server.default_cwd),"远程路径")
        if len(path)>4096: raise ValueError("路径过长")
        args["path"]=path
        category="diagnostics" if operation=="test_connection" else "read_fs"
        eligible=operation not in {"upload_file","upload_directory","create_session","update_session"}
        eligible=eligible and (not server.auto_categories or category in server.auto_categories)
        roots=server.auto_roots if eligible and server.auto_categories else ()
        # Bound filesystem reads by the actual normalized target at execution.
        if roots and not scope_contains(path,roots): eligible=False
        if not eligible: roots=()
        leased=False; reserved=False
        tid=args.get("transfer_id","")
        with self._lock:
            existing=self._client_ids.get(client_request_id)
            if existing and operation in {"download_file","download_directory"}:
                old=self._find(existing)
                tid=json.loads(old.payload.arguments).get("transfer_id","")
                args["transfer_id"]=tid
            elif operation in {"download_file","download_directory"}:
                filename=posixpath.basename(path.rstrip("/")) or "root"
                filename=safe_name(filename+(".zip" if operation=="download_directory" else ""))
                tid=self.transfers.reserve_download(filename)["transfer_id"]
                args["transfer_id"]=tid; reserved=True
            if operation in {"upload_file","upload_directory"}:
                item=self.transfers.info(tid)
                if item["direction"]!="upload" or not item["complete"]: raise ValueError("此上传文件尚未完成校验")
                args.update(file_name=item["file_name"],size_bytes=item["size_bytes"],sha256=item["sha256"])
                if operation=="upload_directory": zip_members(self.transfers.path(tid,complete=True))
                if not existing: self.transfers.lease(tid); leased=True
            raw=json.dumps(args,ensure_ascii=False,sort_keys=True)
            payload=Payload(server.id,server.label,server.ssh_target,operation+" "+raw,
                            server.default_cwd,reason,timeout_seconds,"SFTP / "+operation,
                            resolve_settings(self.config,server),operation,eligible,
                            "结构化 SFTP 操作；上传/会话上下文变更需本地审批",operation,raw,
                            policy_category=category,policy_roots=tuple(roots))
            try: return self._admit(payload,client_request_id)
            except BaseException:
                if leased: self.transfers.release(tid)
                if reserved: self.transfers.remove(tid,force=True)
                raise

    def create_session(self, server_id, cwd, environment, reason, client_request_id):
        environment=self._environment(environment)
        # Session ID is derived from a private per-runtime nonce, stable across retries.
        sid=hashlib.sha256(self._job_secret+b"session"+client_request_id.encode()).hexdigest()[:32]
        return self.submit_operation(server_id,"create_session",{"path":cwd or self.config.server(server_id).default_cwd,
            "session_id":sid,"environment":environment},reason,client_request_id)

    @staticmethod
    def _environment(environment):
        if not isinstance(environment,dict) or len(environment)>30: raise ValueError("环境变量需要对象，最多 30 项")
        for k,v in environment.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}",k) or not isinstance(v,str) or len(v)>4096 or "\x00" in v:
                raise ValueError("环境变量名称或内容无效")
        return dict(environment)

    def session_context(self, session_id):
        with self._lock:
            if session_id not in self.sessions: raise ValueError("会话不存在或已关闭")
            return dict(self.sessions[session_id])

    def update_session(self, session_id, cwd, environment, reason, client_request_id):
        session=self.session_context(session_id)
        return self.submit_operation(session["server_id"],"update_session",{
            "path":cwd or session["cwd"],"session_id":session_id,
            "environment":self._environment(environment),"expected_revision":session["revision"]},reason,client_request_id)

    def exec_in_session(self, session_id, command, reason, client_request_id, timeout_seconds=300):
        with self._lock:
            session=self.session_context(session_id)
            environment=session["environment"]
            script="".join("export "+k+"="+shlex.quote(v)+"\n" for k,v in sorted(environment.items()))+command
            # All exports are literal and part of the reviewed digest. A shell process is never reused.
            view=self.submit(session["server_id"],script,reason,client_request_id,session["cwd"],timeout_seconds,session_id=session_id,session_revision=session["revision"])
            return {**view,"session_id":session_id,"session_revision":session["revision"]}

    def close_session(self, session_id):
        with self._lock:
            session=self.sessions.pop(session_id,None)
            return {"session_id":session_id,"closed":True,"existed":session is not None}

    def _release_transfer(self, request):
        args=json.loads(request.payload.arguments)
        tid=args.get("transfer_id")
        if tid:
            if request.payload.operation.startswith("upload_"): self.transfers.release(tid)
            elif request.payload.operation.startswith("download_") and request.status!="succeeded":
                try: self.transfers.remove(tid,force=True)
                except ValueError: pass

    def _view(self, request: Request, offset: int = 0, limit: int = 16384) -> dict:
        stdout = self._output_text(request.stdout, request.status)
        stderr = self._output_text(request.stderr, request.status)
        return {
            "request_id": request.id, "client_request_id": request.client_request_id,
            **asdict(request.payload), "digest": request.payload.digest(), "status": request.status,
            "created_at": request.created_at, "approved_at": request.approved_at,
            "approval_kind": request.approval_kind,
            "finished_at": request.finished_at, "exit_code": request.exit_code, "error": request.error,
            "approval_expires_in_seconds": max(0, int(request.expires_monotonic - self.clock()))
            if request.status in {"pending_approval", "queued_readonly"} else 0,
            "stdout": stdout[offset:offset + limit], "stderr": stderr[offset:offset + limit],
            "output_offset": offset, "next_output_offset": offset + limit,
            "stdout_length": len(stdout), "stderr_length": len(stderr),
            "has_more_output": len(stdout) > offset + limit or len(stderr) > offset + limit,
            "output_truncated": request.output_truncated,
            "approval_location": "Windows 本地审批窗口",
            "remote_stop_guaranteed": False,
            "phase": request.phase, "phase_history": list(request.phase_history),
            "connection_context": dict(request.connection_context),
            "connection_trace_version": 1,
            "connection_events": deepcopy(request.connection_events),
            "connection_event_seq": request.connection_event_seq,
            "connection_events_dropped": request.connection_event_seq - len(request.connection_events),
            "last_output_at": request.last_output_at,
            "runtime_seconds": round((request.ended_monotonic or self.clock())-request.started_monotonic,2) if request.started_monotonic is not None else 0,
            "pid": request.pid, "pgid": request.pgid,
            "progress_bytes": request.progress_bytes, "total_bytes": request.total_bytes,
            "result": request.result, "termination_requested": request.termination_requested,
            "termination": request.termination,
            "next_stdout_cursor": offset+len(stdout[offset:offset+limit]),
            "next_stderr_cursor": offset+len(stderr[offset:offset+limit]),
        }

    def get(self, request_id: str, offset: int = 0, limit: int = 16384) -> dict:
        integer(offset, 0, 8388608, "输出偏移")
        integer(limit, 1, 32768, "输出页大小")
        with self._lock:
            self._expire()
            return self._view(self._find(request_id), offset, limit)

    @staticmethod
    def _output_text(raw, status):
        # Do not publish a replacement character for an incomplete UTF-8 tail:
        # independent character cursors remain stable as the next bytes arrive.
        decoder=codecs.getincrementaldecoder("utf-8")(errors="replace")
        return decoder.decode(bytes(raw),final=status not in {"running","queued_readonly","pending_approval"})

    def list_local(self) -> list[dict]:
        with self._lock:
            self._expire()
            return [self._view(r, limit=1) for r in reversed(list(self._requests.values()))]

    def list_summaries(self) -> list[dict]:
        """Small desktop poll payload: never decode every historical output on each tick."""
        with self._lock:
            self._expire()
            return [{"request_id": r.id, "server_id": r.payload.server_id,
                     "server_label": r.payload.server_label, "reason": r.payload.reason[:240],
                     "command_preview": r.payload.command[:240], "status": r.status,
                     "approval_kind": r.approval_kind, "created_at": r.created_at,
                     "approved_at": r.approved_at, "finished_at": r.finished_at,
                     "exit_code": r.exit_code, "error": r.error,
                     "output_bytes": len(r.stdout) + len(r.stderr), "phase": r.phase,
                     "connection_event_seq": r.connection_event_seq,
                     "operation": r.payload.operation,"last_output_at":r.last_output_at,
                     "pid":r.pid,"pgid":r.pgid,"progress_bytes":r.progress_bytes,
                     "runtime_seconds": round((r.ended_monotonic or self.clock())-r.started_monotonic,1) if r.started_monotonic is not None else 0,
                     "termination_requested":r.termination_requested,
                     "approval_expires_in_seconds": max(0, int(r.expires_monotonic - self.clock()))
                     if r.status in {"pending_approval", "queued_readonly"} else 0}
                    for r in reversed(list(self._requests.values()))]

    def local_approve(self, request_id: str, expected_digest: str) -> None:
        with self._lock:
            self._expire()
            request = self._find(request_id)
            if self._closed or not self._approval_available or self.clock() - self._approval_heartbeat > 5:
                raise ValueError("本地审批窗口已关闭")
            if request.status != "pending_approval":
                raise ValueError("该请求已被处理或过期；不能重复批准")
            if request.payload.digest() != expected_digest:
                raise ValueError("命令摘要不匹配；未执行")
            if any(r.status == "running" for r in self._requests.values()):
                raise ValueError("已有命令正在运行；请完成后再批准下一条")
            self._start(request, "local")

    def _start(self, request: Request, kind: str) -> None:
        request.approval_kind = kind
        try:
            self._audit("auto_readonly_granted" if kind == "auto_readonly" else "approval_granted", request)
        except OSError:
            request.approval_kind = "none"
            raise
        request.status = "running"
        request.approved_at = timestamp()
        request.started_monotonic = self.clock()
        request.phase = "connecting"
        worker = threading.Thread(target=self._run, args=(request,), daemon=True)
        self._workers.append(worker)
        try:
            worker.start()
        except Exception:
            request.status = "failed"
            request.error = "无法启动执行线程；需要新请求重新审批"
            request.finished_at = timestamp()
            raise

    def _start_readonly_queue(self) -> None:
        if (self._closed or not self.config.auto_allow_readonly or not self._approval_available
                or self.clock() - self._approval_heartbeat > 5
                or any(r.status == "running" for r in self._requests.values())):
            return
        self._expire()
        for request in self._requests.values():
            if request.status == "queued_readonly":
                # Recheck the bounded grammar before admission, never rely only on a stored flag.
                if not request.payload.readonly_eligible:
                    request.status = "pending_approval"
                    continue
                if request.payload.operation == "command":
                    decision = (python_test_command(request.payload.command) if request.payload.policy_category == "python_tests"
                                else readonly_command(request.payload.command))
                    if not decision.allowed or decision.executable_command != request.payload.executed_command:
                        request.status = "pending_approval"
                        continue
                self._start(request, "auto_readonly")
                break

    def reject(self, request_id: str) -> dict:
        with self._lock:
            self._expire()
            request = self._find(request_id)
            if request.status not in {"pending_approval", "queued_readonly"}:
                raise ValueError("只能拒绝/撤回待审批请求")
            request.status = "denied"
            request.finished_at = timestamp()
            request.phase = "finished"
            self._release_transfer(request)
            try:
                self._audit("denied", request)
            except OSError:
                pass
            return self._view(request)

    def disconnect_local(self, request_id: str) -> None:
        with self._lock:
            request = self._find(request_id)
            if request.status != "running":
                raise ValueError("该请求未在运行")
            request.stop.set()

    def terminate(self, request_id: str) -> dict:
        with self._lock:
            request=self._find(request_id)
            if request.status in {"pending_approval","queued_readonly"}: return self.reject(request_id)
            if request.status != "running": return self._view(request)
            if not request.termination_requested:
                request.termination_requested=True
                request.phase="terminating"
                request.stop.set()
                try: self._audit("termination_requested",request)
                except OSError: pass
            return self._view(request)

    def read_output(self, request_id, stdout_cursor=0, stderr_cursor=0, limit=16384):
        integer(stdout_cursor,0,8388608,"stdout 游标")
        integer(stderr_cursor,0,8388608,"stderr 游标")
        integer(limit,1,32768,"读取大小")
        with self._lock:
            r=self._find(request_id)
            result=self._view(r,0,1)
            out=self._output_text(r.stdout,r.status)
            err=self._output_text(r.stderr,r.status)
            result.update(stdout=out[stdout_cursor:stdout_cursor+limit],stderr=err[stderr_cursor:stderr_cursor+limit],
                          next_stdout_cursor=min(len(out),stdout_cursor+limit),next_stderr_cursor=min(len(err),stderr_cursor+limit),
                          has_more_output=len(out)>stdout_cursor+limit or len(err)>stderr_cursor+limit)
            return result

    def _run(self, request: Request) -> None:
        def emit(name: str, chunk: bytes):
            with self._lock:
                stream = request.stdout if name == "stdout" else request.stderr
                available = max(0, self.config.output_limit_bytes - len(request.stdout) - len(request.stderr))
                stream.extend(chunk[:available])
                request.last_output_at = timestamp()
                if len(chunk) > available:
                    request.output_truncated = True
        def progress(**values):
            with self._lock:
                if request.status != "running":
                    return
                context = values.get("connection_context", request.connection_context)
                if "connection_event" in values:
                    request.connection_event_seq += 1
                    request.connection_events.append({**deepcopy(values["connection_event"]),
                                                      "seq": request.connection_event_seq,
                                                      "connection_context": dict(context)})
                    del request.connection_events[:-MAX_CONNECTION_EVENTS]
                if "phase" in values:
                    phase=values["phase"]
                    if request.phase != phase or request.connection_context != context:
                        request.phase_history.append({"phase":phase,"at":timestamp(),"connection_context":dict(context)})
                    if not request.termination_requested: request.phase=phase
                request.connection_context = dict(context)
                for key in ("pid","pgid","progress_bytes","total_bytes"):
                    if key in values: setattr(request,key,values[key])
        try:
            if hasattr(self.runner,"execute"):
                result = self.runner.execute(request.payload,emit,request.stop,progress)
            else:
                result = self.runner(request.payload, emit, request.stop)
            with self._lock:
                request.exit_code = result.exit_code
                request.error = result.error
                request.result = getattr(result,"result",None) or {}
                request.termination = getattr(result,"termination",None) or {}
                request.status = (("terminated" if request.termination.get("remote_group_terminated") else "termination_unconfirmed") if request.termination_requested and result.disconnected else "disconnected" if result.disconnected else "timed_out" if result.timed_out
                                  else "succeeded" if result.exit_code == 0 and not result.error else "failed")
        except Exception as exc:
            with self._lock:
                request.status = "failed"
                request.error = f"执行后端错误: {type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                request.finished_at = timestamp()
                request.ended_monotonic = self.clock()
                request.phase = "finished"
                if request.status == "succeeded":
                    op=request.payload.operation; args=json.loads(request.payload.arguments)
                    if op in {"create_session","update_session"}:
                        sid=args["session_id"]
                        previous=self.sessions.get(sid)
                        if op=="update_session" and (not previous or previous["revision"]!=args["expected_revision"]):
                            request.status="failed"; request.error="会话已关闭或上下文版本变化，请重新提交"
                        else:
                            session={"session_id":sid,"server_id":request.payload.server_id,
                                     "cwd":request.result["cwd"],"environment":args["environment"],
                                     "revision":(previous["revision"]+1) if previous else 1}
                            self.sessions[sid]=session; request.result=dict(session)
                    elif op=="test_connection": self.server_info[request.payload.server_id]={**request.result,"checked_at":timestamp()}
                if request.payload.operation=="test_connection":
                    self.server_info[request.payload.server_id]={**request.result,"success":request.status=="succeeded",
                        "checked_at":timestamp(),"error":request.error,
                        "failure_phase":request.phase_history[-1]["phase"] if request.error and request.phase_history else None}
                self._release_transfer(request)
                try:
                    self._audit("finished", request)
                except OSError:
                    request.error += "；执行已结束，但审计记录写入失败"
                try:
                    self._start_readonly_queue()
                except OSError:
                    # Queue remains unexecuted if admission audit fails.
                    pass

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._approval_available = False
            for request in self._requests.values():
                if request.status in {"pending_approval", "queued_readonly"}:
                    request.status = "denied"
                    request.finished_at = timestamp()
                    self._release_transfer(request)
                    try:
                        self._audit("denied_on_close", request)
                    except OSError:
                        pass
                elif request.status == "running":
                    request.termination_requested=True
                    request.phase="terminating"
                    request.stop.set()
        prompts=getattr(self.runner,"prompts",None)
        if prompts: prompts.close()
        for worker in self._workers:
            worker.join(timeout=15)
        if hasattr(self.runner, "close"):
            self.runner.close()
