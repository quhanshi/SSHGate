"""This Windows PC as an approval-gated target, bounded by configured workspace directories.

File operations resolve links and directory junctions and stay inside the workspace.
Commands are PowerShell in a fresh process that starts in the workspace; they run with the
current Windows user's rights, so per-command local approval is their boundary, not the path.
"""
from __future__ import annotations

import base64
import ctypes
import fnmatch
import getpass
import json
import ntpath
import os
import platform
import stat
import subprocess
import tempfile
import threading
import time
import zipfile
from ctypes import wintypes as wt
from pathlib import Path

from .local_terminal import find_shell, shell_environment
from .ssh import RunResult
from .ssh_config import SSHSettings
from .transfers import MAX_FILES, MAX_TRANSFER_BYTES, zip_members
from .winpath import check_component, ps_quote, within

SHELL_ARGS = ("-NoLogo", "-NoProfile", "-NonInteractive", "-Command")
_NAME_SURROGATE = 0x20000000
_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


def local_settings(server) -> SSHSettings:
    """Connection metadata for views and digests; nothing here opens a network connection."""
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    return SSHSettings(platform.node() or "localhost", user, 0, (), (), connection_id=server.id,
                       host_alias="本机", config_source="本机工作区")


def build_script(command: str, cwd: str) -> str:
    """The exact PowerShell text that is reviewed and run. Native exit codes are preserved."""
    return ("$ProgressPreference = 'SilentlyContinue'\n"
            "try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding } catch {}\n"
            f"try {{ Set-Location -LiteralPath {ps_quote(cwd)} -ErrorAction Stop }} "
            "catch { [Console]::Error.WriteLine('无法进入工作目录：' + $_.Exception.Message); exit 125 }\n"
            "$global:LASTEXITCODE = 0\n"
            f"{command}\n"
            "if ($?) { exit 0 }\n"
            "if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n"
            "exit 1\n")


def launch_description(shell: str) -> str:
    return f"{ntpath.basename(shell)} {' '.join(SHELL_ARGS)} <读取并执行上方脚本> · 新进程 · 无配置文件 · 结束时清理进程树"


def _bootstrap(path: str) -> str:
    # A script block is not subject to the execution policy that would block a .ps1 file.
    quoted = ps_quote(path)
    return (f"$ErrorActionPreference='Stop';$s=[IO.File]::ReadAllText({quoted});"
            f"Remove-Item -LiteralPath {quoted} -Force;$ErrorActionPreference='Continue';& ([ScriptBlock]::Create($s))")


def _kind(st) -> str:
    # Name-surrogate reparse points are symbolic links and directory junctions; they are never followed
    # while walking. Other reparse points (OneDrive placeholders, dedup) are ordinary files and folders.
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) & _NAME_SURROGATE:
        return "symlink"
    return "directory" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "special"


def _attributes(path: str, st) -> dict:
    return {"path": path, "name": ntpath.basename(path) or path, "type": _kind(st),
            "size_bytes": st.st_size, "mtime": st.st_mtime}


class Workspace:
    def __init__(self, roots):
        self.roots = tuple(roots)
        real = []
        for root in self.roots:
            try:
                path = Path(root).resolve(strict=True)
            except OSError:
                continue
            if path.is_dir():
                real.append(str(path))
        if not real:
            raise ValueError("工作区目录都不存在或无法访问")
        self.real_roots = tuple(real)

    def resolve(self, path: str) -> Path:
        """Follow links and junctions, then require the real target to be inside a real workspace root."""
        try:
            real = Path(path).resolve(strict=True)
        except FileNotFoundError:
            raise ValueError(f"路径不存在：{path}") from None
        except OSError as exc:
            raise ValueError(f"无法访问 {path}：{exc.strerror or exc}") from None
        if not within(str(real), self.real_roots):
            raise ValueError(f"{path} 的实际位置在工作区以外（经过符号链接或目录联接）")
        return real

    def locate(self, path: str):
        """Real parent directory inside the workspace and the final name, without following the final name."""
        path = ntpath.normpath(path)
        if any(ntpath.normcase(path) == ntpath.normcase(r) for r in self.roots):
            return self.resolve(path), None
        parent, name = ntpath.split(path)
        real = self.resolve(parent)
        if not real.is_dir():
            raise ValueError("父目录不是目录")
        return real, check_component(name)


def operation(payload, store, stop, progress) -> dict:
    args = json.loads(payload.arguments)
    kind, lexical = payload.operation, args["path"]
    deadline = time.monotonic() + payload.timeout_seconds
    progress(phase="checking_workspace")
    workspace = Workspace(payload.workspace_roots)

    def check():
        if stop.is_set():
            raise InterruptedError("已终止本机文件操作")
        if time.monotonic() > deadline:
            raise TimeoutError("本机文件操作超过执行时限")

    unreadable = 0

    def walk(real_root, lexical_root, depth_limit):
        nonlocal unreadable
        pending, visited = [(real_root, lexical_root, 0)], 0
        while pending:
            real, lex, depth = pending.pop()
            try:
                with os.scandir(real) as entries:
                    rows = list(entries)
            except PermissionError:
                unreadable += 1
                continue
            for entry in rows:
                check()
                visited += 1
                if visited > MAX_FILES:
                    raise ValueError("扫描达到 5000 项上限，请缩小根目录")
                st = entry.stat(follow_symlinks=False)
                full = ntpath.join(lex, entry.name)
                yield Path(entry.path), full, st
                if _kind(st) == "directory" and depth < depth_limit:
                    pending.append((Path(entry.path), full, depth + 1))

    def copy(source, out, total, size=None):
        while True:
            check()
            data = source.read(65536)
            if not data:
                return total
            total += len(data)
            if total > MAX_TRANSFER_BYTES:
                raise ValueError("传输超过 64 MiB 上限")
            out.write(data)
            progress(progress_bytes=total, **({"total_bytes": size} if size is not None else {}))

    progress(phase="running_local", progress_bytes=0)
    if kind == "list_directory":
        real = workspace.resolve(lexical)
        if not real.is_dir():
            raise ValueError("目标不是目录")
        with os.scandir(real) as entries:
            names = sorted(entries, key=lambda e: e.name.casefold())
        offset, limit = args.get("offset", 0), args.get("limit", 200)
        rows = [_attributes(ntpath.join(lexical, e.name), e.stat(follow_symlinks=False)) for e in names[offset:offset + limit]]
        return {"path": lexical, "entries": rows, "offset": offset, "next_offset": offset + len(rows),
                "has_more": offset + len(rows) < len(names), "snapshot": False}
    if kind == "stat_path":
        parent, name = workspace.locate(lexical)
        result = _attributes(lexical, os.lstat(parent / name if name else parent))
        if result["type"] == "symlink":
            try:
                workspace.resolve(lexical)
                result["target_inside_workspace"] = True
            except ValueError:
                result["target_inside_workspace"] = False
        return result
    if kind == "read_file":
        real = workspace.resolve(lexical)
        st = real.stat()
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("只允许读取普通文件")
        offset, limit = args.get("offset", 0), args.get("limit", 16384)
        with real.open("rb") as source:
            source.seek(offset)
            data = source.read(limit)
        return {"path": lexical, "offset": offset, "next_offset": offset + len(data), "eof": offset + len(data) >= st.st_size,
                "size_bytes": st.st_size, "text": data.decode("utf-8", errors="replace"),
                "data_base64": base64.b64encode(data).decode("ascii")}
    if kind == "find_files":
        real = workspace.resolve(lexical)
        if not real.is_dir():
            raise ValueError("搜索根目录不是目录")
        pattern, rows, truncated = args["pattern"].casefold(), [], False
        for _real, full, st in walk(real, lexical, args.get("max_depth", 8)):
            if fnmatch.fnmatchcase(ntpath.basename(full).casefold(), pattern):
                rows.append(_attributes(full, st))
                if len(rows) >= args.get("limit", 100):
                    truncated = True
                    break
        return {"root": lexical, "matches": rows, "truncated": truncated, "follow_symlinks": False,
                "unreadable_directories": unreadable}
    if kind == "test_connection":
        real = workspace.resolve(lexical)
        if not real.is_dir():
            raise ValueError("默认工作目录不是目录")
        shell = find_shell()
        return {"local": True, "hostname": platform.node(), "os_release": platform.platform(),
                "user": payload.ssh_settings.username, "shell": shell.name if shell else "",
                "default_cwd": lexical, "default_cwd_exists": True,
                "workspace_roots": [{"path": r, "exists": Path(r).is_dir()} for r in payload.workspace_roots]}
    if kind in {"download_file", "download_directory"}:
        tid, skipped = args["transfer_id"], 0
        try:
            real = workspace.resolve(lexical)
            if kind == "download_file":
                st = real.stat()
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError("下载目标必须是普通文件")
                if st.st_size > MAX_TRANSFER_BYTES:
                    raise ValueError("下载超过 64 MiB 上限")
                with real.open("rb") as source, store.path(tid).open("wb") as out:
                    copy(source, out, 0, st.st_size)
            else:
                if not real.is_dir():
                    raise ValueError("打包目标必须是目录")
                total = 0
                with zipfile.ZipFile(store.path(tid), "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
                    for path, full, st in walk(real, lexical, 32):
                        relative = ntpath.relpath(full, lexical).replace("\\", "/")
                        entry = _kind(st)
                        if entry == "file":
                            if st.st_size > MAX_TRANSFER_BYTES - total:
                                raise ValueError("下载超过 64 MiB 上限")
                            with path.open("rb") as source, archive.open(relative, "w") as target:
                                total = copy(source, target, total)
                        elif entry == "directory":
                            archive.writestr(relative + "/", b"")
                        else:
                            skipped += 1
            result = store.finish_download(tid)
            if kind == "download_directory":
                result["skipped_links_or_special_files"] = skipped
                result["unreadable_directories"] = unreadable
            return result
        except BaseException:
            store.remove(tid, force=True)
            raise
    if kind in {"upload_file", "upload_directory"}:
        tid = args["transfer_id"]
        local, info = store.path(tid, complete=True), store.info(tid)
        if store._hash(local) != info["sha256"]:
            raise ValueError("上传缓存被修改，拒绝执行")
        parent, name = workspace.locate(lexical)
        if not name:
            raise ValueError("目标不能是工作区根目录本身")

        def write_file(directory: Path, filename: str, source, size, overwrite=False):
            check()
            target = directory / filename
            existing = None
            try:
                existing = os.lstat(target)
            except FileNotFoundError:
                pass
            if existing is not None:
                if not overwrite:
                    raise ValueError("目标已存在；覆盖必须显式选择")
                if _kind(existing) != "file" or getattr(existing, "st_nlink", 1) > 1:
                    raise ValueError("只能覆盖普通文件，不能覆盖链接、目录或多重硬链接文件")
            temporary = directory / f".sshgate-{tid}.part"
            moved = False
            try:
                with temporary.open("xb") as out:
                    count = copy(source, out, 0, size)
                    out.flush()
                    os.fsync(out.fileno())
                check()
                if existing is not None:
                    os.replace(temporary, target)
                elif os.name == "nt":
                    os.rename(temporary, target)  # fails if the name appeared meanwhile
                else:
                    os.link(temporary, target)
                    temporary.unlink()
                moved = True
                return count
            except FileExistsError:
                raise ValueError("目标已存在；覆盖必须显式选择") from None
            finally:
                if not moved:
                    temporary.unlink(missing_ok=True)

        if kind == "upload_file":
            with local.open("rb") as source:
                written = write_file(parent, name, source, info["size_bytes"], args.get("overwrite", False))
            return {"path": lexical, "size_bytes": written, "sha256": info["sha256"], "overwrite": args.get("overwrite", False)}
        members, seen = zip_members(local), {}
        for member, _size, is_dir in members:
            parts = member.rstrip("/").split("/")
            for part in parts:
                check_component(part, "ZIP 条目")
            key = "/".join(p.casefold() for p in parts)
            if key in seen:
                raise ValueError("ZIP 中有仅大小写不同的同名条目，Windows 无法区分")
            seen[key] = is_dir
        for key in seen:
            parts = key.split("/")
            if any(seen.get("/".join(parts[:i])) is False for i in range(1, len(parts))):
                raise ValueError("ZIP 中有文件与目录同名")
        destination = parent / name
        try:
            os.mkdir(destination)  # a NEW directory only; never merges into existing content
        except FileExistsError:
            raise ValueError("目标目录已存在；目录上传只解压到新目录") from None
        completed = []
        try:
            with zipfile.ZipFile(local) as archive:
                for member, size, is_dir in sorted(members, key=lambda m: (m[0].count("/"), m[0])):
                    check()
                    parts = member.rstrip("/").split("/")
                    folder = destination.joinpath(*(parts if is_dir else parts[:-1]))
                    folder.mkdir(parents=True, exist_ok=True)
                    if not is_dir:
                        with archive.open(member) as source:
                            write_file(folder, parts[-1], source, size)
                        completed.append(member)
            return {"path": lexical, "files_written": len(completed), "complete": True, "archive_sha256": info["sha256"]}
        except BaseException as exc:
            raise RuntimeError(f"目录上传未完成；新目录 {lexical} 保留了 {len(completed)} 个已完成文件：{exc}") from exc
    if kind in {"create_session", "update_session"}:
        if not workspace.resolve(lexical).is_dir():
            raise ValueError("会话目录不是目录")
        return {"cwd": lexical}
    raise ValueError("不支持此本机文件操作")


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wt.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wt.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD)]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", ctypes.c_uint64 * 6),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", wt.DWORD), ("TotalProcesses", wt.DWORD),
                ("ActiveProcesses", wt.DWORD), ("TotalTerminatedProcesses", wt.DWORD)]


class _Job:
    """Windows job object: every process the command starts can be stopped together."""

    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.restype = wt.HANDLE
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
        kernel.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
        kernel.QueryInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
        kernel.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
        kernel.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]
        kernel.CloseHandle.argtypes = [wt.HANDLE]
        self._kernel = kernel
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObject failed")
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE: closing the app ends the tree
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")

    @classmethod
    def create(cls):
        if os.name != "nt":
            return None
        try:
            return cls()
        except OSError:
            return None

    def assign(self, process) -> bool:
        return bool(self._kernel.AssignProcessToJobObject(self.handle, int(process._handle)))

    def active(self) -> int:
        info = _Accounting()
        if not self._kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            return -1
        return info.ActiveProcesses

    def terminate(self):
        self._kernel.TerminateJobObject(self.handle, 1)

    def close(self):
        if self.handle:
            self._kernel.CloseHandle(self.handle)
            self.handle = None


def _pump(stream, name, emit):
    try:
        fd = stream.fileno()
        while True:
            data = os.read(fd, 65536)
            if not data:
                break
            emit(name, data)
    except OSError:
        pass
    finally:
        stream.close()


def _stop_tree(process, job, *, assigned) -> dict:
    if job and assigned:
        remaining = job.active()
        if remaining:
            job.terminate()
        deadline = time.monotonic() + 3
        while job.active() > 0 and time.monotonic() < deadline:
            time.sleep(.05)
        confirmed = job.active() == 0
        return {"state": "process_tree_stopped" if confirmed else "unconfirmed", "remote_group_terminated": confirmed,
                "scope": "windows_job_object", "stopped_processes": max(0, remaining), "escaped_processes_guaranteed": False}
    if process.poll() is None:
        process.kill()
    try:
        process.wait(3)
    except subprocess.TimeoutExpired:
        pass
    return {"state": "shell_stopped" if process.poll() is not None else "unconfirmed", "remote_group_terminated": False,
            "scope": "shell_process_only", "escaped_processes_guaranteed": False}


class LocalRunner:
    def __init__(self, transfers=None):
        self.transfers = transfers

    def execute(self, payload, emit, stop, progress) -> RunResult:
        if stop.is_set():
            return RunResult(None, disconnected=True, termination={"state": "not_started", "remote_group_terminated": True})
        try:
            if payload.operation != "command":
                return RunResult(0, result=operation(payload, self.transfers, stop, progress))
            return self._command(payload, emit, stop, progress)
        except InterruptedError as exc:
            return RunResult(None, disconnected=True, error=str(exc), termination={"state": "cancelled", "remote_group_terminated": True})
        except TimeoutError as exc:
            return RunResult(None, timed_out=True, error=str(exc))
        except ValueError as exc:
            return RunResult(None, error=str(exc))
        except Exception as exc:
            return RunResult(None, error=f"{type(exc).__name__}: {exc}")

    def _command(self, payload, emit, stop, progress) -> RunResult:
        progress(phase="checking_workspace")
        cwd = Workspace(payload.workspace_roots).resolve(payload.cwd)
        if not cwd.is_dir():
            raise ValueError("工作目录不是目录")
        shell = payload.local_shell
        if not shell or not os.path.isfile(shell):
            raise ValueError("审批时记录的 PowerShell 已不可用，请重新提交")
        folder = Path(tempfile.gettempdir()) / "SSHGate"
        folder.mkdir(exist_ok=True)
        handle, script = tempfile.mkstemp(prefix="run-", suffix=".ps1", dir=folder)
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as out:
            out.write(payload.executed_command)
        job, process, assigned = _Job.create(), None, False
        try:
            if stop.is_set():
                return RunResult(None, disconnected=True, termination={"state": "not_started", "remote_group_terminated": True})
            process = subprocess.Popen([shell, *SHELL_ARGS, _bootstrap(script)], cwd=str(cwd), env=shell_environment(),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_FLAGS)
            assigned = bool(job and job.assign(process))
            progress(phase="running_local", pid=process.pid)
            readers = [threading.Thread(target=_pump, args=(process.stdout, "stdout", emit), daemon=True),
                       threading.Thread(target=_pump, args=(process.stderr, "stderr", emit), daemon=True)]
            for reader in readers:
                reader.start()
            deadline, outcome = time.monotonic() + payload.timeout_seconds, ""
            while process.poll() is None:
                if stop.wait(.05):
                    outcome = "stopped"
                    break
                if time.monotonic() >= deadline:
                    outcome = "timeout"
                    break
            if outcome:
                progress(phase="terminating")
            # Also ends background processes the command left behind, so its pipes close.
            termination = _stop_tree(process, job, assigned=assigned)
            for reader in readers:
                reader.join(2)
            if outcome == "stopped":
                return RunResult(None, disconnected=True, termination=termination)
            if outcome == "timeout":
                return RunResult(None, timed_out=True, error=f"超过 {payload.timeout_seconds}s 执行时限，已结束进程树", termination=termination)
            return RunResult(process.returncode, result={"leftover_processes_stopped": termination.get("stopped_processes", 0)})
        finally:
            if process and process.poll() is None:
                process.kill()
            if job:
                job.close()
            Path(script).unlink(missing_ok=True)
