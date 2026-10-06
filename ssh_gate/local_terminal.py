"""Local PowerShell terminal for the person at the desktop.

Reachable only through the capability-checked WebView bridge (DesktopAPI); no MCP
tool can open, read or write it. Input and output stay in memory: nothing is
audited, logged or written to disk.
"""
from __future__ import annotations

import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

BUFFER_CHARS = 1 << 20   # retained output per session while the view is hidden or slow
READ_CHARS = 1 << 17     # one bridge reply
WRITE_CHARS = 1 << 16
MAX_SESSIONS = 4
READ_WAIT_SECONDS = .25
_MIN_IDLE, _MAX_IDLE = .004, .05
# Set by the app's own launchers (uv run, the project venv, PyInstaller), not by the user.
_LAUNCHER_ENV = {"PYTHONHOME", "VIRTUAL_ENV", "VIRTUAL_ENV_PROMPT", "UV", "UV_INTERNAL__PYTHONHOME",
                 "UV_RUN_RECURSION_DEPTH", "_MEIPASS2"}


@dataclass(frozen=True)
class Shell:
    path: str
    name: str


def find_shell() -> Shell | None:
    if os.name != "nt":
        return None
    pwsh = shutil.which("pwsh.exe")
    if pwsh:
        return Shell(pwsh, "PowerShell (pwsh)")
    legacy = Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32/WindowsPowerShell/v1.0/powershell.exe")
    found = shutil.which("powershell.exe") or (str(legacy) if legacy.is_file() else "")
    return Shell(found, "Windows PowerShell") if found else None


def shell_environment(source=None) -> dict[str, str]:
    """The user's environment without what launching this app injected."""
    env = dict(os.environ if source is None else source)
    norm = lambda p: os.path.normcase(os.path.normpath(p))
    venv = next((v for k, v in env.items() if k.upper() == "VIRTUAL_ENV"), "")
    internal = {norm(p) for p in (venv and os.path.join(venv, "Scripts"), getattr(sys, "_MEIPASS", "")) if p}
    for key in list(env):
        if key.upper() in _LAUNCHER_ENV or key.upper().startswith("_PYI_"):
            del env[key]
    for key in [k for k in env if k.upper() == "PATH"]:
        env[key] = os.pathsep.join(p for p in env[key].split(os.pathsep) if p and norm(p) not in internal)
    return env


def windows_build() -> int:
    return sys.getwindowsversion().build if os.name == "nt" else 0


def spawn_shell(shell: Shell, cols: int, rows: int, args=("-NoLogo",)):
    from winpty import PTY  # Windows-only dependency
    env = shell_environment()
    # CreateProcess expects the block sorted case-insensitively.
    block = "\0".join(f"{k}={v}" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
    process = PTY(cols, rows)
    if not process.spawn(shell.path, cmdline=" " + subprocess.list2cmdline(args), cwd=str(Path.home()), env=block):
        raise OSError("进程未创建")
    return process


class TerminalSession:
    def __init__(self, process):
        self.id = secrets.token_urlsafe(12)
        self.running = True
        self.exit_code: int | None = None
        self._process = process
        self._chunks: deque[str] = deque()
        self._start = self._end = 0   # absolute character offsets of the retained output
        self._changed = threading.Condition()
        self._closing = threading.Event()
        self._thread = threading.Thread(target=self._pump, name="local-terminal", daemon=True)
        self._thread.start()

    def _append(self, text):
        with self._changed:
            self._chunks.append(text)
            self._end += len(text)
            while self._end - self._start > BUFFER_CHARS and len(self._chunks) > 1:
                self._start += len(self._chunks.popleft())
            self._changed.notify_all()

    def _pump(self):
        # Non-blocking reads: a blocking pseudoconsole read never returns after the shell exits.
        process, idle = self._process, _MIN_IDLE
        try:
            while not self._closing.is_set():
                text = process.read(blocking=False)
                if text:
                    self._append(text)
                    idle = _MIN_IDLE
                    continue
                if not process.isalive():
                    for _ in range(3):  # output written just before exit can trail the exit status
                        time.sleep(.01)
                        text = process.read(blocking=False)
                        if text:
                            self._append(text)
                    break
                time.sleep(idle)
                idle = min(idle * 2, _MAX_IDLE)
        except Exception:
            pass  # a closed pseudoconsole raises here; the exit is reported below
        finally:
            try:
                code = process.get_exitstatus()
            except Exception:
                code = None
            with self._changed:
                self.running, self.exit_code = False, code
                self._changed.notify_all()

    def read(self, offset: int, wait: float = READ_WAIT_SECONDS) -> dict:
        with self._changed:
            if offset >= self._end and self.running and not self._closing.is_set():
                self._changed.wait(wait)
            start = min(max(offset, self._start), self._end)
            parts, position, size = [], self._start, 0
            for chunk in self._chunks:
                if size >= READ_CHARS:
                    break
                end = position + len(chunk)
                if end > start:
                    piece = chunk[max(0, start - position):][:READ_CHARS - size]
                    parts.append(piece)
                    size += len(piece)
                position = end
            text = "".join(parts)
            return {"data": text, "offset": start, "next": start + len(text), "skipped": max(0, start - offset),
                    "more": start + len(text) < self._end, "running": self.running, "exit_code": self.exit_code}

    def write(self, data: str):
        process = self._process
        if process is None or not self.running:
            raise ValueError("终端进程已退出")
        process.write(data)

    def resize(self, cols: int, rows: int):
        process = self._process
        if process is not None and self.running:
            process.set_size(cols, rows)

    def close(self):
        self._closing.set()
        process = self._process
        pid = getattr(process, "pid", None)
        if self.running and pid:
            try:
                os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
            except OSError:
                pass
        with self._changed:
            self._changed.notify_all()
        self._thread.join(1)
        # Dropping the last reference closes the pseudoconsole, which ends console programs still attached.
        self._process = None


def _dimensions(cols, rows):
    if type(cols) is not int or type(rows) is not int or not (2 <= cols <= 500 and 1 <= rows <= 300):
        raise ValueError("终端尺寸无效")
    return cols, rows


class LocalTerminals:
    def __init__(self, shell: Shell | None, spawn=spawn_shell):
        self._shell, self._spawn = shell, spawn
        self._sessions: dict[str, TerminalSession] = {}
        self._lock = threading.Lock()
        self._closed = False

    @classmethod
    def for_platform(cls):
        return cls(find_shell())

    def info(self):
        if not self._shell:
            return {"available": False, "shell": "", "build": 0,
                    "reason": "本地终端需要 Windows 与 PowerShell" if os.name == "nt" else "本地终端仅支持 Windows"}
        return {"available": True, "shell": self._shell.name, "build": windows_build(), "reason": ""}

    def _get(self, session_id) -> TerminalSession:
        session = self._sessions.get(session_id) if isinstance(session_id, str) else None
        if not session:
            raise ValueError("终端会话已结束")
        return session

    def open(self, cols, rows):
        cols, rows = _dimensions(cols, rows)
        if not self._shell:
            raise ValueError(self.info()["reason"])
        with self._lock:
            if self._closed:
                raise ValueError("应用正在退出")
            if len(self._sessions) >= MAX_SESSIONS:
                for key in [k for k, s in self._sessions.items() if not s.running]:
                    self._sessions.pop(key).close()
            if len(self._sessions) >= MAX_SESSIONS:
                raise ValueError(f"最多同时运行 {MAX_SESSIONS} 个本地终端")
            try:
                process = self._spawn(self._shell, cols, rows)
            except Exception as exc:
                raise OSError(f"无法启动 {self._shell.name}：{exc or type(exc).__name__}") from exc
            session = TerminalSession(process)
            self._sessions[session.id] = session
        return {"id": session.id, "shell": self._shell.name}

    def write(self, session_id, data):
        if not isinstance(data, str) or not data or len(data) > WRITE_CHARS:
            raise ValueError("终端输入无效")
        self._get(session_id).write(data)

    def resize(self, session_id, cols, rows):
        self._get(session_id).resize(*_dimensions(cols, rows))

    def read(self, session_id, offset):
        if type(offset) is not int or offset < 0:
            raise ValueError("终端读取位置无效")
        return self._get(session_id).read(offset)

    def close(self, session_id):
        with self._lock:
            session = self._sessions.pop(session_id, None) if isinstance(session_id, str) else None
        if session:
            session.close()

    def close_all(self):
        with self._lock:
            self._closed = True
            sessions, self._sessions = list(self._sessions.values()), {}
        for session in sessions:
            session.close()
