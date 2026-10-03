from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

import uvicorn

from .config import Config, resolve_local_path
from .mcp_server import create_mcp
from .proxy import apply_route, resolve_route, ProxyDiagnostics


class MCPHost:
    def __init__(self, manager):
        self.manager = manager
        self._server = None
        self._thread = None
        self._socket = None
        self.error = ""
        self.port = manager.config.listen_port
        self._lock = threading.RLock()
        self._received = self._answered = 0

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self.port = self.manager.config.listen_port
            self.error = ""
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind(("127.0.0.1", self.port))
                sock.listen(128)
                app = create_mcp(self.manager).streamable_http_app()
                # Counts MCP calls for the UI link animation; bodies and headers are never read.
                async def counted(scope, receive, send):
                    if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] != "/mcp":
                        return await app(scope, receive, send)
                    self._received += 1
                    async def tracked(message):
                        if message["type"] == "http.response.start":
                            self._answered += 1
                        await send(message)
                    await app(scope, receive, tracked)
                server = uvicorn.Server(uvicorn.Config(counted, host="127.0.0.1",
                    port=self.port, log_level="warning", access_log=False))
                # Windowed PyInstaller launches have no stderr/stdout stream.
                def serve():
                    try:
                        server.run(sockets=[sock])
                    except BaseException as exc:
                        self.error = f"MCP 服务启动失败：{type(exc).__name__}"
                    finally:
                        sock.close()
                self._socket, self._server = sock, server
                self._thread = threading.Thread(target=serve, daemon=True, name="local-mcp")
                self._thread.start()
            except Exception as exc:
                sock.close()
                self.error = f"本地端口 {self.port} 无法启动：{exc}"
                raise ValueError(self.error) from exc

    def stop(self):
        with self._lock:
            if self._server:
                self._server.should_exit = True
            thread = self._thread
        if thread:
            thread.join(timeout=4)
        with self._lock:
            if thread and thread.is_alive():
                raise ValueError("MCP 服务仍在停止，请稍后重试")
            self._thread = self._server = self._socket = None

    def status(self):
        running = bool(self._thread and self._thread.is_alive() and self._server and self._server.started)
        return {"running": running, "error": self.error, "port": self.port,
                "endpoint": f"http://127.0.0.1:{self.port}/mcp",
                "calls_received": self._received, "calls_answered": self._answered}


def redact_log(text: str, secret: str = "") -> str:
    if secret:
        text = text.replace(secret, "[已隐藏密钥]")
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{6,}", "[已隐藏密钥]", text)
    text = re.sub(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s\"']+", r"\1[已隐藏]", text)
    text = re.sub(r"(?i)(https?://)[^\s/\"']*@", r"\1[已隐藏认证]@", text)
    return text[:4000]


class TunnelRuntime:
    """Child credentials stay in a private environment, never in command argv or config."""
    def __init__(self, resources: Path, executable_dir: Path):
        self.resources, self.executable_dir = resources, executable_dir
        self._lock = threading.RLock()
        self._process = None
        self._download_process = None
        self._closed = False
        self._logs = deque(maxlen=160)
        self._ready = False
        self._ready_observed_at = None
        self._exit_code = None
        self._health_port = 8766
        self._download_status = "idle"
        self._download_error = ""
        self._proxy_route = None
        self.proxy_diagnostics = ProxyDiagnostics()

    def client_path(self, config: Config) -> str:
        configured = Path(resolve_local_path(config.root, config.tunnel.client_path))
        candidates = [configured, self.executable_dir / "bin/tunnel-client.exe"]
        found = shutil.which("tunnel-client.exe")
        if found:
            candidates.append(Path(found))
        return str(next((p for p in candidates if p.is_file()), configured))

    def _append(self, process, line: str, secret: str = ""):
        with self._lock:
            if self._process is process:
                self._logs.append(redact_log(line.rstrip(), secret))

    def start(self, config: Config, mcp_port: int, api_key: str):
        with self._lock:
            if self._closed:
                raise ValueError("应用已关闭")
            if self._process and self._process.poll() is None:
                raise ValueError("隧道已经运行，请先停止")
            if self._download_status == "running":
                raise ValueError("正在下载客户端，请等待完成")
            if not config.tunnel.id:
                raise ValueError("请先填写并保存 Tunnel ID")
            if not isinstance(api_key, str) or not api_key.strip() or len(api_key) > 4096 or any(c in api_key for c in "\r\n\x00"):
                raise ValueError("运行密钥为空或格式无效")
            binary = self.client_path(config)
            if not Path(binary).is_file():
                raise ValueError("未找到 tunnel-client，请先下载或选择客户端文件")
            route = resolve_route(config.tunnel.proxy_mode, config.tunnel.proxy_url)
            env = apply_route(os.environ.copy(), route)
            env.pop("MCP_COMMAND", None)
            env.pop("LOG_FILE", None)
            env.update(CONTROL_PLANE_API_KEY=api_key, CONTROL_PLANE_TUNNEL_ID=config.tunnel.id,
                       MCP_SERVER_URL=f"http://127.0.0.1:{mcp_port}/mcp",
                       HEALTH_LISTEN_ADDR=f"127.0.0.1:{config.tunnel.health_port}",
                       LOG_HTTP_RAW_UNSAFE="false", ALLOW_REMOTE_UI="false", OPEN_WEB_UI="false")
            try:
                process = subprocess.Popen([binary, "run"], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    encoding="utf-8", errors="replace", env=env, shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            except OSError as exc:
                raise ValueError(f"无法启动隧道客户端：{type(exc).__name__}") from exc
            finally:
                env.pop("CONTROL_PLANE_API_KEY", None)
            self._process = process
            self._ready = False
            self._ready_observed_at = None
            self._exit_code = None
            self._health_port = config.tunnel.health_port
            self._proxy_route = route.public()
            self._logs.clear()
            self._logs.append(f"出站路由：{route.source} · {self._proxy_route['url'] or '直连'}；本地 MCP 直连。")
            self._logs.append("隧道客户端已启动，等待 /readyz 就绪检查。")
            def read_logs():
                try:
                    for line in iter(lambda: process.stdout.readline(65536), ""):
                        self._append(process, line, api_key)
                finally:
                    process.stdout.close()
                    code = process.wait()
                    with self._lock:
                        if self._process is process:
                            self._ready = False
                            self._exit_code = code
                            self._logs.append(f"隧道客户端已退出，代码 {code}。")
            threading.Thread(target=read_logs, daemon=True, name="tunnel-logs").start()
            threading.Thread(target=self._probe, args=(process, self._health_port), daemon=True, name="tunnel-health").start()

    def _probe(self, process, port):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while process.poll() is None:
            ready = False
            try:
                with opener.open(f"http://127.0.0.1:{port}/readyz", timeout=0.8) as response:
                    ready = response.status == 200
            except (OSError, urllib.error.URLError):
                pass
            with self._lock:
                if self._process is not process or self._closed:
                    return
                self._ready = ready
                self._ready_observed_at = time.time()
            for _ in range(20):
                with self._lock:
                    if self._process is not process or self._closed:
                        return
                time.sleep(0.1)

    def stop(self):
        with self._lock:
            process, self._process = self._process, None
            self._ready = False
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        with self._lock:
            if process:
                self._exit_code = process.poll()
                self._logs.append("已在本地停止隧道客户端。")

    def download(self, config: Config):
        with self._lock:
            if self._closed or self._download_status == "running":
                raise ValueError("应用已关闭或下载正在进行")
            if self._process and self._process.poll() is None:
                raise ValueError("请先停止隧道再更新客户端")
            if os.name != "nt":
                raise ValueError("此下载功能用于 Windows；请手动安装对应平台客户端")
            script = self.resources / "scripts/Download-Tunnel.ps1"
            powershell = shutil.which("powershell.exe")
            if not powershell or not script.is_file():
                raise ValueError("未找到 Windows PowerShell 或下载脚本")
            route = resolve_route(config.tunnel.proxy_mode, config.tunnel.proxy_url)
            download_env = apply_route(os.environ.copy(), route)
            download_env["APP_DOWNLOAD_PROXY"] = route.url
            download_env["APP_DOWNLOAD_DIRECT"] = "true" if not route.url else "false"
            download_env.pop("CONTROL_PLANE_API_KEY", None)
            download_env.pop("OPENAI_API_KEY", None)
            self._download_status, self._download_error = "running", ""
            def work():
                process = None
                try:
                    with self._lock:
                        if self._closed:
                            self._download_status = "cancelled"
                            return
                        process = subprocess.Popen([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-File", str(script), "-DestinationRoot", str(config.root)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            text=True, encoding="utf-8", errors="replace", shell=False,
                            creationflags=subprocess.CREATE_NO_WINDOW, env=download_env)
                        self._download_process = process
                    output, _ = process.communicate(timeout=300)
                    with self._lock:
                        self._download_status = "succeeded" if process.returncode == 0 else "failed"
                        self._download_error = "" if process.returncode == 0 else redact_log(output[-3000:])
                except Exception as exc:
                    if process and process.poll() is None:
                        process.kill()
                    with self._lock:
                        self._download_status, self._download_error = "failed", f"下载未完成：{type(exc).__name__}"
                finally:
                    with self._lock:
                        self._download_process = None
                    download_env.clear()
            threading.Thread(target=work, daemon=True, name="tunnel-download").start()

    def status(self, config: Config):
        with self._lock:
            running = bool(self._process and self._process.poll() is None)
            path = self.client_path(config)
            return {"running": running, "ready": running and self._ready,
                    "ready_observed_at": self._ready_observed_at, "exit_code": self._exit_code,
                    "client_path": path, "client_exists": Path(path).is_file(),
                    "id": config.tunnel.id, "health_port": config.tunnel.health_port,
                    "proxy_mode": config.tunnel.proxy_mode, "proxy_url": config.tunnel.proxy_url,
                    "proxy_route": self._proxy_route if running else None,
                    "proxy_diagnostics": self.proxy_diagnostics.status(),
                    "diagnostics_url": f"http://127.0.0.1:{self._health_port if running else config.tunnel.health_port}/ui",
                    "logs": list(self._logs), "download_status": self._download_status,
                    "download_error": self._download_error}

    def close(self):
        with self._lock:
            self._closed = True
            downloading = self._download_process
        if downloading and downloading.poll() is None:
            downloading.terminate()
        self.proxy_diagnostics.close()
        self.stop()
