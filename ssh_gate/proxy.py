"""Local outbound proxy configuration. Never changes Windows global networking."""
from __future__ import annotations

import base64
import os
import re
import socket
import ssl
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, unquote

import httpx


COMMON_PORTS = (7890, 7897, 7891, 10809, 1080, 8080, 8118, 8888, 20171)
PROXY_KEYS = ("CONTROL_PLANE_HTTP_PROXY", "TUNNEL_CLIENT_HTTP_PROXY", "HTTPS_PROXY", "https_proxy",
              "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
CLEAR_KEYS = {*PROXY_KEYS, "MCP_HTTP_PROXY", "HARPOON_HTTP_PROXY", "NO_PROXY", "no_proxy"}
API_URL = "https://api.openai.com/v1/models"


def validate_proxy_url(value: str, *, allow_credentials: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 2048 or not value.strip():
        raise ValueError("请填写 HTTP/HTTPS 代理地址，例如 http://127.0.0.1:7890")
    value = value.strip()
    if any(c.isspace() or unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in value) or "\\" in value:
        raise ValueError("代理地址包含空白或控制字符")
    try:
        url = urlsplit(value)
        port = url.port
        if (url.scheme.lower() not in {"http", "https"} or not url.hostname or
                url.path not in {"", "/"} or url.query or url.fragment or (port is not None and not 1 <= port <= 65535)):
            raise ValueError
        if url.username is not None and not allow_credentials:
            raise ValueError("代理用户名和密码不能保存到配置；可通过本地 HTTPS_PROXY 环境变量提供认证代理")
        url.hostname.encode("idna")
    except (ValueError, UnicodeError) as exc:
        if "用户名" in str(exc):
            raise
        raise ValueError("代理仅支持完整的 HTTP/HTTPS 地址；SOCKS 端口请改用代理软件的 HTTP 或 Mixed 端口") from exc
    return urlunsplit((url.scheme.lower(), url.netloc, "", "", ""))


def public_url(value: str) -> str:
    """Do not expose userinfo from environment proxies to the GUI or logs."""
    url = urlsplit(value)
    return urlunsplit((url.scheme, url.netloc.rsplit("@", 1)[-1], "", "", ""))


@dataclass(frozen=True)
class ProxyRoute:
    url: str = ""
    source: str = "直连"

    def public(self):
        return {"url": public_url(self.url) if self.url else "", "source": self.source,
                "authenticated": bool(self.url and urlsplit(self.url).username is not None)}


def windows_proxy_settings() -> dict:
    if os.name != "nt":
        return {}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            def read(name, default):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except OSError:
                    return default
            return {"enabled": bool(read("ProxyEnable", 0)), "server": read("ProxyServer", ""),
                    "pac": bool(read("AutoConfigURL", ""))}
    except OSError:
        return {}


def configured_routes(env=None, settings=None):
    env = os.environ if env is None else env
    settings = windows_proxy_settings() if settings is None else settings
    routes, warnings, seen = [], [], set()
    def add(raw, source, credentials=False):
        try:
            value = validate_proxy_url(raw, allow_credentials=credentials)
        except ValueError:
            warnings.append(f"{source} 格式不受支持，请指定 HTTP/Mixed 代理端口。")
            return
        if value not in seen:
            routes.append(ProxyRoute(value, source))
            seen.add(value)
    for name in PROXY_KEYS:
        raw = env.get(name, "")
        if raw:
            if raw.startswith("env:"):
                raw = env.get(raw[4:], "")
            add(raw, f"环境变量 {name}", True)
    if settings.get("enabled") and isinstance(settings.get("server"), str):
        raw = settings["server"].strip()
        if "=" in raw:
            protocols = dict(part.strip().split("=", 1) for part in raw.split(";") if "=" in part)
            raw = protocols.get("https") or protocols.get("http") or ""
        if raw:
            add(raw if "://" in raw else "http://" + raw, "Windows 系统代理")
    if settings.get("pac"):
        warnings.append("检测到 PAC 自动配置；本应用不执行 PAC 脚本，请填写代理软件的 HTTP/Mixed 地址。")
    return routes, warnings


def probe_proxy(route: ProxyRoute, timeout=.8) -> dict:
    """Verify CONNECT, not just an open port. api.openai.com DNS stays at the proxy."""
    result = {**route.public(), "tcp": False, "connect_status": None, "usable": False, "error": ""}
    sock = None
    try:
        url = urlsplit(route.url)
        sock = socket.create_connection((url.hostname, url.port or (443 if url.scheme == "https" else 80)), timeout)
        sock.settimeout(timeout)
        result["tcp"] = True
        if url.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=url.hostname)
        headers = "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n"
        if url.username is not None:
            auth = base64.b64encode((unquote(url.username) + ":" + unquote(url.password or "")).encode()).decode()
            headers += "Proxy-Authorization: Basic " + auth + "\r\n"
        sock.sendall((headers + "\r\n").encode("ascii"))
        data = b""
        deadline = time.monotonic() + timeout
        while b"\r\n" not in data and len(data) < 4096:
            sock.settimeout(max(.01, deadline - time.monotonic()))
            block = sock.recv(256)
            if not block or time.monotonic() > deadline:
                break
            data += block
        match = re.match(rb"HTTP/1\.[01] ([0-9]{3})(?: |\r\n)", data)
        if match:
            result["connect_status"] = int(match[1])
            result["usable"] = result["connect_status"] == 200
            if not result["usable"]:
                result["error"] = "代理需要认证" if result["connect_status"] == 407 else f"代理 CONNECT 返回 {result['connect_status']}"
        else:
            result["error"] = "端口已开放，但未收到 HTTP CONNECT 响应；可能是 SOCKS 或其他服务"
    except (OSError, ValueError):
        result["error"] = "代理连接或 CONNECT 超时/失败" if result["tcp"] else "代理 TCP 连接失败"
    finally:
        if sock:
            sock.close()
    return result


def local_routes(ports=COMMON_PORTS):
    # Only scan the loopback ports listed here. No LAN or server scanning.
    routes = [ProxyRoute(f"http://127.0.0.1:{port}", "常见本地端口") for port in ports]
    with ThreadPoolExecutor(max_workers=len(routes) or 1) as pool:
        return [r for r in pool.map(probe_proxy, routes) if r["tcp"]]


def resolve_route(mode: str, url: str = "", *, env=None, settings=None) -> ProxyRoute:
    if mode == "manual":
        return ProxyRoute(validate_proxy_url(url), "手动指定")
    if mode == "direct":
        return ProxyRoute()
    if mode != "auto":
        raise ValueError("代理模式应为 auto、manual 或 direct")
    routes, warnings = configured_routes(env, settings)
    if routes:
        # A broken configured proxy must not silently switch to another exit.
        return routes[0]
    found = next((r for r in local_routes() if r["usable"]), None)
    if found:
        return ProxyRoute(found["url"], found["source"])
    if warnings:
        raise ValueError("；".join(warnings))
    return ProxyRoute(source="自动检测未找到代理，直连")


def apply_route(env: dict, route: ProxyRoute) -> dict:
    result = {k: v for k, v in env.items() if k not in CLEAR_KEYS}
    # Clear inherited global/MCP overrides. An explicit global proxy ignores NO_PROXY.
    result["NO_PROXY"] = result["no_proxy"] = "127.0.0.1,localhost,::1" if route.url else "*"
    if route.url:
        result["CONTROL_PLANE_HTTP_PROXY"] = route.url
        result["HTTP_PROXY"] = result["HTTPS_PROXY"] = route.url
        result["http_proxy"] = result["https_proxy"] = route.url
    return result


def test_route(route: ProxyRoute, progress=lambda phase: None, *, target=API_URL, context=None) -> dict:
    """No API key is sent. A 401 proves transport, not account or Tunnel readiness."""
    started = time.monotonic()
    phase = "connecting_proxy" if route.url else "connecting_api"
    result = {"route": route.public(), "ok": False, "tcp": False, "connect": False,
              "tls": False, "http_status": None, "error": "", "phase": phase}
    in_connect = False
    def trace(event, info):
        nonlocal phase, in_connect
        if event == "connection.connect_tcp.complete":
            result["tcp"] = True
            phase = "proxy_connect" if route.url else "tls_api"
        if event == "http11.send_request_headers.started" and info["request"].method == b"CONNECT":
            in_connect = True
        if event == "http11.receive_response_headers.complete" and in_connect:
            result["connect"] = info["return_value"][1] == 200
            in_connect = False
        if event.endswith("start_tls.started"):
            name = info.get("server_hostname", "")
            if isinstance(name, bytes):
                name = name.decode()
            phase = "tls_api" if name == urlsplit(target).hostname else "tls_proxy"
        if event.endswith("start_tls.complete") and phase == "tls_api":
            result["tls"] = True
            result["connect"] = bool(route.url)
            phase = "http_api"
        progress(phase)
    progress(phase)
    try:
        # Windows system CA roots are loaded by the stdlib SSL context.
        ssl_context = context or ssl.create_default_context()
        proxy = httpx.Proxy(route.url, ssl_context=ssl_context if urlsplit(route.url).scheme == "https" else None) if route.url else None
        with httpx.Client(proxy=proxy, trust_env=False, verify=ssl_context,
                          timeout=httpx.Timeout(4), follow_redirects=False) as client:
            # Stream so a large response body cannot delay or fill the UI snapshot.
            with client.stream("GET", target, headers={"User-Agent": "SSH-Gate-Proxy-Test"},
                               extensions={"trace": trace}) as response:
                result["http_status"] = response.status_code
                result["ok"] = response.status_code in {200, 401}
                if result["ok"]:
                    result["message"] = "HTTPS 链路通过；未验证运行密钥或 Tunnel 权限"
                else:
                    result["error"] = f"OpenAI HTTPS 已响应，但返回 HTTP {response.status_code}；请检查代理出口或访问限制"
    except httpx.ProxyError as exc:
        result["error"] = "代理 CONNECT 被拒绝或需要认证（407）" if "407" in str(exc) else "代理 CONNECT 失败；请检查 HTTP/Mixed 端口与出口"
    except httpx.TimeoutException:
        result["error"] = "此阶段连接超时；请检查代理是否运行、节点与出口"
    except (httpx.HTTPError, OSError, ValueError) as exc:
        result["error"] = ("TLS 证书校验失败；请检查代理证书与系统信任" if "CERTIFICATE_VERIFY_FAILED" in str(exc)
                           else "此阶段连接失败；请检查地址、端口、DNS 与代理节点")
    result["phase"] = phase
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


class ProxyDiagnostics:
    """One asynchronous local GUI job at a time; polling keeps approval heartbeat live."""
    def __init__(self):
        self._lock = threading.RLock()
        self._status = {"state": "idle", "kind": "", "phase": "", "result": None}
        self._closed = False

    def status(self):
        with self._lock:
            return dict(self._status)

    def start(self, kind, mode="auto", url=""):
        if kind not in {"detect", "test"} or mode not in {"auto", "manual", "direct"}:
            raise ValueError("代理检测参数无效")
        if mode == "manual":
            validate_proxy_url(url)
        with self._lock:
            if self._closed or self._status["state"] == "running":
                raise ValueError("代理检测正在运行或应用已关闭")
            self._status = {"state": "running", "kind": kind, "phase": "detecting", "result": None,
                            "mode": mode, "url": url if mode == "manual" else "", "started_at": time.time()}
        def progress(phase):
            with self._lock:
                self._status["phase"] = phase
        def work():
            try:
                if kind == "detect":
                    routes, warnings = configured_routes()
                    with ThreadPoolExecutor(max_workers=8) as pool:
                        candidates = list(pool.map(probe_proxy, routes))
                    seen = {r["url"] for r in candidates}
                    candidates += [r for r in local_routes() if r["url"] not in seen]
                    result = {"candidates": candidates, "warnings": warnings,
                              "message": "CONNECT 通过仅代表代理转发可用，请继续测试 HTTPS 链路。"}
                else:
                    route = resolve_route(mode, url)
                    result = test_route(route, progress)
                state = "finished"
            except Exception:
                # Exception text can contain environment proxy credentials.
                state, result = "failed", {"error": "代理检测未完成，请检查代理配置或手动指定 HTTP/Mixed 地址"}
            with self._lock:
                if not self._closed:
                    self._status.update(state=state, result=result, finished_at=time.time())
        threading.Thread(target=work, daemon=True, name="proxy-diagnostics").start()

    def close(self):
        with self._lock:
            self._closed = True
