from __future__ import annotations

import hmac
import json
import shutil
import secrets
import threading
import time
import uuid
import webbrowser
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .config import Server
from .credentials import CredentialStore
from .ssh import known_host_candidates, config_profiles, resolve_settings


def frontend_html(resources: Path, token: str) -> str:
    assets = resources / "ssh_gate/frontend"
    html = (assets / "index.html").read_text(encoding="utf-8")
    return html.replace("/*__APP_CSS__*/", (assets / "app.css").read_text(encoding="utf-8")).replace(
        "/*__APP_JS__*/", "window.__APP_TOKEN__=" + json.dumps(token) + ";\n" + (assets / "app.js").read_text(encoding="utf-8"))


class DesktopAPI:
    """Only this in-process WebView gets the capability. Nothing here is an HTTP/MCP route."""
    _TUNNEL_API_KEY_REF = CredentialStore.secret_reference("openai-secure-mcp-tunnel-api-key")

    def __init__(self, manager, host, tunnel):
        self._manager, self._host, self._tunnel = manager, host, tunnel
        self._credentials = getattr(getattr(manager, "runner", None), "credentials", None)
        self._token = secrets.token_urlsafe(32)
        self._window = None
        self._lock = threading.RLock()
        self._reviews = {}
        self._active_prompt = None
        self._prompt_id = None
        self._started = time.monotonic()
        self._closed = False

    def _bind(self, window):
        self._window = window

    def _check(self, token):
        if not isinstance(token, str) or not hmac.compare_digest(token, self._token) or self._closed:
            raise ValueError("本地应用会话无效")

    def _reply(self, token, fn):
        try:
            self._check(token)
            with self._lock:
                # A capability-checked call comes from the live local WebView, including
                # a user returning from a native file dialog. No background heartbeat exists.
                self._manager.local_gui_heartbeat()
                return {"ok": True, "data": fn()}
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return {"ok": False, "error": str(exc)}

    def snapshot(self, token):
        def take():
            self._manager.local_gui_heartbeat()
            runner = self._manager.runner
            states = runner.connection_states() if hasattr(runner, "connection_states") else {}
            config = self._manager.config
            if self._active_prompt and self._active_prompt.done.is_set():
                self._active_prompt = self._prompt_id = None
            if not self._active_prompt:
                prompts = getattr(runner, "prompts", None)
                self._active_prompt = prompts.next() if prompts else None
                if self._active_prompt:
                    self._prompt_id = secrets.token_urlsafe(20)
            prompt = ({"id": self._prompt_id, "kind": self._active_prompt.kind, "data": self._active_prompt.data}
                      if self._active_prompt else None)
            tunnel = self._tunnel.status(config)
            try:
                tunnel["api_key_saved"] = bool(self._credentials and self._credentials.has(self._TUNNEL_API_KEY_REF))
            except (OSError, ValueError):
                tunnel["api_key_saved"] = False
            return {"version": __version__, "uptime_seconds": int(time.monotonic() - self._started),
                    "mcp": self._host.status(), "tunnel": tunnel,
                    "servers": [{**asdict(s), "connected": states.get(s.id, False),
                                 "last_diagnostics": self._manager.server_info.get(s.id)} for s in config.servers],
                    "requests": self._manager.list_summaries(), "prompt": prompt,
                    "transfers": self._manager.transfers.list(),
                    "sessions": [{k:v for k,v in s.items() if k!="environment"} | {"environment_keys":list(s["environment"])}
                                 for s in self._manager.sessions.values()],
                    "settings": {"listen_port": config.listen_port,
                        "auto_allow_readonly": config.auto_allow_readonly,
                        "approval_timeout_seconds": config.approval_timeout_seconds,
                        "max_command_timeout_seconds": config.max_command_timeout_seconds,
                        "output_limit_bytes": config.output_limit_bytes,
                        "motion_enabled": config.motion_enabled, "scale_percent": config.ui_scale_percent,
                        "effects": config.ui_effects,
                        "config_path": str(config.config_path or config.root / "config.json")}}
        return self._reply(token, take)

    def request_detail(self, token, request_id, offset=0):
        return self._reply(token, lambda: self._manager.get(request_id, offset, 32768))

    def begin_review(self, token, request_id):
        def begin():
            view = self._manager.get(request_id, limit=1)
            if view["status"] != "pending_approval":
                raise ValueError("此请求已被处理或过期")
            now = time.monotonic()
            self._reviews = {k: v for k, v in self._reviews.items() if v[2] > now}
            ticket = secrets.token_urlsafe(32)
            self._reviews[ticket] = (request_id, view["digest"], now + 120)
            return {"ticket": ticket, "request": view}
        return self._reply(token, begin)

    def approve(self, token, request_id, ticket, confirmed):
        def execute():
            review = self._reviews.pop(ticket, None)
            if confirmed is not True or not review or review[0] != request_id or review[2] <= time.monotonic():
                raise ValueError("请重新打开审批窗口并勾选完整命令检查")
            self._manager.local_approve(request_id, review[1])
        return self._reply(token, execute)

    def reject(self, token, request_id):
        return self._reply(token, lambda: self._manager.reject(request_id))

    def disconnect_request(self, token, request_id):
        return self._reply(token, lambda: self._manager.disconnect_local(request_id))

    def terminate_request(self, token, request_id):
        return self._reply(token, lambda: self._manager.terminate(request_id))

    def submit_local(self, token, server_id, command, reason, cwd="", timeout_seconds=300):
        return self._reply(token, lambda: self._manager.submit(server_id, command, reason,
            "desktop-" + uuid.uuid4().hex, cwd, timeout_seconds))

    def set_readonly(self, token, enabled):
        return self._reply(token, lambda: self._manager.local_set_readonly(enabled))

    def known_hosts(self, token):
        return self._reply(token, lambda: [{"host": host, "port": port or 22} for host, port in known_host_candidates()])

    def ssh_profiles(self, token, ssh_config_file=""):
        return self._reply(token, lambda: config_profiles(ssh_config_file))

    def preview_connection(self, token, values):
        def preview():
            allowed = {"ssh_target", "port", "identity_file", "ssh_config_file"}
            if not isinstance(values, dict) or set(values)-allowed:
                raise ValueError("SSH 预览参数无效")
            settings = resolve_settings(self._manager.config, Server("preview", "SSH 预览", **values))
            return {"config_source": settings.config_source,
                    "route": [{"host_alias": node.host_alias, "hostname": node.hostname,
                               "username": node.username, "port": node.port,
                               "identity_files": node.identity_files, "identities_only": node.identities_only,
                               "proxy_command": bool(node.proxy_command)} for node in [*settings.jump_hosts, settings]]}
        return self._reply(token, preview)

    def save_connection(self, token, values, editing=False):
        def save():
            allowed = {"id", "label", "ssh_target", "default_cwd", "port", "identity_file", "ssh_config_file", "auto_categories", "auto_roots"}
            if not isinstance(values, dict) or set(values) - allowed or type(editing) is not bool:
                raise ValueError("连接参数无效")
            server = Server(**values)
            if editing:
                self._manager.local_update_server(server)
            else:
                self._manager.local_add_server(server)
            return {"id": server.id}
        return self._reply(token, save)

    def remove_connection(self, token, server_id):
        return self._reply(token, lambda: self._manager.local_remove_server(server_id))

    def test_connection(self, token, server_id):
        return self._reply(token, lambda: self._manager.submit_operation(server_id, "test_connection", {},
            "在本地诊断 SSH 与默认目录", "desktop-test-" + uuid.uuid4().hex, timeout_seconds=60))

    def filesystem(self, token, server_id, operation, arguments):
        return self._reply(token, lambda: self._manager.submit_operation(server_id,operation,arguments,
            "本地文件管理 / "+operation,"desktop-file-"+uuid.uuid4().hex))

    def prepare_upload(self, token):
        def prepare():
            if not self._window: raise ValueError("应用窗口不可用")
            import webview
            paths=self._window.create_file_dialog(webview.FileDialog.OPEN,allow_multiple=False)
            if not paths: return None
            path=paths if isinstance(paths,str) else paths[0]
            return self._manager.transfers.import_local(Path(path))
        return self._reply(token,prepare)

    def save_download(self, token, transfer_id):
        def save():
            item=self._manager.transfers.info(transfer_id)
            if item["direction"]!="download" or not item["complete"]: raise ValueError("下载未完成")
            if not self._window: raise ValueError("应用窗口不可用")
            import webview
            paths=self._window.create_file_dialog(webview.FileDialog.SAVE,save_filename=item["file_name"])
            if not paths: return None
            path=paths if isinstance(paths,str) else paths[0]
            shutil.copyfile(self._manager.transfers.path(transfer_id,complete=True),path)
            return str(path)
        return self._reply(token,save)

    def clear_transfer(self, token, transfer_id):
        return self._reply(token,lambda:self._manager.transfers.remove(transfer_id))

    def session_action(self, token, action, values):
        def change():
            if not isinstance(values,dict): raise ValueError("会话参数无效")
            key="desktop-session-"+uuid.uuid4().hex
            if action=="create": return self._manager.create_session(values["server_id"],values["cwd"],values.get("environment",{}),"本地创建受控会话",key)
            if action=="update": return self._manager.update_session(values["session_id"],values["cwd"],values.get("environment",{}),"本地修改会话上下文",key)
            if action=="execute": return self._manager.exec_in_session(values["session_id"],values["command"],values.get("reason","本地会话命令"),key,values.get("timeout_seconds",300))
            if action=="close": return self._manager.close_session(values["session_id"])
            raise ValueError("会话操作无效")
        return self._reply(token,change)

    def session_detail(self, token, session_id):
        return self._reply(token,lambda:self._manager.session_context(session_id))

    def disconnect_connection(self, token, server_id=""):
        def close():
            if any(r["status"] == "running" and (not server_id or r["server_id"] == server_id)
                   for r in self._manager.list_summaries()):
                raise ValueError("连接上仍有执行，请先断开或完成该请求")
            runner = self._manager.runner
            if server_id and hasattr(runner, "close_connection"):
                runner.close_connection(server_id)
            elif not server_id and hasattr(runner, "close_connections"):
                runner.close_connections()
        return self._reply(token, close)

    def answer_prompt(self, token, prompt_id, answer=None):
        def answer_local():
            prompt = self._active_prompt
            if not prompt or self._prompt_id != prompt_id or prompt.done.is_set():
                raise ValueError("登录输入已过期或取消")
            if answer is not None:
                if prompt.kind == "host_key":
                    if answer not in {"once", "save"}:
                        raise ValueError("主机指纹选择无效")
                elif (not isinstance(answer, dict) or not {"secret", "mode"} <= set(answer)
                      or set(answer) - {"secret", "mode", "remember"}
                      or answer["mode"] not in {"password", "passphrase"}
                      or not isinstance(answer["secret"], str) or not answer["secret"] or len(answer["secret"]) > 4096
                      or type(answer.get("remember", False)) is not bool):
                    raise ValueError("登录输入无效")
            prompt.answer = answer
            prompt.done.set()
            self._active_prompt = self._prompt_id = None
        return self._reply(token, answer_local)

    def choose_file(self, token, purpose):
        def choose():
            if purpose not in {"identity", "ssh_config", "tunnel_client"} or not self._window:
                raise ValueError("文件选择无效")
            import webview
            result = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False)
            return (result if isinstance(result, str) else result[0]) if result else ""
        return self._reply(token, choose)

    def export_output(self, token, request_id):
        def export():
            if not self._window:
                raise ValueError("应用窗口不可用")
            import webview
            paths = self._window.create_file_dialog(webview.FileDialog.SAVE, save_filename="ssh-output.txt",
                                                   file_types=("Text (*.txt)",))
            if not paths:
                return None
            path = paths if isinstance(paths, str) else paths[0]
            chunks = []
            offset = 0
            while True:
                view = self._manager.get(request_id, offset, 32768)
                chunks.append((view["stdout"], view["stderr"]))
                if not view["has_more_output"]:
                    break
                offset = view["next_output_offset"]
            text = "标准输出\n" + "".join(c[0] for c in chunks) + "\n标准错误\n" + "".join(c[1] for c in chunks)
            Path(path).write_text(text, encoding="utf-8")
            return str(path)
        return self._reply(token, export)

    def save_settings(self, token, settings):
        def save():
            if not isinstance(settings, dict) or set(settings) - {"listen_port", "approval_timeout_seconds", "max_command_timeout_seconds", "output_limit_bytes", "ui"}:
                raise ValueError("应用设置参数无效")
            if "listen_port" in settings and settings["listen_port"] != self._manager.config.listen_port:
                if self._tunnel.status(self._manager.config)["running"]:
                    raise ValueError("更改 MCP 端口前请先停止隧道")
                if any(r["status"] in {"running", "pending_approval", "queued_readonly"} for r in self._manager.list_summaries()):
                    raise ValueError("更改端口前请处理未完成请求")
                self._manager.local_save_settings(settings)
                self._host.stop()
                self._host.start()
            else:
                self._manager.local_save_settings(settings)
        return self._reply(token, save)

    def set_mcp_running(self, token, enabled):
        def change():
            if type(enabled) is not bool:
                raise ValueError("服务状态无效")
            if not enabled and self._tunnel.status(self._manager.config)["running"]:
                raise ValueError("请先停止隧道")
            return self._host.start() if enabled else self._host.stop()
        return self._reply(token, change)

    def save_tunnel(self, token, values):
        def save():
            if (not isinstance(values, dict) or not {"id", "client_path", "health_port"} <= set(values)
                    or set(values) - {"id", "client_path", "health_port", "proxy_mode", "proxy_url"}):
                raise ValueError("隧道设置无效")
            status = self._tunnel.status(self._manager.config)
            if status["running"] or status["download_status"] == "running":
                raise ValueError("请先停止隧道再更改设置")
            self._manager.local_save_settings({"tunnel": values})
        return self._reply(token, save)

    def proxy_action(self, token, kind, mode="auto", url=""):
        return self._reply(token, lambda: self._tunnel.proxy_diagnostics.start(kind, mode, url))

    def start_tunnel(self, token, api_key="", remember=True):
        def start():
            if type(remember) is not bool or not isinstance(api_key, str):
                raise ValueError("运行密钥参数无效")
            status = self._host.status()
            if not status["running"]:
                raise ValueError("请先启动本地 MCP 服务")
            secret = api_key.strip()
            if not secret:
                saved = self._credentials.get(self._TUNNEL_API_KEY_REF) if self._credentials else None
                if not saved or saved.get("mode") != "api_key" or not saved.get("secret"):
                    raise ValueError("请输入 OpenAI API Key，或先保存一个运行密钥")
                secret = saved["secret"]
            self._tunnel.start(self._manager.config, status["port"], secret)
            if api_key.strip() and self._credentials:
                if remember:
                    self._credentials.save(self._TUNNEL_API_KEY_REF, "api_key", secret)
                else:
                    self._credentials.delete(self._TUNNEL_API_KEY_REF)
        return self._reply(token, start)

    def clear_tunnel_api_key(self, token):
        def clear():
            if self._credentials:
                self._credentials.delete(self._TUNNEL_API_KEY_REF)
        return self._reply(token, clear)

    def stop_tunnel(self, token):
        return self._reply(token, self._tunnel.stop)

    def download_tunnel(self, token):
        return self._reply(token, lambda: self._tunnel.download(self._manager.config))

    def open_external(self, token, destination):
        def open_link():
            urls = {"tunnels": "https://platform.openai.com/settings/organization/tunnels",
                    "keys": "https://platform.openai.com/settings/organization/api-keys",
                    "webview2": "https://developer.microsoft.com/microsoft-edge/webview2/",
                    "diagnostics": self._tunnel.status(self._manager.config)["diagnostics_url"]}
            if destination not in urls:
                raise ValueError("外部链接无效")
            webbrowser.open(urls[destination])
        return self._reply(token, open_link)

    def _close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._reviews.clear()
        self._tunnel.close()
        self._manager.close()
        try:
            self._host.stop()
        except ValueError:
            pass
