"""Isolated desktop UI fixture. Executes no SSH or real tunnel commands."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ssh_gate.config import load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.desktop import DesktopAPI, frontend_html
from ssh_gate.prompts import LocalPrompts, PromptCancelled
from ssh_gate.ssh import RunResult
from ssh_gate.credentials import CredentialStore


class FixtureProxyDiagnostics:
    def __init__(self):
        self.view = {"state":"idle", "kind":"", "result":None}

    def status(self):
        return dict(self.view)

    def start(self, kind, mode="auto", url=""):
        from ssh_gate.proxy import validate_proxy_url
        if kind not in {"detect", "test"} or mode not in {"auto", "manual", "direct"}:
            raise ValueError("代理检测参数无效")
        if mode == "manual":
            validate_proxy_url(url)
        if kind == "detect":
            result = {"candidates":[{"url":"http://127.0.0.1:7890","source":"Windows 系统代理","authenticated":False,
                                     "tcp":True,"connect_status":200,"usable":True,"error":""}],"warnings":[],"message":"测试数据 / 未连接网络"}
        else:
            result = {"ok":url != "http://127.0.0.1:7891", "route":{"url":url if mode == "manual" else "", "source":"手动指定" if mode == "manual" else "直连"},
                      "phase":"http_api" if url != "http://127.0.0.1:7891" else "proxy_connect", "http_status":401 if url != "http://127.0.0.1:7891" else None,
                      "duration_ms":37, "message":"HTTPS 链路通过；未验证运行密钥或 Tunnel 权限" if url != "http://127.0.0.1:7891" else "", "error":"HTTP CONNECT 失败 / 测试数据"}
        self.view = {"state":"finished", "kind":kind,"phase":"finished","result":result,"finished_at":time.time()}


class FixtureHost:
    def __init__(self, manager):
        self.manager, self.running = manager, True
        self.starts = self.stops = 0
        self.received = self.answered = 0

    def start(self):
        self.running = True
        self.starts += 1

    def stop(self):
        self.running = False
        self.stops += 1

    def status(self):
        port = self.manager.config.listen_port
        return {"running": self.running, "error": "", "port": port, "endpoint": f"http://127.0.0.1:{port}/mcp",
                "calls_received": self.received, "calls_answered": self.answered}


class FixtureTunnel:
    def __init__(self):
        self.running, self.ready = False, False
        self.starts = 0
        self.last_key = ""
        self.proxy_diagnostics = FixtureProxyDiagnostics()

    def status(self, config):
        return {"running": self.running, "ready": self.ready, "ready_observed_at": time.time() if self.ready else None,
                "exit_code": None, "id": config.tunnel.id, "health_port": config.tunnel.health_port,
                "client_path": config.tunnel.client_path, "client_exists": True,
                "proxy_mode":config.tunnel.proxy_mode,"proxy_url":config.tunnel.proxy_url,
                "proxy_route":{"url":config.tunnel.proxy_url,"source":"手动指定"} if self.running else None,
                "proxy_diagnostics":self.proxy_diagnostics.status(),
                "diagnostics_url": f"http://127.0.0.1:{config.tunnel.health_port}/ui",
                "logs": ["本地 UI 测试客户端 / 非真实隧道"] if self.running else [],
                "download_status": "idle", "download_error": ""}

    def start(self, config, port, key):
        if not key:
            raise ValueError("运行密钥为空")
        if not config.tunnel.id:
            raise ValueError("Tunnel ID 为空")
        self.running = self.ready = True
        self.last_key = key
        self.starts += 1

    def stop(self):
        self.running = self.ready = False

    def close(self):
        self.stop()

    def download(self, config):
        pass


class FixtureRunner:
    def __init__(self, credential_root: Path | None = None):
        self.prompts = LocalPrompts()
        self.credentials = CredentialStore(credential_root) if credential_root is not None else None
        self.calls = []
        self.connected = {}

    def __call__(self, payload, emit, stop):
        try:
            if payload.ssh_settings.hostname == "password.fixture" and not self.connected.get(payload.server_id):
                self.prompts.ask("host_key", {"hostname": "password.fixture", "port": payload.ssh_settings.port,
                    "verification_name": "password.fixture", "key_type": "ssh-ed25519",
                    "fingerprint": "SHA256:fixture-only-1234567890", "known_hosts_file": str(Path.home() / ".ssh/known_hosts")}, stop)
                answer = self.prompts.ask("credentials", {"hostname": "password.fixture", "port": payload.ssh_settings.port,
                    "username": payload.ssh_settings.username, "attempt": 1}, stop)
                answer.clear()
            self.connected[payload.server_id] = True
            self.calls.append(payload)
            if "secret-output" in payload.command:
                emit("stdout", b"token=fixture-secret-value\n-----BEGIN RSA PRIVATE KEY-----\nshort sensitive line\n")
                stop.wait(.08)
                emit("stdout", b"-----END RSA PRIVATE KEY-----\nordinary line\n")
            elif "unique-output" in payload.command:
                emit("stdout", "".join(f"unique row {i}\n" for i in range(900)).encode())
            elif "long-output" in payload.command:
                emit("stdout", (("line / " + "x" * 70 + "\n") * 1200).encode())
            else:
                emit("stdout", ("/home/fixture\n" if payload.command == "pwd" or payload.operation == "test_connection" else
                    "total 24\ndrwxr-xr-x  6 fixture fixture 4096 Sep 30 14:20 .\n"
                    "drwxr-xr-x  8 fixture fixture 4096 Sep 30 14:18 ..\n"
                    "drwxr-xr-x  3 fixture fixture 4096 Sep 30 14:19 app\n"
                    "-rw-r--r--  1 fixture fixture  824 Sep 30 14:20 pyproject.toml\n"
                    "<img src=x onerror=window.__injected=true>\n").encode())
            emit("stderr", b"fixture stderr\n")
            if stop.wait(.12):
                return RunResult(None, disconnected=True)
            return RunResult(0)
        except PromptCancelled:
            return RunResult(None, disconnected=True)

    def execute(self,payload,emit,stop,progress):
        result=self(payload,emit,stop)
        if result.exit_code!=0: return result
        args=json.loads(payload.arguments)
        op=payload.operation
        progress(phase="executing",pid=12345 if op=="command" else None,pgid=12345 if op=="command" else None)
        if op=="list_directory":
            return RunResult(0,result={"path":args["path"],"entries":[{"path":args["path"].rstrip('/')+"/app","name":"app","type":"directory","size_bytes":4096},{"path":args["path"].rstrip('/')+"/test.log","name":"test.log","type":"file","size_bytes":12}],"next_offset":2,"has_more":False})
        if op=="read_file": return RunResult(0,result={"path":args["path"],"text":"fixture log <img src=x onerror=window.__injected=true>","next_offset":12,"eof":True})
        if op=="find_files": return RunResult(0,result={"root":args["path"],"matches":[{"path":"/data/data-evaluation","name":"data-evaluation","type":"directory","size_bytes":4096}],"truncated":False})
        if op=="stat_path": return RunResult(0,result={"path":args["path"],"type":"file","size_bytes":12})
        if op=="test_connection": return RunResult(0,result={"default_cwd":"/home/fixture","default_cwd_exists":True,"hostname":"fixture"})
        if op in {"create_session","update_session"}: return RunResult(0,result={"cwd":args["path"]})
        if op.startswith("download_"):
            self.transfers.path(args["transfer_id"]).write_bytes(b"fixture download")
            return RunResult(0,result=self.transfers.finish_download(args["transfer_id"]))
        if op.startswith("upload_"): return RunResult(0,result={"path":args["path"],"size_bytes":args["size_bytes"]})
        return result

    def connection_states(self):
        return dict(self.connected)

    def close_connection(self, server_id):
        self.connected.pop(server_id, None)

    def close_connections(self):
        self.connected.clear()

    def close(self):
        self.prompts.close()
        self.close_connections()


class FixtureWindow:
    def __init__(self, root):
        self.path = str(root / "export.txt")

    def create_file_dialog(self, *args, **kwargs):
        return (self.path,)


def make_fixture(root: Path, seed=False, runner_factory=FixtureRunner):
    values = {"listen_port": 18765, "auto_allow_readonly": True, "servers": [
        {"id": "dev", "label": "开发服务器", "ssh_target": "fixture@dev.fixture", "default_cwd": "/home/fixture/workspace"},
        {"id": "logs", "label": "日志节点", "ssh_target": "fixture@logs.fixture", "default_cwd": "/var/log", "port": 2222},
        {"id": "stage", "label": "验证环境", "ssh_target": "fixture@stage.fixture", "default_cwd": "/srv/app"}],
        "tunnel": {"id": "", "client_path": "bin/tunnel-client.exe", "health_port": 18766}}
    (root / "config.json").write_text(json.dumps(values, ensure_ascii=False))
    runner = runner_factory(root / "credentials")
    manager = ApprovalManager(load_config(root / "config.json"), runner=runner)
    runner.transfers=manager.transfers
    host, tunnel = FixtureHost(manager), FixtureTunnel()
    api = DesktopAPI(manager, host, tunnel)
    api._bind(FixtureWindow(root))
    manager.local_gui_heartbeat()
    if seed:
        manager.submit("dev", "ls -lah", "检查开发目录", "fixture-read")
        time.sleep(.18)
        manager.submit("dev", "git reset --hard", "审批行为测试 / 不执行真实命令", "fixture-pending")
        manager.submit("logs", "systemctl status app", "检查应用服务状态", "fixture-pending-2")
    return api, manager, runner, host, tunnel


def main():
    resources = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / '.ssh').mkdir()
        (root / '.ssh/config').write_text('Host 181\n HostName jump.fixture\n Port 2201\n User jumper\nHost 10.208.88.201\n HostName 10.208.88.201\n Port 12138\n User quhanshi\n IdentityFile ~/.ssh/id_ed25519\n IdentitiesOnly yes\n ProxyJump 181\nHost 10.208.88.201-Direct\n HostName 10.208.88.201\n Port 12138\n User quhanshi\n')
        api, manager, _runner, host, _tunnel = make_fixture(root, seed=True)
        html_path = Path(sys.argv[1])
        html_path.write_text(frontend_html(resources, api._token), encoding="utf-8")
        print(json.dumps({"ready": True, "html": str(html_path), "root": str(root)}), flush=True)
        try:
            with patch("pathlib.Path.home", return_value=root), patch("ssh_gate.desktop.known_host_candidates", return_value=(("password.fixture", 2222), ("known.fixture", None))):
                for line in sys.stdin:
                    request = json.loads(line)
                    method = request["method"]
                    if method == "fixture_mcp_traffic":
                        # Stands in for one ChatGPT tool call reaching and leaving the MCP host.
                        host.received += 1
                        host.answered += 1
                        print(json.dumps({"id": request["id"], "result": {"ok": True}}), flush=True)
                        continue
                    if method.startswith("_") or not callable(getattr(api, method, None)):
                        raise ValueError("fixture method rejected")
                    result = getattr(api, method)(api._token, *request.get("args", []))
                    print(json.dumps({"id": request["id"], "result": result}, ensure_ascii=False), flush=True)
        finally:
            api._close()


if __name__ == "__main__":
    main()
