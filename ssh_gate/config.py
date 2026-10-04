from __future__ import annotations

import json
import os
import re
import shutil
import unicodedata
from dataclasses import dataclass, replace, asdict, field
from pathlib import Path

from .proxy import validate_proxy_url


def checked_text(value: str, label: str, *, multiline: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} 不能为空")
    allowed = "\n\t" if multiline else ""
    for c in value:
        if (unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"}) and c not in allowed:
            raise ValueError(f"{label} 包含不可见控制字符 U+{ord(c):04X}")
    return value


@dataclass(frozen=True)
class Server:
    id: str
    label: str
    ssh_target: str
    default_cwd: str = "."
    port: int | None = None
    identity_file: str = ""
    ssh_config_file: str = ""
    auto_categories: tuple[str, ...] = ()
    auto_roots: tuple[str, ...] = ()
    auto_grant_capabilities: tuple[str, ...] = ()
    github_hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class TunnelConfig:
    id: str = ""
    client_path: str = "bin/tunnel-client.exe"
    health_port: int = 8766
    proxy_mode: str = "auto"
    proxy_url: str = ""


@dataclass(frozen=True)
class Config:
    root: Path
    listen_port: int
    approval_timeout_seconds: int
    max_command_timeout_seconds: int
    output_limit_bytes: int
    ssh_executable: str
    servers: tuple[Server, ...]
    auto_allow_readonly: bool = False
    config_path: Path | None = None
    motion_enabled: bool = True
    ui_scale_percent: int = 100
    ui_effects: str = "standard"
    tunnel: TunnelConfig = field(default_factory=TunnelConfig)

    def server(self, server_id: str) -> Server:
        for server in self.servers:
            if server.id == server_id:
                return server
        raise ValueError("服务器 ID 未在本地配置中登记；请先调用 list_servers")


def integer(value: object, lo: int, hi: int, label: str) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{label} 必须在 {lo}–{hi} 之间")
    return value


def resolve_local_path(root: Path, value: str) -> str:
    expanded = Path(os.path.expandvars(value)).expanduser()
    return str((root / expanded).resolve() if not expanded.is_absolute() else expanded)


def load_config(path: Path) -> Config:
    path = path.resolve()
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    root = path.parent
    configured_ssh = data.get("ssh_executable", "")
    if configured_ssh:
        ssh = resolve_local_path(root, configured_ssh)
    else:
        native = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/OpenSSH/ssh.exe"
        ssh = str(native) if os.name == "nt" and native.is_file() else (shutil.which("ssh") or "")
    if configured_ssh and not Path(ssh).is_file():
        raise ValueError("配置的 ssh_executable 文件不存在")
    servers = []
    ids = set()
    for raw in data.get("servers", []):
        sid = raw["id"]
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", sid) or sid in ids:
            raise ValueError("服务器 id 必须唯一，仅允许字母、数字、下划线和连字符")
        target = raw["ssh_target"]
        if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.@:\[\]-]{0,253}", target):
            raise ValueError("ssh_target 应为 SSH Host 别名或 user@hostname，不可包含命令/选项")
        label = checked_text(raw.get("label", sid), "服务器名称")
        cwd = checked_text(raw.get("default_cwd", "."), "默认目录")
        if not (cwd == "." or cwd == "~" or cwd.startswith("~/") or cwd.startswith("/")):
            raise ValueError("默认目录必须是绝对路径、~、~/子目录或 .（登录目录）")
        port = raw.get("port")
        if port is not None:
            integer(port, 1, 65535, "SSH 端口")
        paths = {}
        for field in ("identity_file", "ssh_config_file"):
            value = raw.get(field, "")
            paths[field] = resolve_local_path(root, checked_text(value, field)) if value else ""
            if value and not Path(paths[field]).is_file():
                raise ValueError(f"{field} 文件不存在")
        categories = raw.get("auto_categories", [])
        roots = raw.get("auto_roots", [])
        grant_capabilities = raw.get("auto_grant_capabilities", [])
        github_hosts = raw.get("github_hosts", [])
        if (not isinstance(grant_capabilities, (list, tuple)) or
                any(c not in {"git_deploy_pull", "python_tests"} for c in grant_capabilities) or
                (grant_capabilities and not roots)):
            raise ValueError("临时授权预授权仅支持部署拉取和 pytest，且必须指定绝对目录")
        if (not isinstance(github_hosts, (list, tuple)) or any(not isinstance(h, str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", h) for h in github_hosts)):
            raise ValueError("GitHub Enterprise 主机名无效")
        if (not isinstance(categories, (list, tuple)) or any(c not in {"read_fs", "diagnostics", "git_read", "docker_read", "python_tests", "manual_only"} for c in categories)
                or not isinstance(roots, (list, tuple)) or any(not isinstance(p, str) or not p.startswith("/") or ".." in p.split("/") for p in roots)):
            raise ValueError("自动授权类别或绝对目录范围无效")
        for p in roots:
            checked_text(p, "授权目录")
        servers.append(Server(sid, label, target, cwd, port, **paths,
                              auto_categories=tuple(categories), auto_roots=tuple(roots),
                              auto_grant_capabilities=tuple(grant_capabilities),
                              github_hosts=tuple(h.lower().rstrip('.') for h in github_hosts)))
        ids.add(sid)
    if type(data.get("auto_allow_readonly", True)) is not bool:
        raise ValueError("auto_allow_readonly 必须是 true 或 false")
    ui = data.get("ui", {})
    if not isinstance(ui, dict) or type(ui.get("motion_enabled", True)) is not bool:
        raise ValueError("ui.motion_enabled 必须是布尔值")
    effects = ui.get("effects", "standard" if ui.get("motion_enabled", True) else "off")
    if effects not in {"off", "low", "standard"}:
        raise ValueError("ui.effects 必须是 off、low 或 standard")
    tunnel = data.get("tunnel", {})
    if not isinstance(tunnel, dict):
        raise ValueError("tunnel 必须是对象")
    tunnel_id = tunnel.get("id", "")
    if not isinstance(tunnel_id, str) or (tunnel_id and not re.fullmatch(r"tunnel_[0-9a-f]{32}", tunnel_id)):
        raise ValueError("Tunnel ID 应为 tunnel_ 加 32 位小写十六进制字符")
    health_port = integer(tunnel.get("health_port", 8766), 1024, 65535, "隧道诊断端口")
    if health_port == data.get("listen_port", 8765):
        raise ValueError("MCP 端口与隧道诊断端口必须不同")
    proxy_mode = tunnel.get("proxy_mode", "auto")
    proxy_url = tunnel.get("proxy_url", "")
    if proxy_mode not in {"auto", "manual", "direct"} or not isinstance(proxy_url, str):
        raise ValueError("代理模式或地址无效")
    if proxy_url or proxy_mode == "manual":
        proxy_url = validate_proxy_url(proxy_url)
    return Config(
        root=root,
        listen_port=integer(data.get("listen_port", 8765), 1024, 65535, "本地 MCP 端口"),
        approval_timeout_seconds=min(60, integer(data.get("approval_timeout_seconds", 60), 10, 3600, "审批期限")),
        max_command_timeout_seconds=integer(data.get("max_command_timeout_seconds", 3600), 1, 86400, "命令最长时间"),
        output_limit_bytes=integer(data.get("output_limit_bytes", 1048576), 4096, 4194304, "输出上限"),
        ssh_executable=ssh,
        servers=tuple(servers),
        auto_allow_readonly=data.get("auto_allow_readonly", True),
        config_path=path,
        motion_enabled=ui.get("motion_enabled", True),
        ui_scale_percent=integer(ui.get("scale_percent", 100), 90, 130, "界面缩放"),
        ui_effects=effects,
        tunnel=TunnelConfig(tunnel_id, checked_text(tunnel.get("client_path", "bin/tunnel-client.exe"), "隧道客户端路径"),
                            health_port, proxy_mode, proxy_url),
    )


def write_config(config: Config, *, server: Server | None = None, auto_allow_readonly: bool | None = None,
                 replace_server: bool = False, remove_server_id: str = "", settings: dict | None = None) -> Config:
    """Local GUI mutation only. Never persists passwords or private key contents."""
    path = config.config_path or config.root / "config.json"
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if server:
        exists = any(s.id == server.id for s in config.servers)
        if exists and not replace_server:
            raise ValueError("服务器 ID 已存在，请使用新 ID")
        if replace_server and not exists:
            raise ValueError("要修改的连接不存在")
        if replace_server:
            data["servers"] = [asdict(server) if s["id"] == server.id else s for s in data["servers"]]
        else:
            data.setdefault("servers", []).append(asdict(server))
    if remove_server_id:
        if not any(s.id == remove_server_id for s in config.servers):
            raise ValueError("要删除的连接不存在")
        data["servers"] = [s for s in data["servers"] if s["id"] != remove_server_id]
    if settings is not None:
        allowed = {"listen_port", "approval_timeout_seconds", "max_command_timeout_seconds", "output_limit_bytes", "ui", "tunnel"}
        if not isinstance(settings, dict) or set(settings) - allowed:
            raise ValueError("包含不允许修改的设置")
        data.update(settings)
    if auto_allow_readonly is not None:
        if type(auto_allow_readonly) is not bool:
            raise ValueError("只读开关必须是布尔值")
        data["auto_allow_readonly"] = auto_allow_readonly
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Validate before replacing the user's configuration.
        validated = load_config(tmp)
        os.replace(tmp, path)
        return replace(validated, config_path=path)
    finally:
        tmp.unlink(missing_ok=True)
