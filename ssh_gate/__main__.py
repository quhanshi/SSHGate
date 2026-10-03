from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
from pathlib import Path

from .config import load_config
from .core import ApprovalManager
from .desktop import DesktopAPI, frontend_html
from .runtime import MCPHost, TunnelRuntime


def resource_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))


def default_config_path() -> Path:
    if getattr(sys, "frozen", False):
        beside = Path(sys.executable).parent / "config.json"
        if beside.exists():
            return beside
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SSHGate/config.json"
    return resource_root() / "config.json"


def ensure_config(path: Path):
    if path.exists():
        return
    values = json.loads((resource_root() / "config.example.json").read_text(encoding="utf-8-sig"))
    values["servers"] = []
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive create avoids overwriting a second app's configuration.
    try:
        with path.open("x", encoding="utf-8") as out:
            json.dump(values, out, ensure_ascii=False, indent=2)
    except FileExistsError:
        pass


def main():
    parser = argparse.ArgumentParser(description="WebView SSH 服务器控制台")
    parser.add_argument("--config", type=Path, default=default_config_path())
    parser.add_argument("--debug-ui", action="store_true", help="仅本地开发调试 WebView")
    args = parser.parse_args()
    api = None
    try:
        for stream in ("stdout", "stderr"):
            if getattr(sys, stream) is None:
                setattr(sys, stream, open(os.devnull, "w", encoding="utf-8"))
        ensure_config(args.config)
        config = load_config(args.config)
        manager = ApprovalManager(config)
        host = MCPHost(manager)
        executable_dir = Path(sys.executable).parent if getattr(sys, "frozen", False) else resource_root()
        tunnel = TunnelRuntime(resource_root(), executable_dir)
        api = DesktopAPI(manager, host, tunnel)
        try:
            host.start()
        except ValueError:
            pass  # Show the error and port settings in the application instead of hiding the UI.
        import webview
        webview.settings["ALLOW_FILE_URLS"] = False
        webview.settings["ALLOW_DOWNLOADS"] = False
        window = webview.create_window("SSH Gate", html=frontend_html(resource_root(), api._token),
            js_api=api, width=1400, height=900, min_size=(960, 680), background_color="#090d12",
            text_select=True, confirm_close=True, zoomable=False)
        api._bind(window)
        window.events.closed += api._close
        def dark_title():
            if os.name == "nt":
                try:
                    value = ctypes.c_int(1)
                    ctypes.windll.dwmapi.DwmSetWindowAttribute(int(window.native.Handle.ToInt64()),
                        20, ctypes.byref(value), ctypes.sizeof(value))
                except Exception:
                    pass
        window.events.shown += dark_title
        webview.start(gui="edgechromium" if os.name == "nt" else None,
            debug=args.debug_ui, private_mode=True, http_server=False,
            localization={"global.quitConfirmation": "退出将停止隧道、关闭 SSH 连接并拒绝尚未执行的请求。确认退出？"})
        return 0
    except Exception as exc:
        message = f"应用无法启动：{exc}\n请检查配置、依赖和 Microsoft Edge WebView2 Runtime。"
        if os.name == "nt":
            ctypes.windll.user32.MessageBoxW(None, message, "SSH Gate", 0x10)
        else:
            print(message, file=sys.stderr)
        return 1
    finally:
        if api:
            api._close()


if __name__ == "__main__":
    raise SystemExit(main())
