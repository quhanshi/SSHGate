# Build on Windows using: uv run --group build pyinstaller --clean --noconfirm SSHGate.spec
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

root = Path(SPECPATH)
datas = collect_data_files('webview') + [
    (str(root / 'ssh_gate/frontend'), 'ssh_gate/frontend'),
    (str(root / 'scripts/Download-Tunnel.ps1'), 'scripts'),
    (str(root / 'config.example.json'), '.'),
    (str(root / 'assets/app.ico'), 'assets'),
]
# pywinpty ships conpty.dll, OpenConsole.exe and winpty-agent.exe beside its extension module.
a = Analysis([str(root / 'desktop_launcher.py')], pathex=[str(root)], datas=datas + collect_data_files('winpty', include_py_files=False),
    binaries=collect_dynamic_libs('winpty'),
    hiddenimports=['webview.platforms.winforms', 'webview.platforms.edgechromium', 'winpty', 'winpty._winpty',
        'uvicorn.logging', 'uvicorn.loops.asyncio', 'uvicorn.protocols.http.h11_impl',
        'uvicorn.protocols.websockets.wsproto_impl', 'uvicorn.lifespan.on'],
    excludes=['tkinter', 'PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'gi',
        'webview.platforms.qt', 'webview.platforms.gtk', 'webview.platforms.cocoa', 'webview.platforms.cef'],
    noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='SSHGate',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=False, icon=str(root / 'assets/app.ico'))
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='SSHGate')
