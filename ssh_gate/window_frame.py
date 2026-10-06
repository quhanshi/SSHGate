"""Custom title bar for the WinForms + WebView2 window.

The native caption is removed but the window keeps its sizing frame, so Windows still
provides resize borders, Snap, the shadow and the minimize/maximize animations. The page
marks its drag area with CSS `app-region: drag` (WebView2 non-client region support).
If that support is missing, the native title bar is put back.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes as wt

WM_SIZE, WM_GETMINMAXINFO, WM_NCCALCSIZE, WM_NCHITTEST, WM_SYSCOMMAND = 0x0005, 0x0024, 0x0083, 0x0084, 0x0112
HTCLIENT, HTTOP, HTTOPLEFT, HTTOPRIGHT = 1, 12, 13, 14
SIZE_MAXIMIZED = 2
SM_CYSIZEFRAME, SM_CXPADDEDBORDER = 33, 92
SC = {"minimize": 0xF020, "maximize": 0xF030, "restore": 0xF120, "close": 0xF060}
# SWP_FRAMECHANGED | SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOOWNERZORDER
SWP_REFRAME = 0x0020 | 0x0001 | 0x0002 | 0x0004 | 0x0200
DWMWA_BORDER_COLOR = 34
BORDER_COLOR = 0x00362C22  # COLORREF of #222c36


class _NCCALCSIZE_PARAMS(ctypes.Structure):
    _fields_ = [("rgrc", wt.RECT * 3), ("lppos", ctypes.c_void_p)]


class _MINMAXINFO(ctypes.Structure):
    _fields_ = [("ptReserved", wt.POINT), ("ptMaxSize", wt.POINT), ("ptMaxPosition", wt.POINT),
                ("ptMinTrackSize", wt.POINT), ("ptMaxTrackSize", wt.POINT)]


class _MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("rcMonitor", wt.RECT), ("rcWork", wt.RECT), ("dwFlags", wt.DWORD)]


def _win32():
    user32, comctl32, dwmapi = ctypes.windll.user32, ctypes.windll.comctl32, ctypes.windll.dwmapi
    lresult = ctypes.c_ssize_t
    proc_type = ctypes.WINFUNCTYPE(lresult, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM, ctypes.c_size_t, ctypes.c_size_t)
    comctl32.DefSubclassProc.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    comctl32.DefSubclassProc.restype = lresult
    comctl32.SetWindowSubclass.argtypes = [wt.HWND, proc_type, ctypes.c_size_t, ctypes.c_size_t]
    comctl32.RemoveWindowSubclass.argtypes = [wt.HWND, proc_type, ctypes.c_size_t]
    user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.UINT]
    user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
    user32.IsZoomed.argtypes = [wt.HWND]
    user32.MonitorFromWindow.restype = wt.HMONITOR
    user32.MonitorFromWindow.argtypes = [wt.HWND, wt.DWORD]
    user32.GetMonitorInfoW.argtypes = [wt.HMONITOR, ctypes.POINTER(_MONITORINFO)]
    return user32, comctl32, dwmapi, proc_type


class WindowFrame:
    """attach() and the subclass run on the WinForms UI thread; state() and command() only read or post."""

    def __init__(self):
        self.custom = False
        self._hwnd = 0
        self._form = None
        self._proc = None   # keeps the ctypes callback alive while it is installed
        self._pad = 0
        self._win32 = None

    def attach(self, window):
        if os.name != "nt":
            return
        try:
            self._install(window.native)
        except Exception:
            self._remove()

    def _install(self, form):
        import System.Windows.Forms as WinForms
        user32, comctl32, dwmapi, proc_type = self._win32 = _win32()
        hwnd = int(form.Handle.ToInt64())
        frame = lambda: user32.GetSystemMetrics(SM_CYSIZEFRAME) + user32.GetSystemMetrics(SM_CXPADDEDBORDER)

        def pad_top(maximized):
            # A strip above the WebView stays with the form, so the top edge can still be dragged to resize.
            pad = 0 if maximized else user32.GetSystemMetrics(SM_CYSIZEFRAME)
            if pad != self._pad:
                self._pad = pad
                form.Padding = WinForms.Padding(0, pad, 0, 0)

        def handle(h, msg, wp, lp):
            if msg == WM_NCCALCSIZE and wp:
                params = ctypes.cast(lp, ctypes.POINTER(_NCCALCSIZE_PARAMS)).contents
                top = params.rgrc[0].top
                result = comctl32.DefSubclassProc(h, msg, wp, lp)
                # Keep the side and bottom frames; drop the caption. Maximized windows overhang the monitor by one frame.
                params.rgrc[0].top = top + (frame() if user32.IsZoomed(h) else 0)
                return result
            if msg == WM_NCHITTEST:
                result = comctl32.DefSubclassProc(h, msg, wp, lp)
                if result == HTCLIENT and self._pad and not user32.IsZoomed(h):
                    rect = wt.RECT()
                    user32.GetWindowRect(h, ctypes.byref(rect))
                    x, y = ctypes.c_short(lp & 0xFFFF).value, ctypes.c_short((lp >> 16) & 0xFFFF).value
                    if y < rect.top + self._pad:
                        corner = frame() * 2
                        return HTTOPLEFT if x < rect.left + corner else HTTOPRIGHT if x >= rect.right - corner else HTTOP
                return result
            if msg == WM_GETMINMAXINFO:
                result = comctl32.DefSubclassProc(h, msg, wp, lp)
                info = _MONITORINFO()
                info.cbSize = ctypes.sizeof(info)
                if user32.GetMonitorInfoW(user32.MonitorFromWindow(h, 2), ctypes.byref(info)):
                    limits = ctypes.cast(lp, ctypes.POINTER(_MINMAXINFO)).contents
                    work, monitor = info.rcWork, info.rcMonitor
                    limits.ptMaxPosition.x, limits.ptMaxPosition.y = work.left - monitor.left, work.top - monitor.top
                    limits.ptMaxSize.x, limits.ptMaxSize.y = work.right - work.left, work.bottom - work.top
                return result
            if msg == WM_SIZE:
                result = comctl32.DefSubclassProc(h, msg, wp, lp)
                pad_top(wp == SIZE_MAXIMIZED)
                return result
            return comctl32.DefSubclassProc(h, msg, wp, lp)

        @proc_type
        def proc(h, msg, wp, lp, _id, _data):
            try:
                return handle(h, msg, wp, lp)
            except Exception:
                return comctl32.DefSubclassProc(h, msg, wp, lp)

        if not comctl32.SetWindowSubclass(hwnd, proc, 1, 0):
            raise OSError("SetWindowSubclass failed")
        self._proc, self._form, self._hwnd, self.custom = proc, form, hwnd, True
        pad_top(bool(user32.IsZoomed(hwnd)))
        user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, SWP_REFRAME)
        color = ctypes.c_uint(BORDER_COLOR)
        dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ctypes.byref(color), ctypes.sizeof(color))  # Windows 11 only
        form.browser.webview.CoreWebView2InitializationCompleted += self._webview_ready

    def _webview_ready(self, sender, args):
        try:
            if args.IsSuccess:
                sender.CoreWebView2.Settings.IsNonClientRegionSupportEnabled = True
        except Exception:
            self._remove()  # Older WebView2 runtime: the page could not be dragged, so restore the caption.

    def _remove(self):
        if self._proc and self._hwnd and self._win32:
            user32, comctl32, _dwmapi, _proc_type = self._win32
            comctl32.RemoveWindowSubclass(self._hwnd, self._proc, 1)
            if self._form is not None:
                import System.Windows.Forms as WinForms
                self._form.Padding = WinForms.Padding(0)
            user32.SetWindowPos(self._hwnd, None, 0, 0, 0, 0, SWP_REFRAME)
        self.custom, self._proc, self._pad = False, None, 0

    def _maximized(self):
        return bool(self._hwnd and self._win32 and self._win32[0].IsZoomed(self._hwnd))

    def state(self):
        return {"custom_frame": self.custom, "maximized": self._maximized()}

    def command(self, action):
        """Post the same system command the native caption buttons send; closing still asks for confirmation."""
        if not self.custom or action not in {"minimize", "maximize", "close"}:
            raise ValueError("窗口操作无效")
        maximized = self._maximized()
        if action == "maximize":
            action, maximized = ("restore", False) if maximized else ("maximize", True)
        self._win32[0].PostMessageW(self._hwnd, WM_SYSCOMMAND, SC[action], 0)
        return {"custom_frame": True, "maximized": maximized}
