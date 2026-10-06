"""Lexical Windows path rules shared by configuration and the local target.

Pure string checks (ntpath), so they behave the same on any test platform. Links and
junctions are resolved separately, at execution, by local_machine.Workspace.
"""
from __future__ import annotations

import ntpath
import unicodedata
from pathlib import Path

_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
             *(f"COM{i}" for i in "123456789¹²³"), *(f"LPT{i}" for i in "123456789¹²³")}
_INVALID = set('<>:"|?*')


def check_component(name: str, label: str = "路径") -> str:
    """One file or directory name: no stream suffix, device name or trailing dot/space aliasing."""
    if not name or name in {".", ".."} or any(ord(c) < 32 for c in name) or _INVALID & set(name) or "/" in name or "\\" in name:
        raise ValueError(f"{label}包含 Windows 不允许或有歧义的名称：{name!r}")
    if name != name.rstrip(" ."):
        raise ValueError(f"{label}的名称不能以空格或点结尾：{name!r}")
    if name.split(".", 1)[0].rstrip(" ").upper() in _RESERVED:
        raise ValueError(f"{label}使用了 Windows 设备名：{name!r}")
    return name


def windows_path(value: object, base: str = "", label: str = "路径") -> str:
    """Normalize an absolute Windows path, or one relative to an absolute base."""
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError(f"{label}无效")
    # Same rule as config.checked_text: no invisible control or bidi format characters in a reviewed path.
    if any(unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in value):
        raise ValueError(f"{label}包含不可见控制字符")
    if value[:4].replace("/", "\\") in {"\\\\?\\", "\\\\.\\", "\\??\\"}:
        raise ValueError(f"{label}不能使用设备路径或 \\\\?\\ 前缀")
    if value == "~" or value.startswith(("~\\", "~/")):
        value = str(Path.home()) + value[1:]
    drive, rest = ntpath.splitdrive(value)
    if not drive:
        if not base or value.startswith(("\\", "/")):
            raise ValueError(f"{label}必须是带盘符的绝对路径，例如 D:\\work")
        value = ntpath.join(base, value)
    elif not drive.startswith(("\\\\", "//")) and not rest.startswith(("\\", "/")):
        raise ValueError(f"{label}缺少盘符后的反斜杠（{drive}foo 是相对路径），例如 {drive}\\work")
    path = ntpath.normpath(value)
    drive, rest = ntpath.splitdrive(path)
    if len(drive) == 2 and not (drive[0].isascii() and drive[0].isalpha()):
        raise ValueError(f"{label}的盘符无效")
    for part in rest.split("\\"):
        if part:
            check_component(part, label)
    return path


def within(path: str, roots) -> bool:
    """Case-insensitive containment after normalization; a different drive is never inside."""
    target = ntpath.normcase(ntpath.normpath(path))
    for root in roots:
        base = ntpath.normcase(ntpath.normpath(root))
        try:
            if ntpath.commonpath([target, base]) == base:
                return True
        except ValueError:
            continue
    return False


def ps_quote(value: str) -> str:
    """PowerShell single-quoted literal. PowerShell also treats the curly single quotes as quotes."""
    for quote in "'\u2018\u2019\u201a\u201b":
        value = value.replace(quote, quote * 2)
    return "'" + value + "'"
