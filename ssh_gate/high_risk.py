"""Opt-in, best-effort screening for a lower-friction SSH approval mode.

This is NOT a shell sandbox or a proof that a command is safe. Opaque/dynamic
shell constructs are sent to local review rather than being guessed safe.
"""
from __future__ import annotations

import posixpath
import re
import shlex


_REVIEW_COMMANDS = {
    "reboot", "shutdown", "poweroff", "halt", "init", "telinit",
    "mkfs", "mkswap", "wipefs", "blkdiscard", "fdisk", "sfdisk",
    "cfdisk", "parted", "sgdisk", "gdisk", "pvcreate", "vgremove",
    "lvremove", "cryptsetup",
}
_SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "ash"}
_DYNAMIC = {"eval", "source", ".", "exec", "xargs", "parallel", "busybox",
            "systemd-run", "chroot", "runuser", "su", "pkexec", "doas",
            "setsid", "nohup", "watch", "strace", "ltrace", "ssh", "at",
            "crontab", "screen", "tmux", "nsenter", "unshare"}
_CONTROL = {"if", "then", "else", "elif", "fi", "do", "done", "for",
            "while", "until", "case", "esac", "function", "select", "{", "}"}
_PROTECTED = ("/etc", "/usr", "/boot", "/dev", "/proc", "/sys", "/root", "/var/lib")
_SEPARATORS = {";", "&&", "||", "|", "&", "(", ")"}
_REDIRECT = {">", ">>", ">|", "<", "<<", "<<<", "<>", ">&", "<&", "&>"}


def _program(word: str) -> str:
    return posixpath.basename(word).lower()


def _sensitive_path(path: str, *, recursive: bool = False) -> bool:
    if not path or path.startswith("-"):
        return False
    if "$" in path or "*" in path or "?" in path or "[" in path:
        return True
    if path in {".", "..", "./", "../", "~", "~/", "/", "//"}:
        return True
    if path.startswith("~/") or path.startswith("../"):
        return True
    if not path.startswith("/"):
        return False
    normalized = posixpath.normpath(path)
    if normalized == "/" or normalized in {"/home", "/var", "/opt", "/srv", "/mnt", "/media", "/tmp"}:
        return True
    return any(normalized == root or normalized.startswith(root + "/") for root in _PROTECTED)


def _unwrap(words: list[str]) -> list[str] | None:
    """Recognize common literal launch prefixes; unknown wrappers require review."""
    for _ in range(5):
        if not words:
            return None
        program = _program(words[0])
        if program == "sudo":
            i = 1
            while i < len(words) and words[i] in {"-n", "-H", "-E", "-S", "-k", "--"}:
                i += 1
            # sudo -u, --user, etc. can change which argv is the command.
            if i < len(words) and words[i].startswith("-"):
                return None
            words = words[i:]
        elif program == "env":
            i = 1
            while i < len(words) and (words[i] in {"-i", "--"} or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[i])):
                i += 1
            if i < len(words) and words[i].startswith("-"):
                return None
            words = words[i:]
        elif program == "command":
            words = words[1:]
        else:
            return words
    return None


def _segment_requires_review(tokens: list[str]) -> bool:
    if not tokens:
        return False
    # Redirections can overwrite sensitive system paths and devices.
    for i, token in enumerate(tokens[:-1]):
        if token in {">", ">>", ">|", "<>", "&>"} and _sensitive_path(tokens[i + 1]):
            return True
    # Remove shell redirections and their operands before examining the program.
    args: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i] in _REDIRECT:
            i += 2
        elif i + 1 < len(tokens) and tokens[i].isdigit() and tokens[i + 1] in _REDIRECT:
            i += 3
        else:
            args.append(tokens[i])
            i += 1
    while args and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", args[0]):
        args.pop(0)
    if not args:
        return False
    args = _unwrap(args)
    if not args:
        return True
    if any(c in args[0] for c in ("$", "*", "?", "[", "]", "~")):
        return True
    program, operands = _program(args[0]), args[1:]
    if program in _SHELLS | _DYNAMIC | _CONTROL | _REVIEW_COMMANDS:
        return True
    if program.startswith("mkfs."):
        return True
    if program in {"python", "python3", "perl", "ruby", "node", "php", "lua", "pwsh", "powershell"}:
        if any(arg in {"-c", "-e", "--eval", "-EncodedCommand", "-Command"} for arg in operands):
            return True
    if program == "dd" and any(x.startswith(("of=", "if=/dev/")) for x in operands):
        return True
    if program == "rm":
        recursive = any(x in {"--recursive", "-r", "-R"} or
                        (x.startswith("-") and not x.startswith("--") and "r" in x[1:])
                        for x in operands)
        files = [x for x in operands if not x.startswith("-")]
        if any(_sensitive_path(x, recursive=recursive) for x in files):
            return True
        if recursive and not files:
            return True
    if program in {"rmdir", "shred", "truncate", "mv", "cp", "tee"}:
        if any(_sensitive_path(x) for x in operands if not x.startswith("-")):
            return True
    if program in {"chmod", "chown", "chgrp"}:
        if any(_sensitive_path(x) for x in operands if x.startswith(("/", "~/", "../"))):
            return True
    if program == "find":
        if any(x in {"-delete", "-exec", "-execdir", "-ok", "-okdir"} for x in operands):
            return True
    if program == "systemctl":
        if any(x in {"reboot", "poweroff", "halt", "rescue", "emergency", "isolate", "kexec"} for x in operands):
            return True
    if program == "loginctl" and any(x in {"reboot", "poweroff", "halt"} for x in operands):
        return True
    if program == "service" and any(x in {"reboot", "shutdown", "poweroff", "halt"} for x in operands):
        return True
    if program == "docker" and len(operands) > 1 and operands[0] == "system" and operands[1] == "prune":
        return True
    if program == "git":
        if any(x in {"--hard", "--force", "--force-with-lease", "-f", "--mirror"} for x in operands):
            return True
        if operands and operands[0] in {"clean", "filter-branch"}:
            return True
    return False


def requires_local_approval(command: str) -> bool:
    """True means review; False means no recognizable high-risk shell operation.

    Execution of a trusted-looking binary or script can still be destructive.
    """
    if not isinstance(command, str) or not command.strip() or len(command.encode("utf-8")) > 32768:
        return True
    # Commands generated at runtime cannot be screened reliably.
    if any(x in command for x in ("\n", "\r", "\x00", "\x1b", "$(", "`", "<<", "$" + "{")):
        return True
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return True
    segment: list[str] = []
    for token in [*tokens, ";"]:
        if token and all(c in ";&|<>()" for c in token) and token not in _SEPARATORS | _REDIRECT:
            return True
        if token in _SEPARATORS:
            if _segment_requires_review(segment):
                return True
            segment = []
        elif token in _REDIRECT or token not in {"", "\\"}:
            segment.append(token)
    return False
