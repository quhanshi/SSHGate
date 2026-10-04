from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

BINARIES = {n: f"/usr/bin/{n}" for n in (
    "ls", "cat", "tail", "head", "pwd", "wc", "grep", "find", "stat", "du", "df",
    "ps", "free", "uname", "git", "docker")}
FORBIDDEN = set(";|&><`$(){}\n\r")

@dataclass(frozen=True)
class ReadOnlyDecision:
    allowed: bool
    executable_command: str = ""
    explanation: str = ""
    category: str = ""

# Only these switches are accepted automatically. Unknown arguments remain reviewable.
OPTIONS = {
    "ls": ("aAbBcCdDfFghHiIklLmNnoprRqRsStuUvwxXZ1", {"--all", "--almost-all", "--directory", "--human-readable", "--inode", "--numeric-uid-gid", "--recursive", "--reverse", "--size", "--classify", "--file-type", "--literal", "--group-directories-first"}, {"--color", "--sort", "--time", "--block-size", "--quoting-style"}, ""),
    "cat": ("AbEenstTuv", {"--show-all", "--number-nonblank", "--show-ends", "--number", "--squeeze-blank", "--show-tabs", "--show-nonprinting"}, set(), ""),
    "tail": ("fFqv", {"--follow", "--retry", "--quiet", "--silent", "--verbose"}, {"--lines", "--bytes", "--pid", "--sleep-interval", "--max-unchanged-stats"}, "nc"),
    "head": ("qv", {"--quiet", "--silent", "--verbose"}, {"--lines", "--bytes"}, "nc"),
    "pwd": ("LP", {"--logical", "--physical"}, set(), ""),
    "wc": ("cLlmw", {"--bytes", "--max-line-length", "--lines", "--chars", "--words"}, set(), ""),
    "grep": ("EFGPivwxycLlnHhboqsaIrRzZ", {"--extended-regexp", "--fixed-strings", "--perl-regexp", "--ignore-case", "--invert-match", "--word-regexp", "--line-regexp", "--count", "--files-without-match", "--files-with-matches", "--line-number", "--with-filename", "--no-filename", "--only-matching", "--quiet", "--silent", "--no-messages", "--text", "--binary", "--recursive", "--dereference-recursive", "--null-data", "--null", "--line-buffered"}, {"--regexp", "--file", "--after-context", "--before-context", "--context", "--max-count", "--include", "--exclude", "--exclude-dir", "--color", "--binary-files", "--directories", "--devices"}, "efABCm"),
    "stat": ("Lf", {"--dereference", "--file-system", "--terse"}, {"--format", "--printf"}, "c"),
    "du": ("aBbcDdhHklLmsSx", {"--all", "--bytes", "--dereference-args", "--human-readable", "--summarize", "--one-file-system", "--apparent-size", "--count-links", "--separate-dirs", "--si", "--total", "--inodes"}, {"--max-depth", "--block-size", "--exclude", "--threshold"}, "Bd"),
    "df": ("aBhiHkPlmTtTx", {"--all", "--human-readable", "--si", "--inodes", "--local", "--portability", "--print-type", "--total"}, {"--block-size", "--type", "--exclude-type", "--output"}, "Btx"),
    "free": ("bkmgtphwlv", {"--bytes", "--kibi", "--mebi", "--gibi", "--tebi", "--pebi", "--human", "--wide", "--lohi", "--total", "--si"}, {"--seconds", "--count"}, "sc"),
    "uname": ("asnrvmpio", {"--all", "--kernel-name", "--nodename", "--kernel-release", "--kernel-version", "--machine", "--processor", "--hardware-platform", "--operating-system"}, set(), ""),
    "ps": ("aAdefHjLlMNrsTuvwx", {"--everyone", "--forest", "--no-headers", "--headers", "--threads"}, {"--pid", "--ppid", "--user", "--User", "--group", "--Group", "--format", "--sort", "--cols", "--rows"}, "pPoUuGCq"),
}

def _options(args, spec, *, bsd=False):
    short, flags, values, value_short = spec
    operands=[]; end=False; i=0
    while i < len(args):
        arg=args[i]
        if end or arg == "-" or not arg.startswith("-"):
            if bsd and not end and re.fullmatch(r"[aefHjlLrsTuvwx]+", arg):
                i+=1; continue
            operands.append(arg); i+=1; continue
        if arg == "--":
            end=True; i+=1; continue
        if arg.startswith("--"):
            name, sep, value=arg.partition("=")
            if name in flags and not sep:
                i+=1; continue
            if name not in values:
                return None
            if not sep:
                i+=1
                if i >= len(args): return None
                value=args[i]
            if not value: return None
        else:
            chars=arg[1:]; pos=0
            if not chars: return None
            while pos < len(chars):
                c=chars[pos]
                if c in value_short:
                    if pos+1 == len(chars):
                        i+=1
                        if i >= len(args): return None
                    break
                if c not in short: return None
                pos+=1
        i+=1
    return operands

def _find(args):
    unary={"-name", "-iname", "-path", "-ipath", "-type", "-maxdepth", "-mindepth", "-size", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-user", "-group", "-uid", "-gid", "-perm", "-newer"}
    nullary={"-print", "-print0", "-ls", "-empty", "-readable", "-writable", "-executable", "-true", "-false", "-a", "-and", "-o", "-or", "!", "-not", "-xdev", "-mount"}
    i=0; expression=False
    while i < len(args):
        a=args[i]
        if a in {"-P", "-H", "-L"} and not expression: i+=1; continue
        if a in unary:
            expression=True; i+=1
            if i >= len(args): return False
            if a in {"-maxdepth", "-mindepth"} and not re.fullmatch(r"[0-9]{1,4}", args[i]): return False
        elif a in nullary: expression=True
        elif a.startswith("-") or expression: return False
        elif any(c in a for c in "*?["): return False
        i+=1
    return True

GIT_FLAGS={"--short", "--branch", "--porcelain", "--untracked-files", "--ignored", "--oneline", "--stat", "--numstat", "--shortstat", "--name-only", "--name-status", "--patch", "--no-patch", "--cached", "--staged", "--check", "--summary", "--all", "--graph", "--no-merges", "--merges", "--reverse", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-show-signature", "--color", "--decorate", "--relative", "--abbrev-commit"}
GIT_VALUES={"--max-count", "--since", "--until", "--after", "--before", "--author", "--committer", "--grep", "--format", "--pretty", "--diff-filter", "--unified"}

def _git(args):
    if not args or args[0] not in {"status", "log", "diff"}: return False
    sub=args[0]; i=1; paths=False
    while i < len(args):
        a=args[i]
        if paths: i+=1; continue
        if a == "--": paths=True; i+=1; continue
        if not a.startswith("-"): i+=1; continue
        name, sep, val=a.partition("=")
        if name in GIT_FLAGS:
            if sep and (name not in {"--porcelain", "--untracked-files", "--ignored", "--color", "--decorate", "--relative"} or not val): return False
        elif name in GIT_VALUES:
            if not sep:
                i+=1
                if i >= len(args): return False
        elif a in {"-p", "-s", "-b", "-z", "-w"}: pass
        elif a in {"-n", "-U"}:
            i+=1
            if i >= len(args) or not args[i].isdigit(): return False
        elif re.fullmatch(r"-(?:n|U)[0-9]+", a): pass
        else: return False
        i+=1
    return True

def scoped_read_paths(command: str) -> list[str]:
    """Path operands, including paths carried in options; refuse recursive link traversal."""
    argv = shlex.split(command)
    name, args = argv[0].rsplit('/', 1)[-1], argv[1:]
    if name == 'll': name = 'ls'
    if name == 'find':
        paths = []; i = 0; expression = False
        while i < len(args):
            arg = args[i]
            if arg == '-P':
                i += 1; continue
            if arg in {'-H', '-L'}:
                raise ValueError('目录授权内不允许 find 跟随符号链接')
            if arg.startswith('-') or arg == '!': expression = True
            if not expression: paths.append(arg)
            if arg == '-newer':
                i += 1; paths.append(args[i])
            elif arg in {'-name', '-iname', '-path', '-ipath', '-type', '-maxdepth', '-mindepth',
                         '-size', '-mtime', '-mmin', '-atime', '-amin', '-ctime', '-cmin',
                         '-user', '-group', '-uid', '-gid', '-perm'}:
                i += 1
            i += 1
        return paths or ['.']
    if name not in OPTIONS: return []
    paths = _options(args, OPTIONS[name])
    if paths is None: raise ValueError('无法确认只读命令的路径参数')
    pattern_supplied = False; extra_paths = []; i = 0
    short, flags, values, value_short = OPTIONS[name]
    while i < len(args):
        arg = args[i]
        if arg == '--': break
        if arg.startswith('--'):
            key, sep, value = arg.partition('=')
            if name == 'du' and key == '--dereference-args' or name == 'grep' and key == '--dereference-recursive':
                raise ValueError('目录授权内不允许递归跟随符号链接')
            if key in values:
                if not sep: i += 1; value = args[i]
                if name == 'grep' and key in {'--regexp', '--file'}:
                    pattern_supplied = True
                    if key == '--file': extra_paths.append(value)
        elif arg.startswith('-') and arg != '-':
            chars = arg[1:]; pos = 0
            while pos < len(chars):
                char = chars[pos]
                if name == 'du' and char in 'DHL' or name == 'grep' and char == 'R':
                    raise ValueError('目录授权内不允许递归跟随符号链接')
                if char in value_short:
                    value = chars[pos + 1:]
                    if not value: i += 1; value = args[i]
                    if name == 'grep' and char in 'ef':
                        pattern_supplied = True
                        if char == 'f': extra_paths.append(value)
                    break
                pos += 1
        i += 1
    if name == 'grep' and not pattern_supplied: paths = paths[1:]
    return extra_paths + paths or ['.']


def readonly_command(command: str) -> ReadOnlyDecision:
    no=lambda reason: ReadOnlyDecision(False, explanation=reason)
    if any(c in FORBIDDEN for c in command): return no("含 shell 操作符、替换或多行内容，需要人工审批")
    try: argv=shlex.split(command, posix=True)
    except ValueError: return no("命令引号不完整，需要人工审批")
    if not argv: return no("空命令")
    first=argv[0]; name=first.rsplit("/",1)[-1]
    if name == "ll" and first == "ll": argv=["ls", "-l", *argv[1:]]; name="ls"
    if name not in BINARIES or first not in {name, "ll", f"/usr/bin/{name}", f"/bin/{name}"}: return no("命令不在只读列表中，需要人工审批")
    if name != "find" and any(c in command for c in "*?["): return no("通配符需使用结构化搜索接口，或人工审批")
    args=argv[1:]; category="read_fs"
    if name == "find": valid=_find(args)
    elif name == "git": valid=_git(args); category="git_read"
    elif name == "docker":
        category="docker_read"
        specs={"ps":("aqs", {"--all", "--quiet", "--size", "--no-trunc", "--latest"}, {"--filter", "--last", "--format"}, "fn"), "logs":("ft", {"--follow", "--timestamps", "--details"}, {"--since", "--until", "--tail"}, ""), "inspect":("s", {"--size"}, {"--format", "--type"}, "f")}
        valid=bool(args and args[0] in specs and _options(args[1:],specs[args[0]]) is not None)
    else:
        operands=_options(args, OPTIONS[name], bsd=name == "ps")
        valid=operands is not None and not (name in {"cat", "tail", "head", "wc", "grep"} and not operands and name != "grep")
        if name == "grep": valid=valid and bool(args)
        if name in {"df", "ps", "free", "uname"}: category="diagnostics"
    if not valid: return no("参数未通过该工具的只读规则，需要人工审批")
    rendered=[]
    for arg in args:
        rendered.append('"$HOME"' if arg == "~" else '"$HOME"/'+shlex.quote(arg[2:]) if arg.startswith("~/") else shlex.quote(arg))
    prefix=f"exec {BINARIES[name]}"
    if name == "git":
        prefix="exec /usr/bin/env GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_COUNT=0 GIT_CONFIG_NOSYSTEM=1 /usr/bin/git --no-pager -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.pager=cat -c log.showSignature=false"
        rendered.insert(1, "--no-ext-diff --no-textconv" if args[0] in {"diff", "log"} else "")
    return ReadOnlyDecision(True, prefix+" "+" ".join(rendered) if rendered else prefix, f"只读类别 {category}：固定路径与参数级白名单", category)
