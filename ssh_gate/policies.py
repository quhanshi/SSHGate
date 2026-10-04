from __future__ import annotations
import posixpath
import shlex
from .readonly import ReadOnlyDecision, FORBIDDEN


def scope_contains(cwd, roots):
    if not isinstance(cwd,str) or not cwd.startswith('/'):
        return False
    cwd=posixpath.normpath(cwd)
    return any(cwd==posixpath.normpath(r) or cwd.startswith(posixpath.normpath(r).rstrip('/')+'/') for r in roots)


def python_test_command(command):
    # This is explicitly trusted test execution, not a claim that test code is read-only.
    if any(c in command for c in FORBIDDEN | set('*?[')): return ReadOnlyDecision(False)
    try: argv=shlex.split(command)
    except ValueError: return ReadOnlyDecision(False)
    if not argv or argv[0] not in {'pytest','/usr/bin/pytest'}: return ReadOnlyDecision(False)
    flags={'-q','-v','-vv','-s','-x','--collect-only','--disable-warnings','--strict-markers'}
    values={'-k','-m','--maxfail'}
    i=1
    while i<len(argv):
        a=argv[i]
        if a in flags: pass
        elif a in values:
            i+=1
            if i>=len(argv): return ReadOnlyDecision(False)
        elif a.startswith('--maxfail=') and a.split('=',1)[1].isdigit(): pass
        elif a.startswith('-') or a.startswith('/') or '..' in a.split('/'): return ReadOnlyDecision(False)
        i+=1
    return ReadOnlyDecision(True,'exec /usr/bin/pytest '+' '.join(shlex.quote(a) for a in argv[1:]),
                            '本地授权的测试执行；测试代码能够修改服务器文件','python_tests')
