"""Bounded, Linux-only service inspection and stop helpers.

The embedded remote program is a fixed, reviewed implementation. Arguments are
passed as one shell-quoted JSON value, not interpolated into Python or shell code.
No sudo/root escalation, Docker, Nomad or system-wide systemctl is supported.
"""
from __future__ import annotations

import json
import posixpath
import re
import shlex

OPS = {"service_processes", "service_services", "service_stop", "service_verify"}
UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,180}\.service\Z")
FIELDS = {
    "service_processes": {"workspace_root", "limit"},
    "service_services": {"workspace_root", "limit"},
    "service_stop": {"workspace_root", "target_kind", "pid", "expected_start_ticks",
                     "expected_pgid", "expected_cwd", "unit_name",
                     "expected_main_pid", "expected_fragment_path", "ports"},
    "service_verify": {"workspace_root", "target_kind", "pid", "expected_start_ticks",
                       "expected_pgid", "expected_cwd", "unit_name",
                       "expected_main_pid", "expected_fragment_path", "ports"},
}
# Remote program intentionally does not expose a generic command executor.
REMOTE = r'''
import json, os, re, signal, socket, subprocess, sys, time

def fail(message):
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    sys.exit(3)

def inside(path, root):
    return path == root or path.startswith(root + "/")

def canonical_root(raw):
    if raw.startswith("~/"):
        raw = os.path.join(os.path.expanduser("~"), raw[2:])
    if not raw.startswith("/") or "/../" in raw + "/" or "/./" in raw + "/":
        fail("workspace_root must be an absolute, non-traversing path")
    absolute = os.path.abspath(raw)
    real = os.path.realpath(absolute)
    denied = ("/", "/etc", "/usr", "/var", "/run", "/tmp", "/proc", "/dev",
              "/sys", "/boot", "/opt", "/home", "/root", "/srv")
    if absolute != real or absolute in denied or not os.path.isdir(real):
        fail("workspace_root must be an existing, non-symlink, specific directory")
    return real

def process(pid):
    try:
        if os.stat("/proc/%d" % pid).st_uid != os.geteuid():
            return None
        stat = open("/proc/%d/stat" % pid, encoding="ascii").read()
        fields = stat[stat.rfind(") ") + 2:].split()
        if fields[0] == "Z":
            return None
        cwd = os.readlink("/proc/%d/cwd" % pid)
        if cwd.endswith(" (deleted)"):
            return None
        cwd = os.path.realpath(cwd)
        cg = open("/proc/%d/cgroup" % pid, encoding="utf-8", errors="replace").read(4096).lower()
        managed = bool(re.search(r"nomad|docker|containerd|kubepods|\.service(?:/|$)", cg))
        return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
                "start_ticks": fields[19], "cwd": cwd,
                "command": stat[stat.find("(") + 1:stat.rfind(")")],
                "managed": managed}
    except (OSError, ValueError, IndexError):
        return None

def processes():
    for name in os.listdir("/proc"):
        if name.isdecimal():
            item = process(int(name))
            if item:
                yield item

def ports_for(pids):
    sockets = {}
    for pid in pids:
        try:
            for fd in os.listdir("/proc/%d/fd" % pid)[:4096]:
                link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
                if link.startswith("socket:["):
                    sockets.setdefault(link[8:-1], set()).add(pid)
        except OSError:
            pass
    result = {}
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, encoding="ascii") as inp:
                next(inp)
                for line in inp:
                    parts = line.split()
                    if len(parts) > 9 and parts[3] == "0A" and parts[9] in sockets:
                        port = int(parts[1].split(":")[-1], 16)
                        for pid in sockets[parts[9]]:
                            result.setdefault(pid, set()).add(port)
        except OSError:
            pass
    return {pid: sorted(values) for pid, values in result.items()}

def systemctl(*args):
    try:
        return subprocess.run(["systemctl", "--user", "--no-pager", *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("systemd user manager unavailable")

def unit_info(name):
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,180}\.service", name):
        fail("invalid user unit name")
    data = systemctl("show", name, "--property=Id,LoadState,ActiveState,SubState,MainPID,WorkingDirectory,FragmentPath,Restart")
    if data.returncode:
        fail("systemd user unit inspection failed")
    props = dict(line.split("=", 1) for line in data.stdout.splitlines() if "=" in line)
    return {"unit_name": name, "load_state": props.get("LoadState", ""),
            "active_state": props.get("ActiveState", ""), "sub_state": props.get("SubState", ""),
            "main_pid": int(props.get("MainPID", "0") or "0"),
            "working_directory": props.get("WorkingDirectory", ""),
            "fragment_path": props.get("FragmentPath", ""),
            "restart": props.get("Restart", "")}

def safe_unit(info, root):
    name = info["unit_name"].lower()
    if any(marker in name for marker in ("nomad", "docker", "containerd", "sshgate")):
        fail("protected service name")
    wd = info["working_directory"]
    if not wd or not wd.startswith("/") or os.path.realpath(wd) != wd or not inside(wd, root):
        fail("service WorkingDirectory is not in the requested workspace")
    if info["load_state"] != "loaded":
        fail("service unit is not loaded")
    pid = info["main_pid"]
    if pid:
        p = process(pid)
        if not p or not inside(p["cwd"], root) or p["managed"] and "nomad" in name:
            fail("service main PID not safely attributable to workspace")
    return info

def identity(p, args, root):
    if (not p or p["pid"] <= 1 or p["pid"] == os.getpid() or
        p["start_ticks"] != args["expected_start_ticks"] or
        p["pgid"] != args["expected_pgid"] or
        p["cwd"] != args["expected_cwd"] or
        not inside(p["cwd"], root) or p["managed"]):
        fail("PROCESS_IDENTITY_CHANGED or protected/managed process")
    return p

def group_members(pgid):
    # Include unknown-UID/unreadable processes; never silently omit a group member
    # and then issue a group-wide signal based on an incomplete process list.
    rows = []
    for name in os.listdir("/proc"):
        if not name.isdecimal():
            continue
        pid = int(name)
        try:
            stat = open("/proc/%d/stat" % pid, encoding="ascii").read()
            fields = stat[stat.rfind(") ") + 2:].split()
            if fields[0] == "Z" or int(fields[2]) != pgid:
                continue
        except (OSError, ValueError, IndexError):
            continue
        rows.append(process(pid) or {"pid": pid, "managed": True, "cwd": ""})
    return rows

def group_safe(pgid, root):
    members = group_members(pgid)
    if not members or any(p["managed"] or not inside(p["cwd"], root) or p["pid"] == os.getpid() for p in members):
        fail("process group contains outside-workspace or managed members")
    return members

def same_process(pid, ticks):
    p = process(pid)
    return p is not None and p["start_ticks"] == ticks

def check_ports(wanted):
    if not wanted:
        return []
    open_ports = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, encoding="ascii") as inp:
                next(inp)
                for row in inp:
                    cols = row.split()
                    if len(cols) > 3 and cols[3] == "0A":
                        open_ports.add(int(cols[1].split(":")[-1], 16))
        except OSError:
            return list(wanted)  # unknown is never reported free
    return sorted(set(wanted) & open_ports)

mode = sys.argv[1]
args = json.loads(sys.argv[2])
root = canonical_root(args["workspace_root"])
kind = args.get("target_kind", "")
if mode == "service_processes":
    rows = [p for p in processes() if inside(p["cwd"], root)]
    rows.sort(key=lambda p: p["pid"])
    rows = rows[:args["limit"]]
    port_map = ports_for([p["pid"] for p in rows])
    for p in rows:
        p["listen_ports"] = port_map.get(p["pid"], [])
        p["process_group_safe"] = (not p["managed"] and
            all(not m["managed"] and inside(m["cwd"], root) for m in group_members(p["pgid"])))
        p["command"] = p["command"][:80]  # argv is never returned; it can contain secrets
    print(json.dumps({"ok": True, "workspace_root": root, "processes": rows}))
elif mode == "service_services":
    response = systemctl("list-units", "--type=service", "--all", "--plain", "--no-legend")
    if response.returncode:
        fail("systemd user manager unavailable")
    results = []
    for line in response.stdout.splitlines()[:300]:
        fields = line.split()
        if fields and re.fullmatch(r"[A-Za-z0-9_.@:-]{1,180}\.service", fields[0]):
            info = unit_info(fields[0])
            wd = info["working_directory"]
            if wd and inside(os.path.realpath(wd), root):
                info["can_request_stop"] = (info["load_state"] == "loaded" and
                    os.path.realpath(wd) == wd and not any(x in info["unit_name"].lower()
                    for x in ("nomad", "docker", "containerd", "sshgate")))
                results.append(info)
                if len(results) >= args["limit"]:
                    break
    print(json.dumps({"ok": True, "workspace_root": root, "services": results}))
elif mode in ("service_stop", "service_verify"):
    wanted = args["ports"]
    if kind == "user_service":
        before = unit_info(args["unit_name"])
        safe_unit(before, root)
        if mode == "service_stop" and (before["main_pid"] != args["expected_main_pid"] or
            before["fragment_path"] != args["expected_fragment_path"]):
            fail("PROCESS_IDENTITY_CHANGED: service identity changed")
        if mode == "service_stop":
            response = systemctl("stop", args["unit_name"])
            if response.returncode:
                fail("systemctl --user stop failed")
        after = unit_info(args["unit_name"])
        remaining_ports = check_ports(wanted)
        stopped = after["active_state"] in ("inactive", "failed") and not remaining_ports
        print(json.dumps({"ok": True, "signal_sent": mode == "service_stop",
                          "verified_stopped": stopped, "service": after,
                          "occupied_ports": remaining_ports,
                          "restart_risk": after["restart"] not in ("", "no")}))
    elif kind in ("process", "process_group"):
        pid = args["pid"]
        p = process(pid)
        if mode == "service_stop":
            identity(p, args, root)
            if kind == "process_group":
                if pid != p["pgid"]:
                    fail("process group stop requires PID == PGID (leader)")
                group_safe(p["pgid"], root)
            signal_target = -p["pgid"] if kind == "process_group" else pid
            os.kill(signal_target, signal.SIGTERM)
            for i in range(20):
                if kind == "process":
                    alive = same_process(pid, args["expected_start_ticks"])
                else:
                    alive = bool(group_members(args["expected_pgid"]))
                if not alive:
                    break
                time.sleep(0.1)
            if alive:
                identity(process(pid), args, root)
                if kind == "process_group":
                    group_safe(args["expected_pgid"], root)
                os.kill(signal_target, signal.SIGKILL)
                for i in range(20):
                    time.sleep(0.1)
                    if not (same_process(pid, args["expected_start_ticks"]) if kind == "process"
                            else bool(group_members(args["expected_pgid"]))):
                        break
        remaining = (same_process(pid, args["expected_start_ticks"]) if kind == "process"
                     else bool(group_members(args["expected_pgid"])))
        remaining_ports = check_ports(wanted)
        print(json.dumps({"ok": True, "signal_sent": mode == "service_stop",
                          "verified_stopped": not remaining and not remaining_ports,
                          "original_identity_alive": bool(remaining),
                          "occupied_ports": remaining_ports}))
    else:
        fail("unknown target kind")
else:
    fail("unknown operation")
'''

def command(operation: str, arguments: dict) -> tuple[str, str, dict]:
    """Validate structure before admission; return display summary, literal remote command, args."""
    if operation not in OPS or not isinstance(arguments, dict):
        raise ValueError("Unsupported service operation")
    if set(arguments) - FIELDS[operation]:
        raise ValueError("Unknown service arguments")
    args = dict(arguments)
    root = args.get("workspace_root")
    if not isinstance(root, str) or len(root) > 1024 or not (
            root.startswith("/") or root.startswith("~/")) or "\n" in root or "\x00" in root:
        raise ValueError("workspace_root must be a remote absolute path or ~/subdir")
    if operation in ("service_processes", "service_services"):
        limit = args.get("limit", 60)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        args["limit"] = limit
    else:
        kind = args.get("target_kind")
        if kind not in ("process", "process_group", "user_service"):
            raise ValueError("target_kind invalid")
        ports = args.get("ports", [])
        if not isinstance(ports, list) or len(ports) > 16 or any(
                type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("ports must be a list of 1..16 TCP port numbers")
        args["ports"] = ports
        if kind == "user_service":
            unit = args.get("unit_name")
            if not isinstance(unit, str) or not UNIT.fullmatch(unit):
                raise ValueError("unit_name invalid")
            if (type(args.get("expected_main_pid")) is not int or
                    not 0 <= args["expected_main_pid"] < 1 << 30 or
                    not isinstance(args.get("expected_fragment_path"), str) or
                    not args["expected_fragment_path"].startswith("/")):
                raise ValueError("service inspection identity required")
            if any(k in args for k in ("pid", "expected_start_ticks", "expected_pgid", "expected_cwd")):
                raise ValueError("conflicting process parameters")
        else:
            pid, pgid = args.get("pid"), args.get("expected_pgid")
            ticks, cwd = args.get("expected_start_ticks"), args.get("expected_cwd")
            if (type(pid) is not int or not 2 <= pid < 1 << 30 or
                    type(pgid) is not int or not 2 <= pgid < 1 << 30 or
                    not isinstance(ticks, str) or not re.fullmatch(r"[0-9]{1,24}", ticks) or
                    not isinstance(cwd, str) or not cwd.startswith("/") or len(cwd) > 1024 or
                    any(k in args for k in ("unit_name", "expected_main_pid", "expected_fragment_path"))):
                raise ValueError("process inspection identity required")
    label = (args.get("unit_name") or str(args.get("pid", ""))) if operation in (
        "service_stop", "service_verify") else root
    # The display is never a command executor. Remote uses fixed reviewed Python.
    summary = operation + " " + str(label) + " [workspace=" + root + "]"
    if operation in ("service_stop", "service_verify"):
        if args["target_kind"] == "user_service":
            summary += " [main_pid=" + str(args["expected_main_pid"]) + " fragment=" + args["expected_fragment_path"] + "]"
        else:
            summary += " [start_ticks=" + args["expected_start_ticks"] + " pgid=" + str(args["expected_pgid"]) + " cwd=" + args["expected_cwd"] + "]"
        summary += " [ports=" + repr(args["ports"]) + "]"
    encoded = json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    remote_command = "python3 -c " + shlex.quote(REMOTE) + " " + shlex.quote(operation) + " " + shlex.quote(encoded)
    return summary, remote_command, args
