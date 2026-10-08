"""Linux integration tests for fixed service tools; never touches host services."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from ssh_gate.config import Config, Server
from ssh_gate.core import ApprovalManager
from ssh_gate.service_ops import REMOTE, command
from ssh_gate.ssh import RunResult


def invoke(operation, args, *, env=None):
    return subprocess.run([sys.executable, "-c", REMOTE, operation, json.dumps(args)],
                          capture_output=True, text=True, timeout=12, env=env)


@unittest.skipUnless(sys.platform.startswith("linux") and Path("/proc/self/stat").exists(),
                     "Linux /proc required")
class LinuxServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = str(Path(self.tmp.name).resolve())
        self.proc = None
        self.addCleanup(self.cleanup_process)

    def cleanup_process(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def spawn(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-c", "import os,sys,time; os.chdir(sys.argv[1]); time.sleep(30)", self.root],
            start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if os.readlink("/proc/%d/cwd" % self.proc.pid) == self.root:
                    return self.proc.pid
            except OSError:
                pass
            time.sleep(.01)
        self.fail("child did not enter workspace")

    def snapshot(self):
        pid = self.spawn()
        response = invoke("service_processes", {"workspace_root": self.root, "limit": 100})
        self.assertEqual(0, response.returncode, response.stderr + response.stdout)
        data = json.loads(response.stdout)
        self.assertTrue(data["ok"])
        rows = [r for r in data["processes"] if r["pid"] == pid]
        self.assertEqual(1, len(rows), rows)
        return rows[0]

    def test_inspection_and_pid_stop_then_readonly_verify(self):
        row = self.snapshot()
        args = {"workspace_root": self.root, "target_kind": "process",
                "pid": row["pid"], "expected_start_ticks": row["start_ticks"],
                "expected_pgid": row["pgid"], "expected_cwd": row["cwd"], "ports": []}
        finished = invoke("service_stop", args)
        if row["managed"]:
            # Hosted CI runners may put all children in a systemd .service cgroup.
            # The safe behavior is to refuse this stop; never disable that guard
            # merely to make the integration test pass on managed hosts.
            self.assertNotEqual(0, finished.returncode)
            self.assertIn("protected/managed process", finished.stdout)
            self.assertIsNone(self.proc.poll())
            return
        self.assertEqual(0, finished.returncode, finished.stdout + finished.stderr)
        result = json.loads(finished.stdout)
        self.assertTrue(result["signal_sent"])
        self.assertTrue(result["verified_stopped"])
        self.proc.wait(timeout=4)
        again = invoke("service_verify", args)
        self.assertTrue(json.loads(again.stdout)["verified_stopped"])

    def test_stale_start_ticks_cannot_signal_pid(self):
        row = self.snapshot()
        args = {"workspace_root": self.root, "target_kind": "process", "pid": row["pid"],
                "expected_start_ticks": str(int(row["start_ticks"]) + 1),
                "expected_pgid": row["pgid"], "expected_cwd": row["cwd"], "ports": []}
        attempt = invoke("service_stop", args)
        self.assertNotEqual(0, attempt.returncode)
        self.assertIn("PROCESS_IDENTITY_CHANGED", attempt.stdout)
        self.assertIsNone(self.proc.poll())

    def test_wrong_workspace_and_unsafe_root_rejected(self):
        row = self.snapshot()
        with tempfile.TemporaryDirectory() as other:
            args = {"workspace_root": other, "target_kind": "process", "pid": row["pid"],
                    "expected_start_ticks": row["start_ticks"], "expected_pgid": row["pgid"],
                    "expected_cwd": row["cwd"], "ports": []}
            self.assertNotEqual(0, invoke("service_stop", args).returncode)
            self.assertIsNone(self.proc.poll())
        bad_root = invoke("service_processes", {"workspace_root": "/", "limit": 20})
        self.assertNotEqual(0, bad_root.returncode)

    def test_systemd_unit_outside_workspace_never_stopped(self):
        with tempfile.TemporaryDirectory() as bin_dir:
            fake = Path(bin_dir) / "systemctl"
            record = Path(bin_dir) / "stop_called"
            fake.write_text("#!/bin/sh\n"
                            "case \" $* \" in *' show '*) printf "
                            "'Id=dev.service\\nLoadState=loaded\\nActiveState=active\\n"
                            "SubState=running\\nMainPID=0\\nWorkingDirectory=/tmp\\n"
                            "FragmentPath=/tmp/dev.service\\nRestart=always\\n';;"
                            " *' stop '*) touch '" + str(record) + "';; esac\n",
                            encoding="utf-8")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=bin_dir + ":" + os.environ.get("PATH", ""))
            args = {"workspace_root": self.root, "target_kind": "user_service",
                    "unit_name": "dev.service", "expected_main_pid": 0,
                    "expected_fragment_path": "/tmp/dev.service", "ports": []}
            response = invoke("service_stop", args, env=env)
            self.assertNotEqual(0, response.returncode)
            self.assertFalse(record.exists())


    def fake_user_systemd(self, directory, *, managed_launcher=False, restart_on_stop=False):
        binary = Path(directory) / "systemctl"
        marker = Path(directory) / "stopped"
        script = '''#!/usr/bin/env python3
import os, sys
cmd = sys.argv[1:]
if "show" in cmd:
    stopped = os.path.exists(os.environ["FAKE_STOP_MARK"])
    active = (not stopped) or os.environ.get("FAKE_RESTART", "") == "1"
    pid = os.environ["FAKE_MAIN_PID"] if active else "0"
    print("Id=dev.service")
    print("LoadState=loaded")
    print("ActiveState=" + ("active" if active else "inactive"))
    print("SubState=" + ("running" if active else "dead"))
    print("MainPID=" + pid)
    print("WorkingDirectory=" + os.environ["FAKE_WORKSPACE"])
    print("FragmentPath=" + os.environ["FAKE_UNIT_FRAGMENT"])
    print("Restart=always")
    print("ExecStart=" + os.environ["FAKE_EXEC_START"])
    print("ExecStop=")
elif "list-units" in cmd:
    print("dev.service loaded active running Test service")
elif "stop" in cmd:
    open(os.environ["FAKE_STOP_MARK"], "w").close()
else:
    sys.exit(2)
'''
        binary.write_text(script, encoding="utf-8")
        binary.chmod(0o755)
        env = {**os.environ,
               "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
               "FAKE_STOP_MARK": str(marker),
               "FAKE_MAIN_PID": str(self.proc.pid if self.proc else 0),
               "FAKE_WORKSPACE": self.root,
               "FAKE_UNIT_FRAGMENT": str(Path(directory) / "dev.service"),
               "FAKE_EXEC_START": "/usr/bin/docker run --rm test" if managed_launcher else "/usr/bin/sleep 30",
               "FAKE_RESTART": "1" if restart_on_stop else "0"}
        return env, marker

    def test_systemd_inactive_is_not_enough_when_original_pid_still_exists(self):
        row = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.fake_user_systemd(directory)
            inspect = invoke("service_services", {"workspace_root": self.root, "limit": 10}, env=env)
            self.assertEqual(0, inspect.returncode, inspect.stdout + inspect.stderr)
            info = json.loads(inspect.stdout)["services"][0]
            self.assertEqual(row["pid"], info["main_pid"])
            self.assertEqual(row["start_ticks"], info["main_start_ticks"])
            args = {"workspace_root": self.root, "target_kind": "user_service",
                    "unit_name": "dev.service", "expected_main_pid": row["pid"],
                    "expected_main_start_ticks": row["start_ticks"],
                    "expected_fragment_path": info["fragment_path"], "ports": []}
            stopped = invoke("service_stop", args, env=env)
            self.assertEqual(0, stopped.returncode, stopped.stdout + stopped.stderr)
            result = json.loads(stopped.stdout)
            self.assertTrue(marker.exists())
            self.assertTrue(result["signal_sent"])
            self.assertFalse(result["verified_stopped"])
            self.assertTrue(result["original_identity_alive"])
            verify = invoke("service_verify", args, env=env)
            self.assertFalse(json.loads(verify.stdout)["verified_stopped"])

    def test_systemd_stale_main_pid_or_managed_launcher_never_calls_stop(self):
        row = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.fake_user_systemd(directory)
            args = {"workspace_root": self.root, "target_kind": "user_service",
                    "unit_name": "dev.service", "expected_main_pid": row["pid"],
                    "expected_main_start_ticks": str(int(row["start_ticks"]) + 1),
                    "expected_fragment_path": env["FAKE_UNIT_FRAGMENT"], "ports": []}
            stale = invoke("service_stop", args, env=env)
            self.assertNotEqual(0, stale.returncode)
            self.assertIn("PROCESS_IDENTITY_CHANGED", stale.stdout)
            self.assertFalse(marker.exists())
            env["FAKE_EXEC_START"] = "/usr/bin/docker run --rm test"
            protected = invoke("service_stop", {**args, "expected_main_start_ticks": row["start_ticks"]}, env=env)
            self.assertNotEqual(0, protected.returncode)
            self.assertIn("protected service name", protected.stdout)
            self.assertFalse(marker.exists())

    def test_service_restart_cannot_be_reported_stopped(self):
        row = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.fake_user_systemd(directory, restart_on_stop=True)
            args = {"workspace_root": self.root, "target_kind": "user_service",
                    "unit_name": "dev.service", "expected_main_pid": row["pid"],
                    "expected_main_start_ticks": row["start_ticks"],
                    "expected_fragment_path": env["FAKE_UNIT_FRAGMENT"], "ports": []}
            result = invoke("service_stop", args, env=env)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            status = json.loads(result.stdout)
            self.assertTrue(marker.exists())
            self.assertFalse(status["verified_stopped"])
            self.assertEqual("active", status["service"]["active_state"])


class ServiceAdmissionTests(unittest.TestCase):
    def test_safe_argv_and_strict_argument_validation(self):
        display, rendered, args = command("service_processes",
                                           {"workspace_root": "/home/test/dev", "limit": 10})
        argv = shlex.split(rendered)
        self.assertEqual(["python3", "-c", REMOTE, "service_processes",
                          json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))], argv)
        self.assertIn("/home/test/dev", display)
        for invalid in ({"workspace_root": "/tmp/x", "limit": 1000},
                        {"workspace_root": "/a\nbad"},
                        {"workspace_root": "/a", "path": "/etc"},
                        {"workspace_root": "relative/path"}):
            with self.assertRaises(ValueError):
                command("service_processes", invalid)
        with self.assertRaises(ValueError):
            command("service_stop", {"workspace_root": "/home/test/dev", "target_kind": "process",
                                     "pid": 33, "expected_start_ticks": "1", "expected_pgid": 33,
                                     "expected_cwd": "/home/test/dev", "ports": [1, "2"]})

    def test_destructive_operation_always_waits_for_local_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            calls = []
            def runner(payload, emit, _stop):
                calls.append(payload)
                emit("stdout", b'{"ok":true,"signal_sent":true,"verified_stopped":true}')
                return RunResult(0)
            cfg = Config(Path(folder), 18765, 10, 3600, 16384, "ssh",
                         (Server("server", "Linux", "user@example.org", auto_categories=("diagnostics",)),),
                         auto_allow_readonly=True)
            manager = ApprovalManager(cfg, runner=runner)
            self.addCleanup(manager.close)
            manager.local_gui_heartbeat()
            args = {"workspace_root": "/home/test/dev", "target_kind": "process",
                    "pid": 100, "expected_start_ticks": "234", "expected_pgid": 100,
                    "expected_cwd": "/home/test/dev", "ports": [8701]}
            denied = manager.submit_service("server", "service_stop", args, "test denial", "stop-denied")
            self.assertEqual("pending_approval", denied["status"])
            self.assertFalse(denied["readonly_eligible"])
            self.assertEqual("service_stop_manual", denied["policy_category"])
            manager.reject(denied["request_id"])
            self.assertEqual("denied", manager.get(denied["request_id"])["status"])
            self.assertEqual([], calls)
            stop = manager.submit_service("server", "service_stop", args, "stop exact PID", "stop-once")
            retry = manager.submit_service("server", "service_stop", args, "stop exact PID", "stop-once")
            self.assertEqual(stop["request_id"], retry["request_id"])
            with self.assertRaises(ValueError):
                manager.submit_service("server", "service_stop", {**args,"pid":101}, "stop exact PID", "stop-once")
            manager.local_approve(stop["request_id"], stop["digest"])
            for _ in range(150):
                status = manager.get(stop["request_id"])
                if status["status"] != "running":
                    break
                time.sleep(.01)
            self.assertEqual("succeeded", status["status"], status)
            self.assertTrue(status["result"]["verified_stopped"])
            self.assertEqual(1, len(calls))
            self.assertEqual("service_stop", calls[0].operation)
            self.assertNotIn("stop-once", calls[0].executed_command)
