from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ssh_gate.config import Config, Server, load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.ssh import RunResult, SSHRunner, build_remote_command


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = Config(self.root, 18765, 10, 3600, 4096, shutil.which("ssh") or "ssh.exe",
                             (Server("server", "Test Server", "user@example.org"),))
        self.calls = []
        self.started = threading.Event()
        self.release = threading.Event()
        def runner(payload, emit, stop):
            self.calls.append(payload)
            self.started.set()
            while not self.release.wait(0.01):
                if stop.is_set():
                    return RunResult(None, disconnected=True)
            emit("stdout", "完成\n".encode())
            emit("stderr", b"test warning")
            return RunResult(0)
        self.manager = ApprovalManager(self.config, runner=runner)
        self.manager.local_gui_heartbeat()
        self.addCleanup(self.manager.close)

    def submit(self, key="r1", command="pwd", **kwargs):
        return self.manager.submit("server", command, "Test connection", key, **kwargs)

    def approve(self, view):
        self.manager.local_approve(view["request_id"], view["digest"])

    def finish(self, view):
        self.release.set()
        deadline = time.monotonic() + 3
        while self.manager.get(view["request_id"])["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.01)
        return self.manager.get(view["request_id"])

    def test_submission_and_polling_never_execute(self):
        view = self.submit()
        self.assertEqual("pending_approval", view["status"])
        for _ in range(3):
            self.manager.get(view["request_id"])
        self.assertEqual([], self.calls)

    def test_local_approval_executes_exactly_once(self):
        view = self.submit(command="printf '%s\\n' 'approved only'")
        self.approve(view)
        self.assertTrue(self.started.wait(1))
        with self.assertRaises(ValueError):
            self.approve(view)
        done = self.finish(view)
        self.assertEqual("succeeded", done["status"])
        self.assertEqual("完成\n", done["stdout"])
        self.assertEqual(1, len(self.calls))
        self.assertEqual(view["command"], self.calls[0].command)

    def test_denied_request_cannot_execute_or_be_reapproved(self):
        view = self.submit()
        self.manager.reject(view["request_id"])
        with self.assertRaises(ValueError):
            self.approve(view)
        self.assertEqual("denied", self.manager.get(view["request_id"])["status"])
        self.assertFalse(self.calls)

    def test_expiry_is_checked_at_approval(self):
        clock = [0.0]
        manager = ApprovalManager(self.config, runner=lambda *args: self.fail("must not execute"),
                                  clock=lambda: clock[0])
        manager.local_gui_heartbeat()
        view = manager.submit("server", "pwd", "test", "expiry")
        clock[0] = 10
        with self.assertRaises(ValueError):
            manager.local_approve(view["request_id"], view["digest"])
        self.assertEqual("expired", manager.get(view["request_id"])["status"])
        manager.close()

    def test_no_gui_and_unresponsive_gui_fail_closed(self):
        clock = [100.0]
        manager = ApprovalManager(self.config, clock=lambda: clock[0])
        with self.assertRaises(ValueError):
            manager.submit("server", "pwd", "test", "no-gui")
        manager.local_gui_heartbeat()
        clock[0] += 6
        with self.assertRaises(ValueError):
            manager.submit("server", "pwd", "test", "stale-gui")
        self.assertEqual([], manager.list_local())
        manager.close()

    def test_digest_mismatch_never_executes(self):
        view = self.submit()
        with self.assertRaises(ValueError):
            self.manager.local_approve(view["request_id"], "0" * 64)
        self.assertFalse(self.calls)
        self.assertEqual("pending_approval", self.manager.get(view["request_id"])["status"])

    def test_retry_idempotency_and_parameter_replacement(self):
        view = self.submit()
        self.assertEqual(view["request_id"], self.submit()["request_id"])
        with self.assertRaises(ValueError):
            self.submit(command="ls")
        with self.assertRaises(ValueError):
            self.submit(timeout_seconds=10)
        self.approve(view)
        self.finish(view)
        self.assertEqual(view["request_id"], self.submit()["request_id"])
        self.assertEqual(1, len(self.calls))

    def test_concurrent_retries_share_one_request(self):
        views = []
        errors = []
        def submit():
            try:
                views.append(self.submit())
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=submit) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(errors)
        self.assertEqual(1, len({v["request_id"] for v in views}))
        self.assertFalse(self.calls)

    def test_concurrent_approvals_admit_only_one_execution(self):
        view = self.submit()
        wins = []
        def approve():
            try:
                self.approve(view)
                wins.append(True)
            except ValueError:
                pass
        threads = [threading.Thread(target=approve) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([True], wins)
        self.finish(view)
        self.assertEqual(1, len(self.calls))

    def test_approve_second_request_requires_first_to_finish(self):
        first, second = self.submit(), self.submit("r2", "ls")
        self.approve(first)
        with self.assertRaises(ValueError):
            self.approve(second)
        self.assertEqual("pending_approval", self.manager.get(second["request_id"])["status"])
        self.finish(first)
        self.approve(second)
        self.finish(second)
        self.assertEqual(2, len(self.calls))

    def test_audit_failure_prevents_execution(self):
        view = self.submit()
        audit = self.manager.audit_path
        audit.unlink()
        audit.mkdir()
        with self.assertRaises(OSError):
            self.approve(view)
        self.assertFalse(self.calls)
        self.assertEqual("pending_approval", self.manager.get(view["request_id"])["status"])

    def test_close_denies_pending_and_blocks_new_requests(self):
        view = self.submit()
        self.manager.close()
        with self.assertRaises(ValueError):
            self.approve(view)
        with self.assertRaises(ValueError):
            self.submit("r2")
        self.assertEqual("denied", self.manager.get(view["request_id"])["status"])
        self.assertFalse(self.calls)

    def test_restart_does_not_restore_pending_or_approved_requests(self):
        view = self.submit()
        new = ApprovalManager(self.config)
        with self.assertRaises(ValueError):
            new.get(view["request_id"])
        self.assertFalse(new.list_local())
        new.close()

    def test_output_cap_and_paging(self):
        def runner(_payload, emit, _stop):
            emit("stdout", b"A" * 5000)
            emit("stderr", b"B" * 5000)
            return RunResult(0)
        self.manager.runner = runner
        view = self.submit()
        self.approve(view)
        done = self.finish(view)
        self.assertTrue(done["output_truncated"])
        self.assertEqual(4096, done["stdout_length"] + done["stderr_length"])
        page = self.manager.get(view["request_id"], 0, 10)
        self.assertEqual("A" * 10, page["stdout"])
        self.assertTrue(page["has_more_output"])
        self.assertEqual(10, page["next_output_offset"])

    def test_audit_does_not_contain_script_or_output(self):
        view = self.submit(command="echo SECRET_COMMAND_LITERAL")
        self.approve(view)
        self.finish(view)
        audit = self.manager.audit_path.read_text()
        self.assertNotIn("SECRET_COMMAND_LITERAL", audit)
        self.assertNotIn("完成", audit)
        events = [json.loads(line)["event"] for line in audit.splitlines()]
        self.assertEqual(["submitted", "approval_granted", "finished"], events)

    def test_hidden_characters_and_invalid_parameters_are_rejected(self):
        for command in ("pwd\x00", "ls\u202erm -rf /", "ls\x1b[0m"):
            with self.assertRaises(ValueError):
                self.submit(command=command)
        for timeout in (0, 3601, True):
            with self.assertRaises(ValueError):
                self.submit(timeout_seconds=timeout)
        with self.assertRaises(ValueError):
            self.submit(cwd="relative/path")
        with self.assertRaises(ValueError):
            self.manager.submit("unknown", "pwd", "test", "id")
        self.assertFalse(self.calls)

    def test_queue_limit_does_not_execute_or_silently_drop(self):
        for i in range(20):
            self.submit(str(i))
        with self.assertRaises(ValueError):
            self.submit("overflow")
        self.assertEqual(20, len(self.manager.list_local()))
        self.assertFalse(self.calls)

    def test_manual_shell_script_is_preserved_and_connection_is_resolved(self):
        view = self.submit(command="echo `hostname`; printf '%s' '$HOME'")
        self.assertEqual("example.org", view["ssh_settings"]["hostname"])
        self.assertEqual("user", view["ssh_settings"]["username"])
        self.assertEqual(view["command"], view["executed_command"])
        self.assertFalse(view["readonly_eligible"])

    @unittest.skipUnless(shutil.which("sh") and shutil.which("timeout"), "Linux wrapper validation")
    def test_shell_quoting_preserves_literal_working_directory(self):
        tricky = self.root / "dir ' $(touch INJECTED) ; [test]"
        tricky.mkdir()
        command = build_remote_command("printf '%s\\n' 'literal $HOME'; pwd", str(tricky), 5)
        result = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=8)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["literal $HOME", str(tricky)], result.stdout.splitlines())
        self.assertFalse((self.root / "INJECTED").exists())

    @unittest.skipUnless(shutil.which("sh") and shutil.which("timeout"), "Linux timeout validation")
    def test_remote_wrapper_timeout_terminates_foreground_command(self):
        wrapper = build_remote_command("sleep 10", str(self.root), 1)
        before = time.monotonic()
        result = subprocess.run(["sh", "-c", wrapper], capture_output=True, timeout=8)
        self.assertEqual(124, result.returncode)
        self.assertLess(time.monotonic() - before, 6)

    def test_config_rejects_target_option_injection(self):
        path = self.root / "config.json"
        base = {"ssh_executable": self.config.ssh_executable,
                "servers": [{"id": "server", "ssh_target": "-oProxyCommand=evil"}]}
        path.write_text(json.dumps(base))
        with self.assertRaises(ValueError):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
