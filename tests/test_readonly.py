from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ssh_gate.config import Server, load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.readonly import readonly_command
from ssh_gate.ssh import RunResult


class ReadOnlyParsingTests(unittest.TestCase):
    def test_common_readonly_commands(self):
        for command in ("ls", "ls -lah /tmp", "ll /tmp", "cat '/tmp/a b.txt'", "tail -n 50 /var/log/app.log",
                        "head -n 10 /tmp/file", "pwd", "wc -l /tmp/file", "grep -n error /tmp/file",
                        "/bin/cat /tmp/file", "/usr/bin/ls -a", "cat ~/file",
                        "git log -1 --oneline --decorate", "git show --stat HEAD",
                        "git rev-parse HEAD", "git rev-parse --show-toplevel", "git branch --show-current"):
            with self.subTest(command=command):
                self.assertTrue(readonly_command(command).allowed)

    def test_ll_uses_fixed_ls_binary(self):
        self.assertEqual("exec /usr/bin/ls -l /tmp", readonly_command("ll /tmp").executable_command)

    def test_literal_arguments_stay_quoted(self):
        command = readonly_command("cat '/tmp/a b.txt'")
        self.assertEqual("exec /usr/bin/cat '/tmp/a b.txt'", command.executable_command)

    def test_operators_and_shell_expansion_require_manual_approval(self):
        for command in ("ls; rm -rf /tmp/x", "ls && touch /tmp/x", "ls | sh", "cat a > b", "tail a >> b",
                        "cat < a", "cat $(touch /tmp/x)", "cat `whoami`", "ls\nrm /tmp/x", "ls &",
                        "ls /tmp/*.txt", "cat /proc/$PID/environ", "cat <(touch /tmp/x)", "ls || true",
                        "cat a 2>/tmp/x", "cat a;", "ls /tmp/{a,b}"):
            with self.subTest(command=command):
                self.assertFalse(readonly_command(command).allowed)

    def test_non_readonly_tools_and_alias_paths_are_manual(self):
        for command in ("rm file", "touch file", "sed -i s/a/b/ file", "awk 'BEGIN{system(\"touch x\")}'",
                        "find . -exec rm x +", "python script.py", "curl example.org", "sh -c ls", "sudo ls",
                        "env ls", "git reset --hard", "git rev-parse --verify HEAD", "git branch -a",
                        "/tmp/ls", "/bin/../bin/ls", "X=1 ls", "cat", "tail", "ls '"):
            with self.subTest(command=command):
                self.assertFalse(readonly_command(command).allowed)


class ReadOnlyAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = {"auto_allow_readonly": True,
                  "ssh_executable": shutil.which("ssh") or "",
                  "servers": [{"id": "server", "label": "Fixture", "ssh_target": "fixture@localhost"}]}
        (self.root / "config.json").write_text(json.dumps(config))
        self.calls = []
        self.release = threading.Event()
        def runner(payload, emit, stop):
            self.calls.append(payload.executed_command)
            while not self.release.wait(0.01):
                if stop.is_set():
                    return RunResult(None, disconnected=True)
            return RunResult(0)
        self.manager = ApprovalManager(load_config(self.root / "config.json"), runner=runner)
        self.addCleanup(self.manager.close)
        self.manager.local_gui_heartbeat()

    def submit(self, command="ls", key="id"):
        return self.manager.submit("server", command, "test", key)

    def wait(self, rid):
        deadline = time.monotonic() + 2
        while self.manager.get(rid)["status"] in {"running", "queued_readonly"} and time.monotonic() < deadline:
            time.sleep(0.01)
        return self.manager.get(rid)

    def test_safe_command_auto_executes_and_is_audited(self):
        view = self.submit("ll /tmp")
        self.assertEqual("auto_readonly", view["approval_kind"])
        self.release.set()
        done = self.wait(view["request_id"])
        self.assertEqual("succeeded", done["status"])
        self.assertEqual(["exec /usr/bin/ls -l /tmp"], self.calls)
        self.assertIn("auto_readonly_granted", self.manager.audit_path.read_text())

    def test_dangerous_combination_stays_pending(self):
        view = self.submit("ls; touch /tmp/x")
        self.assertEqual("pending_approval", view["status"])
        self.assertEqual("none", view["approval_kind"])
        self.assertFalse(self.calls)

    def test_switch_off_requires_manual_approval_and_persists(self):
        self.manager.local_set_readonly(False)
        view = self.submit("cat /tmp/test")
        self.assertEqual("pending_approval", view["status"])
        self.assertFalse(self.calls)
        self.assertFalse(load_config(self.root / "config.json").auto_allow_readonly)

    def test_queued_readonly_runs_after_current_command(self):
        first, second = self.submit("ls", "one"), self.submit("pwd", "two")
        self.assertEqual("queued_readonly", second["status"])
        self.release.set()
        self.assertEqual("succeeded", self.wait(first["request_id"])["status"])
        self.assertEqual("succeeded", self.wait(second["request_id"])["status"])
        self.assertEqual(2, len(self.calls))

    def test_switch_off_demotes_queued_requests(self):
        self.submit("ls", "one")
        second = self.submit("pwd", "two")
        self.manager.local_set_readonly(False)
        self.release.set()
        time.sleep(0.05)
        self.assertEqual("pending_approval", self.manager.get(second["request_id"])["status"])
        self.assertEqual(1, len(self.calls))

    def test_auto_retry_does_not_execute_twice(self):
        first = self.submit()
        self.release.set()
        self.wait(first["request_id"])
        retry = self.submit()
        self.assertEqual(first["request_id"], retry["request_id"])
        self.assertEqual(1, len(self.calls))

    def test_local_new_connection_persists_without_password(self):
        self.manager.local_add_server(Server("second", "Second", "other@example.org", "/tmp", 2222))
        saved = load_config(self.root / "config.json")
        self.assertEqual("other@example.org", saved.server("second").ssh_target)
        self.assertEqual(2222, saved.server("second").port)
        self.assertNotIn("password", (self.root / "config.json").read_text())
        with self.assertRaises(ValueError):
            self.manager.local_add_server(Server("second", "Duplicate", "x"))

    def test_auto_admission_audit_failure_prevents_execution(self):
        audit = self.manager._audit
        def unavailable(event, request):
            if event == "auto_readonly_granted":
                raise OSError("fixture audit unavailable")
            return audit(event, request)
        self.manager._audit = unavailable
        with self.assertRaises(OSError):
            self.submit()
        self.manager.local_gui_heartbeat()
        view = self.manager.list_local()[0]
        self.assertEqual("queued_readonly", view["status"])
        self.assertEqual("none", view["approval_kind"])
        self.assertFalse(self.calls)

    def test_switch_on_leaves_existing_manual_request_pending(self):
        self.manager.local_set_readonly(False)
        view = self.submit()
        self.manager.local_set_readonly(True)
        self.assertEqual("pending_approval", self.manager.get(view["request_id"])["status"])
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
