from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ssh_gate.config import load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.ssh import RunResult


class LowFrictionApprovalIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "config.json"
        self.path.write_text(json.dumps({
            "auto_allow_readonly": False,
            "approval_mode": "dangerous_only",
            "servers": [{"id": "test", "ssh_target": "test.example",
                         "default_cwd": "/srv/project"}],
        }), encoding="utf-8")
        self.calls = []
        def runner(payload, emit, stop):
            self.calls.append(payload.command)
            return RunResult(0)
        self.manager = ApprovalManager(load_config(self.path), runner=runner)
        self.manager.local_gui_heartbeat()
        self.addCleanup(self.manager.close)

    def submit(self, command, key):
        return self.manager.submit("test", command, "regression test", key)

    def done(self, view):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = self.manager.get(view["request_id"])
            if current["status"] not in {"running", "queued_readonly"}:
                return current
            time.sleep(0.01)
        self.fail("Request did not complete")

    def test_opt_in_allows_normal_mutations_even_with_readonly_disabled(self):
        view = self.submit("mkdir -p .cache && touch .cache/check", "normal")
        self.assertEqual("succeeded", self.done(view)["status"])
        self.assertEqual(["mkdir -p .cache && touch .cache/check"], self.calls)
        self.assertEqual("auto_high_risk_screen", self.manager.get(view["request_id"])["approval_kind"])

    def test_destructive_commands_still_require_local_confirmation(self):
        for key, command in enumerate(("rm -rf /", "sudo reboot", "sh -c 'reboot'", "echo x > /etc/passwd")):
            view = self.submit(command, "danger-%s" % key)
            self.assertEqual("pending_approval", view["status"])
        self.assertFalse(self.calls)

    def test_switching_off_revokes_automatic_admission_of_new_requests(self):
        first = self.submit("touch ordinary", "first")
        self.done(first)
        self.manager.local_save_settings({"approval_mode": "standard"})
        second = self.submit("touch ordinary", "second")
        self.assertEqual("pending_approval", second["status"])
        self.assertEqual(["touch ordinary"], self.calls)

    def test_invalid_mode_is_rejected_by_config_validator(self):
        self.path.write_text(json.dumps({
            "approval_mode": "never_approve",
            "servers": [{"id": "test", "ssh_target": "test.example"}],
        }), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(self.path)
