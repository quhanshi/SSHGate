"""Finite operation plans: admission, immutable review, fail-stop and cancellation."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ssh_gate.config import Config, Server
from ssh_gate.core import ApprovalManager
from ssh_gate.operation_plans import validate_plan
from ssh_gate.ssh import RunResult

ROOT = "/home/test/dq_dev"
CWD = ROOT + "/project"
TREE = ROOT + "/worktrees/agent-test"
STEPS = [
    {"kind": "check", "label": "Read current Git state", "command": "ls -lah", "timeout_seconds": 5},
    {"kind": "git_repair", "label": "Repair moved worktree", "paths": [TREE], "timeout_seconds": 10},
    {"kind": "verify", "label": "Check recovered directory", "command": "git rev-parse HEAD", "timeout_seconds": 5},
]


class PlanValidationTests(unittest.TestCase):
    def plan(self, steps=None):
        return validate_plan(ROOT, CWD, STEPS if steps is None else steps, 30)

    def test_frozen_commands_are_literal_and_bounded(self):
        steps, display, total = self.plan()
        self.assertEqual(20, total)
        self.assertEqual(["check", "git_repair", "verify"], [s["kind"] for s in steps])
        self.assertEqual("git worktree repair " + TREE, steps[1]["command"])
        self.assertIn("共 3 步", display)
        self.assertIn(TREE, display)
        self.assertNotIn("root password", display)

    def test_reject_shell_programs_paths_and_extra_fields(self):
        for candidate in (
            [{"kind": "check", "command": "sh -c ls"}, *STEPS[1:]],
            [{"kind": "check", "command": "ls; rm -rf /"}, *STEPS[1:]],
            [{"kind": "check", "command": "ls"}, {"kind": "git_repair", "paths": ["/etc/systemd"]}, STEPS[-1]],
            [{"kind": "check", "command": "ls"}, {"kind": "git_repair", "paths": ["/home/test/dq_dev2/x"]}, STEPS[-1]],
            [{"kind": "check", "command": "ls"}, {"kind": "git_repair", "paths": [TREE], "shell": "sudo sh"}, STEPS[-1]],
            [{"kind": "check", "command": "ls"}, {"kind": "git_repair", "paths": [TREE]}, {"kind": "stop", "command": "kill -9 1"}, STEPS[-1]],
            [{"kind": "check", "command": "ls"}, {"kind": "git_repair", "paths": [TREE]}, {"kind": "verify", "command": "git reset --hard"}],
            [{"kind": "check", "command": "ls"}, {"kind": "git_repair", "paths": [TREE]}, {"kind": "verify", "command": "ls", "timeout_seconds": 300}],
            [STEPS[1], STEPS[0], STEPS[2]],
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.plan(candidate)
        for root, cwd in (("/", CWD), ("/home/test/dq_dev2", CWD), (ROOT, "/tmp"), (ROOT+"/../secret", CWD)):
            with self.subTest(root=root,cwd=cwd), self.assertRaises(ValueError):
                validate_plan(root, cwd, STEPS, 360)


class PlanRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = Config(Path(self.tmp.name), 18765, 30, 3600, 8192, "ssh",
                     (Server("ssh", "Test SSH", "u@example.org", auto_categories=("git_read","read_fs"),
                             auto_roots=(ROOT,)),), auto_allow_readonly=True)
        self.calls = []
        self.fail_at = 0
        self.block_at = 0
        self.block = threading.Event()
        self.started = threading.Event()
        def runner(payload, emit, stop):
            self.calls.append(payload)
            idx = len(self.calls)
            self.started.set()
            if idx == self.block_at:
                while not self.block.wait(.01):
                    if stop.is_set():
                        return RunResult(None, disconnected=True,
                                         termination={"remote_group_terminated": True, "state": "stopped"})
            emit("stdout", ("step " + str(idx) + "\n").encode())
            return RunResult(2 if idx == self.fail_at else 0)
        self.manager = ApprovalManager(cfg, runner=runner)
        self.manager.local_gui_heartbeat()
        self.addCleanup(self.manager.close)

    def request(self, key="plan-1", steps=None):
        return self.manager.submit_plan("ssh", ROOT, CWD, steps or STEPS, "repair worktree", key, 30)

    def wait(self, rid):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            view=self.manager.get(rid)
            if view["status"] not in {"running", "queued_readonly", "queued_authorized"}:
                return view
            time.sleep(.01)
        self.fail("plan did not finish")

    def test_one_approval_exact_commands_and_results(self):
        proposed = self.request()
        self.assertEqual("pending_approval", proposed["status"])
        self.assertEqual("operation_plan_manual", proposed["policy_category"])
        self.assertFalse(proposed["readonly_eligible"])
        self.assertIn("git worktree repair", proposed["command"])
        self.assertFalse(self.calls)
        identical = self.request()
        self.assertEqual(proposed["request_id"], identical["request_id"])
        with self.assertRaises(ValueError):
            self.request(steps=[STEPS[0], {**STEPS[1],"paths":[CWD]}, STEPS[2]])
        self.manager.local_approve(proposed["request_id"], proposed["digest"])
        done=self.wait(proposed["request_id"])
        self.assertEqual("succeeded", done["status"], done)
        self.assertEqual(3, len(self.calls))
        self.assertEqual("git_manual", self.calls[1].policy_category)
        self.assertEqual("git worktree repair " + TREE, self.calls[1].command)
        self.assertEqual(3, done["result"]["completed_steps"])
        self.assertEqual(["succeeded"]*3, [x["status"] for x in done["result"]["steps"]])
        self.assertTrue(done["result"]["side_effects_possible"])
        self.assertNotIn("git worktree repair", self.manager.audit_path.read_text())

    def test_denied_and_expired_never_run(self):
        proposed=self.request()
        self.manager.reject(proposed["request_id"])
        with self.assertRaises(ValueError):
            self.manager.local_approve(proposed["request_id"], proposed["digest"])
        self.assertEqual([], self.calls)
        proposed=self.request("expired")
        self.manager._requests[proposed["request_id"]].expires_monotonic = self.manager.clock()-1
        with self.assertRaises(ValueError):
            self.manager.local_approve(proposed["request_id"], proposed["digest"])
        self.assertEqual("expired", self.manager.get(proposed["request_id"])["status"])
        self.assertEqual([], self.calls)

    def test_failure_on_precheck_never_mutates(self):
        self.fail_at=1
        p=self.request()
        self.manager.local_approve(p["request_id"], p["digest"])
        done=self.wait(p["request_id"])
        self.assertEqual("failed", done["status"])
        self.assertEqual(1, done["result"]["failed_step"])
        self.assertFalse(done["result"]["side_effects_possible"])
        self.assertEqual(1, len(self.calls))

    def test_failure_on_repair_prevents_verify_and_reports_side_effects(self):
        self.fail_at=2
        p=self.request()
        self.manager.local_approve(p["request_id"], p["digest"])
        done=self.wait(p["request_id"])
        self.assertEqual("failed", done["status"])
        self.assertEqual(2, done["result"]["failed_step"])
        self.assertTrue(done["result"]["side_effects_possible"])
        self.assertEqual(2, len(self.calls))

    def test_cancel_during_step_skips_remainder(self):
        self.block_at=2
        p=self.request()
        self.manager.local_approve(p["request_id"], p["digest"])
        self.assertTrue(self.started.wait(2))
        deadline=time.monotonic()+3
        while len(self.calls)<2 and time.monotonic()<deadline:
            time.sleep(.01)
        self.assertEqual(2,len(self.calls))
        self.manager.terminate(p["request_id"])
        done=self.wait(p["request_id"])
        self.assertEqual("terminated", done["status"])
        self.assertEqual(2, len(self.calls))
        self.assertTrue(done["result"]["side_effects_possible"])
        self.block.set()

    def test_digest_mismatch_never_executes(self):
        p=self.request()
        with self.assertRaises(ValueError):
            self.manager.local_approve(p["request_id"], "0"*64)
        self.assertEqual([], self.calls)
