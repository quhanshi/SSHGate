from __future__ import annotations

import os
import re
import tempfile
import time
import unittest
from pathlib import Path

from fixture_desktop import FixturePty, make_fixture
from ssh_gate import local_terminal
from ssh_gate.local_terminal import LocalTerminals, Shell, find_shell, shell_environment


def read_until(terminals, session_id, needle, timeout=10):
    text, offset, deadline = "", 0, time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = terminals.read(session_id, offset)
        text, offset = text + chunk["data"], chunk["next"]
        if needle in re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07", "", text) or not chunk["running"]:
            return text, chunk
    return text, chunk


class LocalTerminalTests(unittest.TestCase):
    def setUp(self):
        self.spawned = []
        def spawn(_shell, cols, rows):
            pty = FixturePty(cols, rows)
            self.spawned.append(pty)
            return pty
        self.terminals = LocalTerminals(Shell("fixture.exe", "PowerShell (pwsh)"), spawn=spawn)
        self.addCleanup(self.terminals.close_all)

    def test_echo_resize_and_exit_are_reported(self):
        session = self.terminals.open(100, 30)["id"]
        self.terminals.write(session, "echo hello\r")
        text, _ = read_until(self.terminals, session, "hello\r\n")
        self.assertIn("hello", text)
        self.terminals.resize(session, 120, 40)
        self.assertEqual(self.spawned[0].size, (120, 40))
        self.terminals.write(session, "exit\r")
        _, chunk = read_until(self.terminals, session, "never")
        self.assertFalse(chunk["running"])
        self.assertEqual(chunk["exit_code"], 0)
        with self.assertRaises(ValueError):
            self.terminals.write(session, "echo late\r")

    def test_input_dimensions_and_offsets_are_validated(self):
        session = self.terminals.open(80, 24)["id"]
        for cols, rows in [(1, 24), (80, 0), (501, 24), ("80", 24), (80.0, 24)]:
            with self.assertRaises(ValueError):
                self.terminals.open(cols, rows)
        for data in ["", None, "x" * (local_terminal.WRITE_CHARS + 1), b"bytes"]:
            with self.assertRaises(ValueError):
                self.terminals.write(session, data)
        for offset in [-1, "0", 1.5]:
            with self.assertRaises(ValueError):
                self.terminals.read(session, offset)
        for unknown in ["missing", None, 3]:
            with self.assertRaises(ValueError):
                self.terminals.write(unknown, "x")

    def test_session_limit_reuses_exited_slots(self):
        sessions = [self.terminals.open(80, 24)["id"] for _ in range(local_terminal.MAX_SESSIONS)]
        with self.assertRaises(ValueError):
            self.terminals.open(80, 24)
        self.terminals.write(sessions[0], "exit\r")
        read_until(self.terminals, sessions[0], "never")
        self.terminals.open(80, 24)
        with self.assertRaises(ValueError):
            self.terminals.read(sessions[0], 0)

    def test_buffer_is_bounded_and_reports_skipped_output(self):
        session = self.terminals.open(80, 24)["id"]
        pty = self.spawned[0]
        block = "x" * 65536
        for _ in range(local_terminal.BUFFER_CHARS // len(block) + 4):
            pty._out.append(block)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.terminals._sessions[session]._end < local_terminal.BUFFER_CHARS + 3 * len(block):
            time.sleep(.02)
        chunk = self.terminals.read(session, 0)
        self.assertGreater(chunk["skipped"], 0)
        self.assertLessEqual(len(chunk["data"]), local_terminal.READ_CHARS)
        self.assertTrue(chunk["more"])

    def test_close_all_stops_sessions_and_refuses_new_ones(self):
        session = self.terminals.open(80, 24)["id"]
        self.terminals.close_all()
        with self.assertRaises(ValueError):
            self.terminals.read(session, 0)
        with self.assertRaises(ValueError):
            self.terminals.open(80, 24)

    def test_unavailable_shell_explains_itself(self):
        terminals = LocalTerminals(None)
        self.assertFalse(terminals.info()["available"])
        with self.assertRaises(ValueError):
            terminals.open(80, 24)

    def test_shell_environment_drops_launcher_state(self):
        venv = os.path.join("C:\\", "app", ".venv")
        env = {"Path": os.pathsep.join([os.path.join(venv, "Scripts"), "C:\\Windows"]), "VIRTUAL_ENV": venv,
               "PYTHONHOME": "C:\\uv\\python", "UV_RUN_RECURSION_DEPTH": "1", "_PYI_APPLICATION_HOME_DIR": "x", "HOME": "C:\\Users\\me"}
        clean = shell_environment(env)
        self.assertEqual(clean["Path"], "C:\\Windows")
        self.assertEqual(set(clean), {"Path", "HOME"})


class DesktopTerminalBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.api, self.manager, *_ = make_fixture(Path(self.temp.name))
        self.token = self.api._token
        self.addCleanup(self.api._close)

    def test_bridge_requires_capability_and_never_creates_requests_or_audit(self):
        for method, args in [(self.api.terminal_info, ()), (self.api.terminal_open, (80, 24)), (self.api.terminal_read, ("x", 0)),
                             (self.api.terminal_write, ("x", "ls\r")), (self.api.window_action, ("close",))]:
            self.assertFalse(method("wrong-capability", *args)["ok"])
        session = self.api.terminal_open(self.token, 80, 24)["data"]["id"]
        self.assertTrue(self.api.terminal_write(self.token, session, "echo private-local-text\r")["ok"])
        text, offset, deadline = "", 0, time.monotonic() + 5
        while "private-local-text\r\n" not in text and time.monotonic() < deadline:
            chunk = self.api.terminal_read(self.token, session, offset)["data"]
            text, offset = text + chunk["data"], chunk["next"]
        self.assertIn("private-local-text", text)
        self.assertEqual(self.manager.list_summaries(), [])
        audit = self.manager.audit_path
        self.assertFalse(audit.exists() and "private-local-text" in audit.read_text(encoding="utf-8"))
        self.assertNotIn("private-local-text", str(self.api.snapshot(self.token)["data"]))

    def test_window_actions_are_allowlisted(self):
        self.assertTrue(self.api.window_state(self.token)["data"]["custom_frame"])
        self.assertTrue(self.api.window_action(self.token, "maximize")["data"]["maximized"])
        self.assertFalse(self.api.window_action(self.token, "move")["ok"])

    def test_app_close_ends_terminals(self):
        session = self.api.terminal_open(self.token, 80, 24)["data"]["id"]
        self.api._close()
        self.assertFalse(self.api._terminals._sessions)
        self.assertFalse(self.api.terminal_read(self.token, session, 0)["ok"])


@unittest.skipUnless(os.name == "nt" and find_shell(), "needs Windows PowerShell")
class RealPowerShellTests(unittest.TestCase):
    def test_powershell_runs_unicode_reports_exit_and_closes(self):
        terminals = LocalTerminals.for_platform()
        self.addCleanup(terminals.close_all)
        session = terminals.open(100, 30)["id"]
        terminals.write(session, "Write-Output ('mark-' + (6*7) + '-中文')\r")
        text, chunk = read_until(terminals, session, "mark-42-中文", timeout=30)
        self.assertTrue(chunk["running"], text[-400:])
        self.assertIn("mark-42-中文", re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text))
        terminals.write(session, "exit 7\r")
        _, chunk = read_until(terminals, session, "never", timeout=15)
        self.assertFalse(chunk["running"])
        self.assertEqual(chunk["exit_code"], 7)


if __name__ == "__main__":
    unittest.main()
