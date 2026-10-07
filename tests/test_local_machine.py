from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ssh_gate.authorizations import check_pattern, pattern_matches, ps_literal_argv, ps_render
from ssh_gate.config import load_config
from ssh_gate.core import ApprovalManager
from ssh_gate.git_policy import git_args_command
from ssh_gate.local_terminal import find_shell
from ssh_gate.ssh import RunResult
from ssh_gate.winpath import windows_path, within

WINDOWS = os.name == "nt"


class WindowsPathTests(unittest.TestCase):
    def test_paths_are_absolute_normalized_and_unambiguous(self):
        self.assertEqual("D:\\work\\app", windows_path("D:/work/./x/../app"))
        self.assertEqual("D:\\work\\src", windows_path("src", "D:\\work"))
        for value in ["work", "\\work", "D:work", "\\\\?\\C:\\x", "\\\\.\\pipe\\x", "D:\\work\\CON", "D:\\work\\nul.txt",
                      "D:\\work\\a:stream", "D:\\work\\trail.", "D:\\work\\trail ", "D:\\work\\a\u202eb", "1:\\x"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                windows_path(value)

    def test_containment_is_case_insensitive_and_drive_aware(self):
        self.assertTrue(within("D:\\Work\\App\\src", ["d:\\work\\app"]))
        self.assertFalse(within("D:\\Work\\Application", ["D:\\Work\\App"]))
        self.assertFalse(within("E:\\Work\\App", ["D:\\Work\\App"]))


class PowerShellPatternTests(unittest.TestCase):
    def matches(self, pattern, line):
        check_pattern(pattern, "powershell")
        return pattern_matches(pattern, ps_literal_argv(line), "powershell")

    def test_literal_lines_only(self):
        for line in ["npm run a; calc", "npm run $env:X", "npm run $(calc)", "npm run a | Out-File x", "npm run a > x",
                     "npm run {a}", "npm run @args", 'npm run "a"', "npm run a#x", "npm run `a", "npm run a,b",
                     "npm run %PATH%", "npm run a^b", "npm run --% x", "npm run a&b", "npm run it''s", ".\\x.ps1 a",
                     "npm run [a]", "npm run ‘a’"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                ps_literal_argv(line)
        self.assertEqual(["Write-Output", "a b", "it's"], ps_literal_argv("Write-Output 'a b' 'it''s'"))
        self.assertEqual("& 'npm' 'run' 'build' -Verbose", ps_render(["npm", "run", "build", "-Verbose"]))

    def test_wildcards_stay_relative_and_names_are_case_insensitive(self):
        self.assertTrue(self.matches("npm run *", "NPM run build"))
        self.assertTrue(self.matches("dotnet test ...", "dotnet test"))
        self.assertTrue(self.matches("Get-ChildItem -Path src\\**", "get-childitem -Path src\\app\\x.cs"))
        for pattern, line in [("npm run *", "npm run C:\\x"), ("npm run *", "npm run \\\\srv\\share"), ("npm run *", "npm run -x"),
                              ("npm run *", "npm run /flag"), ("npm run *", "npm run ..\\x"), ("npm run *", "npm run ~"),
                              ("npm run *", "npm run env:PATH"), ("Get-ChildItem -Path src\\**", "Get-ChildItem -Path src\\*"),
                              ("dotnet test ...", "dotnet test C:\\other"), ("npm run *", "npm run a b"),
                              ("npm run *", "npm.cmd run build")]:
            with self.subTest(line=line):
                self.assertFalse(self.matches(pattern, line))

    def test_programs_that_run_other_code_are_refused(self):
        for pattern in ["Invoke-Expression *", "iex *", "Start-Process *", "pwsh *", "powershell.exe *", "cmd /c *",
                        "Remove-Item *", "del *", "Set-Alias *", "New-Item *", "ForEach-Object *", "git *", "git.exe *",
                        "C:\\Windows\\System32\\cmd.exe *", "npx *", "* run", "Get-ChildItem -*", "Get-ChildItem /*",
                        "regsvr32 *", "python -c *"]:
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                check_pattern(pattern, "powershell")


class GitArgumentTests(unittest.TestCase):
    def test_structured_git_arguments_render_one_literal_command(self):
        self.assertEqual("git status --short", git_args_command(["status", "--short"]))
        self.assertEqual("git commit -m 'fix(ui): a; b'", git_args_command(["commit", "-m", "fix(ui): a; b"]))
        for args in [[], ["-C", "/x", "status"], ["--git-dir=/x", "status"], ["-c", "a=b", "status"], ["Status"],
                     ["status", ""], ["status", "a\nb"], "status", [1]]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                git_args_command(args)


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "work"
        (self.workspace / "src").mkdir(parents=True)
        (self.workspace / "src" / "a.txt").write_text("inside", encoding="utf-8")
        (self.root / "outside").mkdir()
        (self.root / "outside" / "secret.txt").write_text("outside", encoding="utf-8")
        (self.root / "config.json").write_text(json.dumps({"auto_allow_readonly": True, "servers": [
            {"id": "pc", "label": "PC", "kind": "local", "workspace_roots": [str(self.workspace)], "auto_categories": ["read_fs"]},
            {"id": "s", "label": "S", "ssh_target": "u@host.example", "default_cwd": "/srv/project"}]}), encoding="utf-8")
        self.ssh_calls = []
        def runner(payload, emit, stop):
            self.ssh_calls.append(payload)
            return RunResult(0)
        self.manager = ApprovalManager(load_config(self.root / "config.json"), runner=runner)
        self.addCleanup(self.manager.close)
        self.manager.local_gui_heartbeat()

    def wait(self, request_id):
        deadline = time.monotonic() + 30
        while self.manager.get(request_id)["status"] in {"running", "queued_readonly", "queued_authorized"} and time.monotonic() < deadline:
            time.sleep(.02)
        return self.manager.get(request_id)

    def approve(self, view):
        self.manager.local_approve(view["request_id"], self.manager.get(view["request_id"])["digest"])
        return self.wait(view["request_id"])


class GitRoutingTests(Base):
    def test_git_command_tool_and_local_refusal(self):
        view = self.manager.request_git_command("s", ["status", "--short"], "check", "git-1")
        self.assertEqual("git status --short", view["command"])
        self.assertEqual("queued_readonly", view["status"]) if not self.ssh_calls else None
        with self.assertRaises(ValueError):
            self.manager.request_git_command("pc", ["status"], "check", "git-local")
        with self.assertRaises(ValueError):
            self.manager.request_git_command("s", ["-C", "/etc", "status"], "check", "git-2")


@unittest.skipUnless(WINDOWS, "Windows workspace and job objects")
class LocalWorkspaceTests(Base):
    def test_file_tools_stay_inside_the_workspace(self):
        listing = self.wait(self.manager.submit_operation("pc", "list_directory", {"path": str(self.workspace)}, "list", "ls")["request_id"])
        self.assertEqual("succeeded", listing["status"])
        self.assertEqual(["src"], [e["name"] for e in listing["result"]["entries"]])
        read = self.wait(self.manager.submit_operation("pc", "read_file", {"path": str(self.workspace / "src" / "a.txt")}, "read", "rd")["request_id"])
        self.assertEqual("inside", read["result"]["text"])
        with self.assertRaises(ValueError):
            self.manager.submit_operation("pc", "read_file", {"path": str(self.root / "outside" / "secret.txt")}, "read", "out")
        link = self.workspace / "escape"
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(self.root / "outside")], capture_output=True)
        if made.returncode == 0:
            escaped = self.wait(self.manager.submit_operation("pc", "read_file", {"path": str(link / "secret.txt")}, "read", "junction")["request_id"])
            self.assertEqual("failed", escaped["status"])
            self.assertIn("工作区以外", escaped["error"])

    def test_commands_need_approval_unless_a_powershell_pattern_grant_matches(self):
        if not find_shell():
            self.skipTest("PowerShell not available")
        manual = self.manager.submit("pc", "Write-Output manual", "manual", "manual", str(self.workspace))
        self.assertEqual("pending_approval", manual["status"])
        self.assertEqual("succeeded", self.approve(manual)["status"])
        proposal = self.manager.request_pattern_approval("pc", str(self.workspace), ["Write-Output pattern-*"], "echo", "grant")
        self.assertEqual("pending_approval", proposal["status"])
        self.assertIn("PowerShell", proposal["authorization"] or self.manager.get(proposal["request_id"])["command"])
        self.manager.local_approve(proposal["request_id"], self.manager.get(proposal["request_id"])["digest"])
        grant = self.manager.get_auto_approval_status(proposal["request_id"])["authorization"]["grant_id"]
        view = self.manager.submit("pc", "Write-Output pattern-ok", "auto", "auto", str(self.workspace / "src"), grant_id=grant)
        self.assertEqual("queued_authorized", view["status"]) if view["status"] != "running" else None
        done = self.wait(view["request_id"])
        self.assertEqual("succeeded", done["status"])
        self.assertEqual("temporary_grant", done["approval_kind"])
        self.assertEqual("pattern-ok", done["stdout"].strip())
        self.assertIn("& 'Write-Output' 'pattern-ok'", done["executed_command"])
        for line, cwd in [("Write-Output other", self.workspace), ("Write-Output pattern-x; calc", self.workspace),
                          ("Write-Output pattern-ok", self.root / "outside")]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.manager.submit("pc", line, "bad", "bad-" + str(abs(hash((line, str(cwd))))), str(cwd), grant_id=grant)
        with self.assertRaises(ValueError):
            self.manager.request_pattern_approval("pc", str(self.root / "outside"), ["Write-Output *"], "outside", "grant-out")
        with self.assertRaises(ValueError):
            self.manager.request_auto_approval("pc", str(self.workspace), ["read_fs"], "reads", "grant-read")
        with self.assertRaises(ValueError):
            self.manager.request_pattern_approval("pc", str(self.workspace), ["git *"], "git", "grant-git")


if __name__ == "__main__":
    unittest.main()
