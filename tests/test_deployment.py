from __future__ import annotations

import shlex
import unittest

from ssh_gate.deployment import build_bootstrap_command


class DeploymentBuilderTests(unittest.TestCase):
    def test_github_ssh_bootstrap_checks_effective_hostname_and_sha(self):
        view = build_bootstrap_command(
            "git@github.com:quhanshi/DQ.git", "/home/quhanshi/dq_project_new",
            "main", "a" * 40)
        self.assertEqual("github", view["provider"])
        script = shlex.split(view["command"])[2]
        self.assertIn("/usr/bin/ssh -G github.com", script)
        self.assertIn("target directory is not empty", script)
        self.assertIn("clone --progress --branch main --single-branch", script)
        self.assertIn("checkout --detach " + "a" * 40, script)
        self.assertIn("SSH_GATE_DEPLOY_HEAD", script)
        self.assertIn("core.hooksPath=/dev/null", script)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", script)

    def test_https_bootstrap_does_not_need_ssh_resolution(self):
        script = shlex.split(build_bootstrap_command(
            "https://github.com/o/r.git", "/srv/repo")["command"])[2]
        self.assertNotIn("/usr/bin/ssh -G", script)

    def test_invalid_urls_targets_branch_and_sha_are_rejected(self):
        bad = [
            ("https://gitee.com/o/r.git", "/srv/repo"),
            ("https://token@github.com/o/r.git", "/srv/repo"),
            ("https://github.com/o/r.git?x=1", "/srv/repo"),
            ("http://github.com/o/r.git", "/srv/repo"),
            ("git://github.com/o/r.git", "/srv/repo"),
            ("https://github.com/o/r.git", "/"),
            ("https://github.com/o/r.git", "/srv/../tmp/repo"),
        ]
        for url, path in bad:
            with self.subTest(url=url, path=path), self.assertRaises(ValueError):
                build_bootstrap_command(url, path)
        with self.assertRaises(ValueError):
            build_bootstrap_command("https://github.com/o/r.git", "/srv/repo", "../main")
        with self.assertRaises(ValueError):
            build_bootstrap_command("https://github.com/o/r.git", "/srv/repo", expected_sha="abc")


if __name__ == "__main__":
    unittest.main()
