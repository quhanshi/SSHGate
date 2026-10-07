from __future__ import annotations

import shlex
import unittest

from ssh_gate.deployment import build_bootstrap_command


class DeploymentBuilderTests(unittest.TestCase):
    def test_github_bootstrap_is_structured_and_reviewable(self):
        view = build_bootstrap_command(
            "git@github.com:quhanshi/DQ.git", "/home/quhanshi/dq_project_new",
            "main", "a" * 40)
        self.assertEqual("github", view["provider"])
        self.assertEqual("a" * 40, view["expected_sha"])
        argv = shlex.split(view["command"])
        self.assertEqual(["/bin/sh", "-ceu"], argv[:2])
        script = argv[2]
        self.assertIn("target directory is not empty", script)
        self.assertIn("clone --progress --branch main --single-branch", script)
        self.assertIn("checkout --detach " + "a" * 40, script)
        self.assertIn("SSH_GATE_DEPLOY_HEAD", script)
        self.assertIn("core.hooksPath=/dev/null", script)

    def test_non_github_or_ambiguous_targets_are_rejected(self):
        bad = [
            ("https://gitee.com/o/r.git", "/srv/repo"),
            ("https://token@github.com/o/r.git", "/srv/repo"),
            ("https://github.com/o/r.git?x=1", "/srv/repo"),
            ("https://github.com/o/r.git", "/"),
            ("https://github.com/o/r.git", "/srv/../tmp/repo"),
        ]
        for url, path in bad:
            with self.subTest(url=url, path=path), self.assertRaises(ValueError):
                build_bootstrap_command(url, path)

    def test_branch_and_sha_are_bounded(self):
        with self.assertRaises(ValueError):
            build_bootstrap_command("https://github.com/o/r.git", "/srv/repo", "../main")
        with self.assertRaises(ValueError):
            build_bootstrap_command("https://github.com/o/r.git", "/srv/repo", expected_sha="abc")


if __name__ == "__main__":
    unittest.main()
