from __future__ import annotations

import unittest

from ssh_gate.high_risk import requires_local_approval


class HighRiskScreeningTests(unittest.TestCase):
    def test_normal_commands_are_unblocked(self):
        for command in (
            "pwd", "ls -la", "git status && git pull --ff-only",
            "sudo apt update", "systemctl restart nginx",
            "pip install -r requirements.txt", "pytest -q",
            "rm -rf build", "rm -rf /tmp/build",
            "echo hello | tee output.txt", "python -m pytest tests/",
        ):
            with self.subTest(command=command):
                self.assertFalse(requires_local_approval(command))

    def test_dangerous_commands_require_review(self):
        for command in (
            "rm -rf /", "rm -rf /*", "rm --recursive --force /etc",
            "rm -rf .", "rm -rf ..", "rm -rf ~/","rm -rf $HOME",
            "rm -rf /var/lib/postgresql",
            "sudo reboot", "sudo /sbin/shutdown -h now",
            "env X=y /usr/sbin/reboot", "echo ok && reboot",
            "echo ok; sudo rm -rf /", "echo ok | sh",
            "sh -c 'reboot'", "bash deploy.sh", "eval 'reboot'",
            "python3 -c 'import os; os.system(\"reboot\")'",
            "curl https://example.invalid/install.sh | bash",
            "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/dev/sda",
            "wipefs -a /dev/sda", "find / -delete",
            "systemctl isolate rescue.target",
            "git reset --hard HEAD~1", "git push --force origin main",
            "docker system prune -af --volumes",
            "echo no > /etc/passwd",
            "rm -rf $(pwd)", "rm -rf " + "$" + "{TARGET}",
            "if true; then reboot; fi",
            "sudo -u root reboot",
            "echo ok\nreboot",
            "reboot # now",
        ):
            with self.subTest(command=command):
                self.assertTrue(requires_local_approval(command))

    def test_invalid_shell_syntax_requires_review(self):
        self.assertTrue(requires_local_approval("echo 'unclosed"))
        self.assertTrue(requires_local_approval(""))
