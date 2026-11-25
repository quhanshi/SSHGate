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
            "echo hello | tee output.txt", "python --version", "uv --version",
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
            "python -m pytest tests/", "python cleanup.py",
            "python3.12 scripts/verify.py", "uv run python scripts/check.py",
            "uv run pytest -q", "uv run --no-project python scripts/check.py",
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


    def test_connection_disruptions_require_review_in_both_modes(self):
        for command in (
            "sudo systemctl stop sshd", "systemctl restart ssh.service",
            "systemctl restart NetworkManager.service", "service networking restart",
            "ip link set eth0 down", "ip route flush table main", "ifdown eth0",
            "nmcli connection down office", "iptables -F", "nft flush ruleset",
            "pkill sshd", "kill -9 123", "loginctl terminate-user appuser",
        ):
            for critical_only in (False, True):
                with self.subTest(command=command, critical_only=critical_only):
                    self.assertTrue(requires_local_approval(command, critical_only=critical_only))

    def test_critical_only_trusts_literal_project_scripts(self):
        for command in (
            "python verify.py", "python3.12 scripts/check.py", "python -m pytest -q",
            "uv run pytest -q", "uv run --no-project python scripts/check.py",
            "bash scripts/deploy.sh", "systemctl restart nginx", "rm -rf build",
            "ip addr show", "iptables -L",
        ):
            with self.subTest(command=command):
                self.assertFalse(requires_local_approval(command, critical_only=True))
        for command in (
            "sudo reboot", "rm -rf /*", "uv run reboot", "uv run bash -c 'reboot'",
            "python -c 'print(1)'", "sh -c 'reboot'", "rm -rf $(pwd)",
            "echo ok && systemctl stop sshd",
        ):
            with self.subTest(command=command):
                self.assertTrue(requires_local_approval(command, critical_only=True))
