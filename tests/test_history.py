from __future__ import annotations

import unittest

from ssh_gate.history import command_history


class FakeManager:
    def __init__(self):
        self.rows = [
            {"request_id": "r4", "server_id": "other", "created_at": "2026-10-07T14:40:00+00:00", "output_bytes": 40},
            {"request_id": "r3", "server_id": "s", "created_at": "2026-10-07T14:30:00+00:00", "output_bytes": 30},
            {"request_id": "r2", "server_id": "s", "created_at": "2026-10-07T14:20:00+00:00", "output_bytes": 20},
            {"request_id": "r1", "server_id": "s", "created_at": "2026-10-07T13:00:00+00:00", "output_bytes": 10},
        ]

    def list_summaries(self):
        return list(self.rows)

    def get(self, request_id, limit=1):
        row = next(row for row in self.rows if row["request_id"] == request_id)
        return {
            **row,
            "client_request_id": "client-" + request_id,
            "server_label": "Server",
            "operation": "command",
            "command": "git status --short --branch",
            "arguments": "{}",
            "cwd": "/srv/project",
            "reason": "recover",
            "status": "succeeded",
            "approval_kind": "auto_readonly",
            "approved_at": row["created_at"],
            "finished_at": row["created_at"],
            "exit_code": 0,
            "error": "",
            "phase": "finished",
            "progress_bytes": 0,
            "total_bytes": None,
            "result": {},
            "termination_requested": False,
            "termination": {},
        }


class CommandHistoryTests(unittest.TestCase):
    def test_count_returns_newest_n(self):
        view = command_history(FakeManager(), count=2)
        self.assertEqual(["r4", "r3"], [item["request_id"] for item in view["items"]])
        self.assertEqual(2, view["count"])
        self.assertEqual(4, view["total_matching"])
        self.assertEqual(2, view["requested_count"])

    def test_zero_returns_all(self):
        view = command_history(FakeManager(), count=0)
        self.assertEqual(["r4", "r3", "r2", "r1"], [item["request_id"] for item in view["items"]])
        self.assertEqual(4, view["count"])
        self.assertEqual(4, view["total_matching"])

    def test_server_filter_applies_before_count(self):
        view = command_history(FakeManager(), count=2, server_id="s")
        self.assertEqual(["r3", "r2"], [item["request_id"] for item in view["items"]])
        self.assertEqual("s", view["server_id"])
        self.assertEqual(3, view["total_matching"])

    def test_bounds(self):
        for value in (-1, 201, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                command_history(FakeManager(), count=value)


if __name__ == "__main__":
    unittest.main()
