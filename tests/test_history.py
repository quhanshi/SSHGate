from __future__ import annotations

import unittest

from ssh_gate.history import command_history


class FakeManager:
    def __init__(self):
        self.rows = [
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
    def test_recent_returns_latest_activity_batch(self):
        view = command_history(FakeManager(), "recent", activity_gap_seconds=900)
        self.assertEqual(["r3", "r2"], [item["request_id"] for item in view["items"]])
        self.assertFalse(view["has_more"])
        self.assertIn("latest_activity_batch", view["grouping"])

    def test_all_is_paginated_and_contains_full_command(self):
        view = command_history(FakeManager(), "all", limit=2)
        self.assertEqual(2, view["count"])
        self.assertTrue(view["has_more"])
        self.assertEqual("r2", view["next_before_request_id"])
        self.assertEqual("git status --short --branch", view["items"][0]["command"])
        next_page = command_history(FakeManager(), "all", limit=2, before_request_id="r2")
        self.assertEqual(["r1"], [item["request_id"] for item in next_page["items"]])


if __name__ == "__main__":
    unittest.main()
