"""Read-only current-runtime request history used to recover interrupted work."""
from __future__ import annotations

import json


def _arguments(value: str):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def command_history(manager, count: int = 50, server_id: str = "") -> dict:
    if type(count) is not int or not 0 <= count <= 200:
        raise ValueError("count 必须在 0–200 之间，0 表示返回全部")
    if not isinstance(server_id, str):
        raise ValueError("server_id 必须是字符串")

    rows = manager.list_summaries()
    if server_id:
        rows = [row for row in rows if row["server_id"] == server_id]
    selected = rows if count == 0 else rows[:count]

    items = []
    for summary in selected:
        view = manager.get(summary["request_id"], limit=1)
        items.append({
            "request_id": view["request_id"],
            "client_request_id": view["client_request_id"],
            "server_id": view["server_id"],
            "server_label": view["server_label"],
            "operation": view["operation"],
            "command": view["command"],
            "arguments": _arguments(view["arguments"]),
            "cwd": view["cwd"],
            "reason": view["reason"],
            "status": view["status"],
            "approval_kind": view["approval_kind"],
            "created_at": view["created_at"],
            "approved_at": view["approved_at"],
            "finished_at": view["finished_at"],
            "exit_code": view["exit_code"],
            "error": view["error"],
            "phase": view["phase"],
            "progress_bytes": view["progress_bytes"],
            "total_bytes": view["total_bytes"],
            "result": view["result"],
            "termination_requested": view["termination_requested"],
            "termination": view["termination"],
            "output_bytes": summary["output_bytes"],
        })
    return {
        "history_scope": "current_runtime",
        "server_id": server_id or None,
        "requested_count": count,
        "count": len(items),
        "total_matching": len(rows),
        "items": items,
        "note": "完整命令仅来自当前 SSH Gate 进程内存，不会写入持久审计日志；应用重启后不会恢复。",
    }
