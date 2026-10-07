"""Read-only request history views used to recover interrupted ChatGPT work."""
from __future__ import annotations

import json
from datetime import datetime


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _arguments(value: str):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def command_history(manager, mode: str = "recent", server_id: str = "", limit: int = 50,
                    before_request_id: str = "", activity_gap_seconds: int = 900) -> dict:
    if mode not in {"recent", "all"}:
        raise ValueError("mode 仅支持 recent 或 all")
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("limit 必须在 1–200 之间")
    if type(activity_gap_seconds) is not int or not 60 <= activity_gap_seconds <= 3600:
        raise ValueError("activity_gap_seconds 必须在 60–3600 之间")

    rows = manager.list_summaries()
    if server_id:
        rows = [row for row in rows if row["server_id"] == server_id]

    grouping = "current_runtime_all"
    if mode == "recent" and rows:
        grouping = f"latest_activity_batch_gap_{activity_gap_seconds}s"
        batch = [rows[0]]
        newer = _time(rows[0]["created_at"])
        for row in rows[1:]:
            older = _time(row["created_at"])
            if (newer - older).total_seconds() > activity_gap_seconds:
                break
            batch.append(row)
            newer = older
        rows = batch

    if before_request_id:
        try:
            index = next(i for i, row in enumerate(rows) if row["request_id"] == before_request_id)
        except StopIteration as exc:
            raise ValueError("before_request_id 不在当前历史范围内") from exc
        rows = rows[index + 1:]

    selected = rows[:limit]
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
    has_more = len(rows) > len(selected)
    return {
        "history_scope": "current_runtime",
        "mode": mode,
        "grouping": grouping,
        "server_id": server_id or None,
        "items": items,
        "count": len(items),
        "has_more": has_more,
        "next_before_request_id": selected[-1]["request_id"] if has_more and selected else None,
        "note": "recent 是按连续活动时间分组的恢复视图，不代表可信的 ChatGPT 会话身份；完整命令不会写入持久审计日志。",
    }
