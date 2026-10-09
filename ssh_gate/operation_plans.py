"""Single-use finite maintenance plans: no generic shell commands or grant delegation.

All step arguments are validated before the *one* Windows-local approval. Plans
are tied to one existing server/workspace/cwd and never authorize later commands.
"""
from __future__ import annotations

import posixpath
import re
import shlex

from .config import checked_text, integer
from .git_policy import git_args_command
from .policies import scope_contains
from .readonly import readonly_command

MAX_STEPS = 8
MAX_SECONDS = 360
MAX_COMMAND = 4096


def _specific_path(value: str, label: str) -> str:
    checked_text(value, label)
    if len(value) > 1024 or not value.startswith("/") or posixpath.normpath(value) != value:
        raise ValueError(f"{label}必须是规范化绝对路径")
    if value in {"/", "/home", "/srv", "/tmp", "/var", "/opt", "/root"}:
        raise ValueError(f"{label}必须指向具体工作区，不允许系统根目录")
    if ".." in value.split("/") or "." in value.split("/"):
        raise ValueError(f"{label}不允许路径遍历")
    return value


def validate_plan(workspace_root: str, cwd: str, steps: list, max_timeout: int) -> tuple[list[dict], str, int]:
    root = _specific_path(workspace_root, "工作区")
    directory = _specific_path(cwd, "工作目录")
    if not scope_contains(directory, (root,)):
        raise ValueError("操作计划工作目录不在指定工作区内")
    if type(steps) is not list or not 3 <= len(steps) <= MAX_STEPS:
        raise ValueError("操作计划必须有 3–8 步：前置检查、维护动作、后置检查")
    if type(max_timeout) is not int or max_timeout < 3:
        raise ValueError("操作计划执行时限无效")
    validated = []
    total = 0
    modifications = 0
    for index, item in enumerate(steps):
        if type(item) is not dict:
            raise ValueError("计划步骤必须是结构化对象")
        kind = item.get("kind")
        timeout = integer(item.get("timeout_seconds", 30), 1, 90, "步骤执行时限")
        if kind in {"check", "verify"}:
            if set(item) - {"kind", "command", "timeout_seconds", "label"}:
                raise ValueError("只读检查包含不支持的字段")
            raw = checked_text(item.get("command"), "检查命令")
            if len(raw.encode("utf-8")) > MAX_COMMAND:
                raise ValueError("检查命令过长")
            decision = readonly_command(raw)
            if not decision.allowed or decision.category not in {"read_fs", "diagnostics", "git_read", "docker_read"}:
                raise ValueError("计划的前后置检查只允许严格白名单中的只读命令")
            executable = decision.executable_command
            category = decision.category
        elif kind == "git_repair":
            if set(item) - {"kind", "paths", "timeout_seconds", "label"}:
                raise ValueError("Git 修复包含不支持的字段")
            paths = item.get("paths")
            if type(paths) is not list or not 1 <= len(paths) <= 3:
                raise ValueError("git_repair 必须提供 1–3 个完整工作树路径")
            paths = [_specific_path(p, "工作树路径") for p in paths]
            if any(not scope_contains(p, (root,)) for p in paths):
                raise ValueError("工作树路径不在当前已批准的工作区")
            raw = git_args_command(["worktree", "repair", *paths])
            executable = raw
            category = "git_manual"
            modifications += 1
        else:
            raise ValueError("不支持的计划操作。服务停止、删除、推送及任意 Shell 命令必须单独审批")
        label = item.get("label", f"Step {index + 1}")
        if type(label) is not str or not 1 <= len(label) <= 72:
            raise ValueError("步骤说明长度为 1–72 字符")
        checked_text(label, "步骤说明")
        total += timeout
        validated.append({"index": index + 1, "kind": kind, "label": label, "command": raw,
                          "executable": executable, "category": category,
                          "timeout_seconds": timeout})
    if validated[0]["kind"] != "check" or validated[-1]["kind"] != "verify":
        raise ValueError("计划必须以只读前置检查开始，以只读后置检查结束")
    if not 1 <= modifications <= 2:
        raise ValueError("计划仅允许 1–2 项经明确审查的 Git 修复动作")
    if total > MAX_SECONDS or total > max_timeout:
        raise ValueError("计划步骤累计时限超过限制")
    lines = [f"有限操作计划 | 服务器内工作区 {root} | 工作目录 {directory}",
             f"共 {len(validated)} 步，累计时限 {total}s；所有步骤在本次 Windows 审批后才执行。"]
    for step in validated:
        lines.append(f'{step["index"]}. [{step["kind"]}] {step["label"]}  (timeout {step["timeout_seconds"]}s)')
        lines.append("    " + step["command"])
    lines.append("遇到失败、取消或超时立即停止；已完成修改不自动回滚。")
    return validated, "\n".join(lines), total
