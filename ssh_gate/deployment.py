"""Structured deployment command builders.

These helpers only construct commands from validated fields. The resulting command is still
submitted through ApprovalManager, so a human approval is required before any remote write.
"""
from __future__ import annotations

import posixpath
import re
import shlex
from urllib.parse import urlsplit

from .git_policy import provider_for_urls


_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}")
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")


def _repository_url(value: str, github_hosts=()) -> tuple[str, list[str]]:
    if not isinstance(value, str) or not value or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError("仓库 URL 无效")
    if "://" in value:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ValueError("仓库 URL 无法解析") from exc
        if parsed.query or parsed.fragment or parsed.password:
            raise ValueError("仓库 URL 不允许查询参数、片段或内嵌密码")
        if parsed.scheme in {"http", "https"} and parsed.username:
            raise ValueError("HTTP(S) 仓库 URL 不允许内嵌凭据")
    provider, hosts = provider_for_urls([value], github_hosts=github_hosts)
    if provider != "github":
        raise ValueError("bootstrap_repository 仅用于已确认的 GitHub 部署仓库")
    return value, hosts


def _target_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096 or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("部署目标必须是 Linux 绝对路径")
    normalized = posixpath.normpath(value)
    if normalized in {"/", "."} or normalized != value:
        raise ValueError("部署目标必须是规范化的非根绝对路径，不能包含多余分隔符、. 或 ..")
    return normalized


def build_bootstrap_command(repo_url: str, target_path: str, branch: str = "main",
                            expected_sha: str = "", github_hosts=()) -> dict:
    """Build a reviewable GitHub bootstrap command for an empty/non-existent target directory."""
    repo_url, hosts = _repository_url(repo_url, github_hosts)
    target_path = _target_path(target_path)
    if not isinstance(branch, str) or not _BRANCH.fullmatch(branch) or ".." in branch or branch.endswith("/"):
        raise ValueError("Git 分支名称无效")
    if expected_sha:
        if not isinstance(expected_sha, str) or not _SHA.fullmatch(expected_sha):
            raise ValueError("expected_sha 必须是完整 40/64 位十六进制提交 SHA")
        expected_sha = expected_sha.lower()

    q = shlex.quote
    script = [
        "set -eu",
        f"target={q(target_path)}",
        'if [ -e "$target" ]; then',
        '  [ -d "$target" ] || { echo "SSHGate: target exists and is not a directory" >&2; exit 64; }',
        '  [ -z "$(/usr/bin/find "$target" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo "SSHGate: target directory is not empty" >&2; exit 64; }',
        "fi",
        f"/usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false clone --progress --branch {q(branch)} --single-branch -- {q(repo_url)} "$target"",
    ]
    if expected_sha:
        script.append(
            f"/usr/bin/git -C "$target" -c core.hooksPath=/dev/null -c core.fsmonitor=false checkout --detach {q(expected_sha)}"
        )
    script.extend([
        'head=$(/usr/bin/git -C "$target" --no-pager -c core.hooksPath=/dev/null -c core.fsmonitor=false rev-parse HEAD)',
    ])
    if expected_sha:
        script.append(
            f'[ "$head" = {q(expected_sha)} ] || {{ echo "SSHGate: deployed SHA mismatch: $head" >&2; exit 65; }}'
        )
    script.append('printf "SSH_GATE_DEPLOY_HEAD=%s\\n" "$head"')
    return {
        "command": "/bin/sh -ceu " + q("\n".join(script)),
        "provider": "github",
        "hosts": hosts,
        "target_path": target_path,
        "branch": branch,
        "expected_sha": expected_sha,
    }
