# Structured Linux service management (P0-1)

The four MCP tools are `inspect_processes`, `inspect_services`, `request_stop_service`, and `verify_service_state`. They are intended for a Linux SSH target with `python3`, `/proc`, and optionally a working `systemctl --user` bus. **They are not a general shell executor or a bulk kill API.**

## Suggested workflow

1. Call `list_servers` to obtain a configured Linux SSH server. Choose a **specific** workspace such as `~/dq_dev`, not `~` or the filesystem root.
2. Call `inspect_processes(server_id, workspace_root, client_request_id)` and/or `inspect_services(...)`. Poll `get_command_status` until completion. The structured JSON is in `result`.
3. Select one exact target. For a process or group, copy the inspected `pid`, `start_ticks`, `pgid`, `cwd` into `request_stop_service` as `pid`, `expected_start_ticks`, `expected_pgid`, `expected_cwd`. Use `target_kind=process` or `process_group` (group requests must select the leader, where PID=PGID). For a user service, copy `unit_name`, `main_pid`, `main_start_ticks`, `fragment_path` and use `target_kind=user_service` with corresponding `expected_*` fields. Include any known listening ports.
4. The stop request is **always pending Windows-local approval**. Do not treat the presence of a request ID as approval. Rejection or expiry must not send a signal.
5. After local approval, poll `get_command_status`. Check **both** `status` and `result.verified_stopped`. `result.signal_sent` is not proof that the target exited. Run `verify_service_state` after a short interval if restart is possible. If confirmation is missing, diagnose rather than blindly issuing a broader kill.

## Safety constraints and limitations

- Workspace roots must be existing, specific, non-symlink paths on the remote host. Home directories and system roots are refused.
- Inspection is limited to same-user processes with readable `/proc` identity; argv arguments and environment variables are never returned. The program name is a short `comm` field, not a full executable command line.
- A process cannot be stopped by program name alone. PID start ticks, PGID, cwd, Linux UID and workspace boundaries are re-evaluated when the approved stop actually runs. Managed Docker, Nomad, containerd, Kubernetes and systemd processes are not directly killed. Group stops refuse unreadable, managed, or outside-workspace members.
- User service stops only use `systemctl --user stop <exact-unit>`. The unit must have a matching fragment, main PID identity and a WorkingDirectory in the requested workspace. Units named for core management services or invoking container managers are rejected. No `sudo`, system units, containers or Nomad jobs are stopped.
- TERM is attempted before KILL for standalone processes and eligible groups. `systemctl --user` owns user-service stop semantics. Neither path guarantees independent subprocesses or ports owned by another daemon will exit.
- Port checks examine TCP listening sockets visible in the current network namespace. They cannot prove that a process in another namespace or on another machine is stopped. If port inspection fails, the checked ports are considered occupied.
- The CLI remains useful when structured management refuses an unusual case, but manual shell commands still require Windows review; do not bypass policies by asking for unrestricted authority.

## DQ example

Use `~/dq_dev` as the inspection root, and inspect individual 8701 service/process identities. The formal Nomad workload under `~/dq_project/DQ` should remain outside that root. **Do not issue a blanket `pkill`, `killall`, `systemctl stop` with wildcards, or Nomad stop from these structured tools.**

## Testing

`python -m unittest discover -s tests -p 'test_service_ops.py' -v` exercises real Linux `/proc` inspection, stale identity refusal, workspace restrictions, a safe temporary child process when not systemd-managed, a protected cgroup refusal when run under systemd, a fake user service manager, and the Windows approval manager via its test harness. GitHub Actions runs the targeted suite on Python 3.11/3.12 and then the full Python `unittest` discovery. Windows WebView2 and real-host validation remain required before release.

This initial P0-1 release does not provide bulk stop, service start/restart, system-level systemd control, Docker/Nomad job management, or a persistent service inventory.
