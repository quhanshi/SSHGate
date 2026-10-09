# SSHGate 审批：有限操作计划（第一版）

`request_operation_plan` 不是临时 Shell 授权，不会创建可复用的 `grant_id`。一个计划绑定一台 Linux SSH 服务器、一个绝对工作区、一个工作目录、**3–8 个不可变步骤**。Windows 用户必须在本地审批窗口审核**完整内容**并批准一次，不能由 MCP 自行批准。最多允许 1–2 项 `git worktree repair` 写操作；其他步骤必须是现有只读命令白名单中的检查。

## 请求格式

```json
{
  "server_id": "development",
  "workspace_root": "/home/developer/dq_dev",
  "cwd": "/home/developer/dq_dev/member/repository",
  "reason": "移动工作区后修复 Git worktree 指针，并核验仓库是否可用",
  "client_request_id": "repair-member-worktree-20261009",
  "timeout_seconds": 120,
  "steps": [
    {"kind": "check", "label": "前置目录检查", "command": "ls -la", "timeout_seconds": 20},
    {"kind": "git_repair", "label": "修复工作树关联", "paths": ["/home/developer/dq_dev/member/repository/worktree"], "timeout_seconds": 60},
    {"kind": "verify", "label": "验证 Git 可读取", "command": "git rev-parse HEAD", "timeout_seconds": 20}
  ]
}
```

请求参数中的 `paths`、`command`、工作区和时限在 Windows 本地审批前就被冻结并进入请求 SHA256 摘要。同一个 `client_request_id` 只允许完全相同的重试。步骤之间不会接收新命令，也不接受 Shell 管道、变量替换、任意脚本、Git push/reset/clean、目录移动/删除或系统服务停止。

## 运行与恢复

- 前置检查、修复、后置验证**必须按顺序**执行，每步独立 SSH 任务，单步最长 90 秒，累计不超过 360 秒。
- 每一步以退出码及连接/超时状态决定成功；任何非零、断连、取消或超时均阻止后续步骤。调用 `terminate_command(request_id)` 可以取消正在执行的步骤和尚未开始的步骤，但不能撤销已产生的副作用。
- `get_command_status` 的 `result.steps` 记录已经执行的步骤、退出码以及失败项；`side_effects_possible` 提醒 Git 修复可能已经修改元数据。不要把失败、取消或网络断开理解为远端完全未修改。
- 执行前 SSHRunner 通过 SFTP 确认工作区的实际位置及 Git 修复目标规范化路径仍在工作区中。执行过程中发生目录替换仍可能产生竞态；重要目录应停止其他写入后操作。
- 计划完成只代表最后一条只读检查退出码为 0，**不意味着自动验证所有工作树或路径引用**。验证命令应由请求人按具体目标选择。
- 高风险、可破坏性步骤（杀进程、`systemctl stop`、删库、删除工作区、移动目录、多文件修改）暂不包含在该版本；仍分别走 `request_stop_service` 或现有本地单条审批，待后续专用结构化事务接口实现后才能安全组合。

## 审批范围

该计划**不受只读自动放行总开关影响**：无论只读命令是否自动放行，整条计划始终需要 Windows 本地人工确认。审批窗口中的请求详情显示所有步骤及完整参数；在执行前应展开/打开完整请求，确认目标服务器、工作区、路径、操作次数和失败后果。

测试入口：`python -m unittest discover -s tests -p 'test_operation_plans.py' -v`；另需执行完整 Python 回归和 Windows WebView2 实机审批验收。
