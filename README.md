# SSH Gate 1.0.0

SSH Gate 是一个运行在 Windows 本机的 SSH 访问网关。它通过 **OpenAI Secure MCP Tunnel** 将受控 SSH 能力提供给 ChatGPT，同时把密码、私钥口令、主机指纹确认、写操作审批和策略配置保留在本机界面中处理。

**1.0.0 是当前项目的基线版本。** 本仓库中的说明均以当前代码为准，不再保留早期原型、阶段编号或旧版本迁移叙事。后续功能、接口和文档都从 1.0.0 继续演进。

## 核心能力

- **SSH 连接管理**：支持 IP/域名、OpenSSH `Host` 别名、`IdentityFile`、`IdentitiesOnly`、`ProxyJump`、多跳跳板和可信 `ProxyCommand`。
- **本地安全交互**：未知主机指纹、SSH 密码、私钥口令以及需要人工批准的操作只在本机 WebView 中处理。
- **命令执行**：异步提交、状态查询、stdout/stderr 增量读取、受控超时和运行中终止。
- **自动授权策略**：可按服务器配置只读类别与绝对目录范围；不满足规则的操作进入本地审批。
- **SFTP 文件操作**：目录列表、属性、搜索、分段读取、单文件/目录下载、单文件/ZIP 目录上传和 SHA256 校验。
- **受控会话**：保存 cwd 与非敏感环境变量上下文；每条命令仍为独立 shell，不提供交互式 PTY。
- **连接诊断**：记录 DNS、TCP、SSH 握手、密钥交换、主机核验和认证事件，支持失败原因与逐跳查看。
- **Secure MCP Tunnel**：应用内配置、启动、停止、健康检查、运行密钥本地保存，以及自动/手动/直连三种出站模式。
- **React 桌面前端**：React + TypeScript + Vite 构建，运行时由 pywebview / Edge WebView2 加载静态资源。

## 运行模型

```text
ChatGPT
   │
   │ OpenAI Secure MCP Tunnel
   ▼
127.0.0.1:<MCP port>
   │
   ▼
MCPHost ── ApprovalManager ── SSHRunner / SFTP / Sessions
                          │
                          └── Windows WebView 本地审批与凭据输入
```

MCP 工具不能远程批准请求、修改自动授权策略、修改服务器配置或读取本机保存的明文凭据。审批能力只存在于当前桌面进程的本地桥接中。

## 快速开始

要求：Windows 10/11、Microsoft Edge WebView2 Runtime。源码环境由 `uv` 管理，目标 Python 为 3.12。

首次初始化：

```text
Setup.cmd
```

随后启动：

```text
Start-App.cmd
```

`Start-App.cmd` 若发现 `dist\SSHGate\SSHGate.exe` 会优先启动已构建 EXE；修改源码或前端资源后，如果仍要使用 EXE，请重新运行 `Build-App.cmd`。

源码启动：

```powershell
uv sync --locked
uv run --locked python -m ssh_gate
```

Windows 打包：

```text
Build-App.cmd
```

输出目录为 `dist\SSHGate\`。分发时应分发整个目录；不要把自己的 `config.json`、日志、传输缓存或凭据目录打入安装包。

## 连接配置

连接优先复用本机 OpenSSH 配置。新建连接时可以选择 `%USERPROFILE%\.ssh\config` 中的具体 `Host`，执行时读取该 Host 的 `HostName`、`User`、`Port`、`IdentityFile`、`IdentitiesOnly` 和 `ProxyJump`。

- 支持直连和最多 8 跳的 `ProxyJump`。
- 跳板与目标分别进行主机指纹校验和认证。
- 跳板后的目标域名可以由跳板侧解析，不要求 Windows 本机可解析目标内网域名。
- `IdentitiesOnly yes` 会限制可使用身份；不会启用 agent forwarding。
- 自定义 `ProxyCommand` 视为用户本机可信配置，但不能由 MCP 远程写入。

未知主机必须在本地确认真实 SHA256 指纹后才能临时信任或保存。已知主机指纹不匹配时直接拒绝连接。

## 请求、审批与终止

远端操作通过请求对象执行。常见状态包括 `pending_approval`、`queued_readonly`、`running`、`succeeded`、`failed`、`cancelled` 等。

- 符合自动授权策略的只读请求可以直接排队执行。
- 其他操作进入本地“请求审批”界面；审批票据与请求摘要绑定，只对该次请求有效。
- 待审批/排队请求使用 `cancel_pending_request` 取消。
- 运行中的命令或传输使用 `terminate_command` 请求终止，并继续查询最终状态。

命令运行在独立远端进程组中。终止逻辑会校验 PID/PGID/启动时间并按 TERM → KILL 尝试清理，但自行 daemonize、另建 session 或提交给 Docker daemon 的后台任务可能逃离原进程组，因此必须检查 `termination.remote_group_terminated`，不能仅凭“已发送终止请求”判断远端工作已停止。

## 自动授权策略

全局 `auto_allow_readonly` 控制是否启用自动只读准入。服务器还可以限制允许类别和绝对路径范围。

| 类别 | 当前覆盖 |
| --- | --- |
| `read_fs` | ls/ll/cat/head/tail/pwd/wc/grep/find/stat/du，以及结构化只读文件工具 |
| `diagnostics` | df/ps/free/uname、连接和默认目录诊断 |
| `git_read` | 受限参数的 git status/log/diff |
| `docker_read` | 受限参数的 docker ps/logs/inspect |
| `python_tests` | 显式授权范围内的受限 pytest；测试代码本身仍可能写文件 |
| `manual_only` | 仅人工审批 |

管道、重定向、组合脚本、未知选项和写操作不会因为“看起来像只读”而自动执行。目录范围属于准入与路径检查，不是操作系统沙箱。

## 文件与传输

文件系统操作使用 SFTP，不拼接 SCP 命令。默认限制包括：

- 单文件最大 64 MiB；传输分块最大 32 KiB。
- 本地传输缓存总配额 256 MiB，最多 100 项。
- 目录 ZIP 最多 5000 项、展开数据最多 64 MiB。
- `find_files` 不跟随目录符号链接，扫描项和返回结果有上限。
- 文件上传默认不覆盖；目录 ZIP 只能解压到新目录。
- ZIP 会拒绝绝对路径、`..`、符号链接、重复成员、加密条目和异常展开。

下载首先进入 Windows 本地传输缓存，不会自动变成 ChatGPT 附件。需要由调用端重建文件时使用 `read_download_chunk`；大文件更适合在本机保存后自行附加。

## 受控会话

`create_session / update_session / exec_in_session / list_sessions / close_session` 提供受控上下文：

- 会话保存 cwd 与字面环境变量；创建和修改需要本地批准。
- 每次执行都冻结当时的会话版本，随后修改会话不会影响已经提交的请求。
- 每条命令仍启动新 shell，因此命令内部的 `cd` / `export` 不会改变后续上下文。
- 不提供交互式 stdin/PTY；需要多轮 sudo、验证码或终端提示的操作应在普通终端完成。

不要把 SSH 密码、Token 等秘密放入会话环境变量。

## MCP 工具（23 个）

| 类别 | 工具 |
| --- | --- |
| 服务器 | `list_servers`, `test_connection` |
| 命令 | `request_command`, `get_command_status`, `read_command_output`, `cancel_pending_request`, `terminate_command` |
| 文件系统 | `list_directory`, `stat_path`, `read_file`, `find_files` |
| 下载 | `download_file`, `download_directory`, `read_download_chunk` |
| 上传 | `begin_upload`, `append_upload_chunk`, `upload_file`, `upload_directory` |
| 会话 | `create_session`, `update_session`, `exec_in_session`, `list_sessions`, `close_session` |

`read_command_output` 的 stdout/stderr 游标按 **Unicode 字符** 计数；文件读取和下载分块 offset 按 **字节** 计数，两者不能混用。

## Secure MCP Tunnel 与代理

应用内“隧道接入”负责官方 Tunnel 客户端的下载/选择、Tunnel ID、Runtime API Key、启动/停止、`/readyz` 健康状态和日志。

出站模式：

| 模式 | 行为 |
| --- | --- |
| 自动检测 | 优先受支持的环境变量，再读取 Windows 当前用户系统代理，最后检查常见本地 HTTP/Mixed 端口 |
| 手动指定 | 使用明确的 HTTP/HTTPS 代理 URL |
| 直连 | 清除 Tunnel 子进程代理并强制直接联网 |

SSH 本身仍按 `.ssh/config` 的直连/ProxyJump 路由运行，Tunnel 代理设置不会改写 SSH 路由，也不会修改 Windows 全局代理。

代理诊断会验证 TCP、CONNECT、TLS 和 HTTP 响应。无认证测试得到 HTTP 401 只表示 HTTPS 链路已通，不代表 Tunnel 权限或账号配置正确。

## 本机凭据

SSH 密码、私钥口令和可选保存的 Tunnel Runtime API Key 不写入 `config.json`。当前实现使用随机 256-bit 主密钥和 AES-256-GCM：

- 密文保存在当前用户数据目录下的 `credentials.json`。
- 主密钥保存在独立的当前用户配置目录。
- SSH Gate 运行时只在需要时解密秘密。
- API Key 传给 Tunnel 客户端时使用子进程环境变量，不放入命令行、快照或审计日志。

这套 `FileKeyProvider` 的目标是防止源码目录、配置或日志被误提交/误上传；它不抵抗已经获得当前用户文件读取权限的恶意程序。`KeyProvider` 边界已保留，后续可以替换为系统级凭据存储。

## 配置与数据位置

源码模式默认使用项目根目录 `config.json`；EXE 模式优先读取 EXE 同目录的 `config.json`，否则使用 `%LOCALAPPDATA%\SSHGate\config.json`。

主要持久数据：

- `config.json`：服务器、策略、UI、Tunnel 和代理设置，不含 SSH 密码/API Key。
- `logs/audit.jsonl`：请求 ID、摘要、状态、准入和终止事件，不记录完整命令输出或秘密。
- `transfers/`：上传准备文件和下载缓存，可能包含真实文件内容。
- 当前用户凭据目录：加密凭据与独立主密钥。

请求历史、审批和受控会话主要保存在当前进程内，应用重启后不会恢复旧审批上下文。

## 项目结构

```text
ssh_gate/                 Python 后端、桌面桥接、SSH/SFTP、MCP、Tunnel
frontend/                 React + TypeScript 源码与前端测试
ssh_gate/frontend/        应用实际加载的编译前端资源
docs/                     当前基线的技术文档
tests/                    Python、协议与浏览器集成测试
scripts/                  Windows 启动、构建、Tunnel 辅助脚本
preview/                  本地生成的 UI 测试/预览产物（不入库）
```

## 文档索引

- [架构说明](docs/ARCHITECTURE.md)
- [安全模型](docs/SECURITY.md)
- [SSH 连接事件](docs/SSH_CONNECTION_TRACE.md)
- [开发说明](docs/DEVELOPMENT.md)
- [测试说明](docs/TESTING.md)
- [前端开发说明](frontend/README.md)
- [版本记录](CHANGELOG.md)

## 当前边界

- 主要目标环境是 Windows 桌面端；Linux 测试主要用于协议与逻辑验证。
- 目标服务器按当前执行封装预期为 Linux，并需要 SSH/SFTP 及若干标准命令。
- 不提供通用交互式 shell、远程审批 API 或远程策略编辑 API。
- `ProxyJump` / SSH 连接状态来自真实事件，但前端轮询可能合并非常短的阶段；不会人为延迟协议来播放动画。
- Tunnel `/readyz` 成功表示客户端就绪，不等价于 ChatGPT 账号、工作区或插件权限已经正确配置。

版本：**1.0.0**；基线日期：**2026-10-04**。
