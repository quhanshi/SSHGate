# SSH Gate 架构说明

本文描述 **1.0.0 基线**的运行结构。它面向维护者，重点说明模块边界和数据流，不记录开发过程。

## 1. 组件关系

SSH Gate 由四层组成：

1. **桌面 UI**：`pywebview` 承载 `ssh_gate/frontend/` 的静态 React 应用。
2. **本地控制层**：`DesktopAPI` 提供仅 WebView 可调用的配置、审批、凭据输入、Tunnel 控制与本地文件选择功能。
3. **执行层**：`ApprovalManager` 统一管理请求、策略、状态、会话、传输缓存和 SSH 执行。
4. **MCP 层**：`MCPHost` / `FastMCP` 只监听本机回环地址，经 OpenAI Secure MCP Tunnel 对 ChatGPT 暴露受限工具。

关键模块：

| 模块 | 职责 |
| --- | --- |
| `ssh_gate/core.py` | 请求状态机、审批、自动准入、输出、会话、连接事件汇总 |
| `ssh_gate/ssh.py` | SSH 连接、认证、ProxyJump/ProxyCommand、命令与 SFTP |
| `ssh_gate/ssh_config.py` | OpenSSH Host/Include/ProxyJump 解析与路由预览 |
| `ssh_gate/ssh_trace.py` | 真实 SSH 协议事件观测与安全字段过滤 |
| `ssh_gate/readonly.py` | 只读命令解析与类别识别 |
| `ssh_gate/policies.py` | 服务器类别、目录范围和 pytest 特殊授权 |
| `ssh_gate/authorizations.py` | 临时授权、能力与固定命令规则、期限和使用次数 |
| `ssh_gate/git_policy.py` | 生效远端核验、GitHub 部署与其他远端 Git 工作流 |
| `ssh_gate/transfers.py` | 本地上传/下载缓存、SHA256、配额与恢复 |
| `ssh_gate/credentials.py` | 本机加密凭据存储 |
| `ssh_gate/proxy.py` | Tunnel 出站代理发现、验证和环境构造 |
| `ssh_gate/runtime.py` | MCP 与 Tunnel 客户端生命周期 |
| `ssh_gate/desktop.py` | WebView 本地桥接与 UI 快照 |
| `ssh_gate/mcp_server.py` | 28 个 MCP 工具和本地 HTTP MCP 服务 |

## 2. 进程与网络

默认本地端口：

- MCP：`127.0.0.1:8765`
- Tunnel 健康端口：`127.0.0.1:8766`

MCP HTTP 服务仅监听回环地址，并启用 Host/Origin 防护。公网入口由官方 Secure MCP Tunnel 客户端建立；SSH Gate 本身不开放公网监听端口。

Tunnel 与 SSH 是两条独立网络路径：

```text
ChatGPT ── Secure MCP Tunnel ── 本机 MCP
                                  │
                                  └── SSH / ProxyJump ── Linux 服务器
```

Tunnel 的 HTTP 代理设置只影响 Tunnel 控制面和客户端下载，不改变 SSH 的 `.ssh/config` 路由。

## 3. 请求状态机

MCP 提交远端操作后，`ApprovalManager` 生成请求并冻结执行参数。请求根据策略进入：

| 准入条件 | 起始状态 | 启动条件 |
| --- | --- | --- |
| 符合本地自动策略 | `queued_readonly` | 本地 UI 在线且执行器空闲，重复核验规则 |
| 携带匹配的临时授权 | `queued_authorized` | 本地 UI 在线且执行器空闲，重复核验授权 |
| 其他操作 | `pending_approval` | 60 秒内完成本地审批，执行器空闲 |

命令启动后为 `running`，最终进入 `succeeded / failed / cancelled / terminated` 等结束状态。排队和待审批请求最长保留 60 秒。

授权申请使用同一请求流程，但批准时只在本机创建临时授权并把申请标记为 `succeeded`，不启动 SSH worker。授权从批准时开始计时。调用方查询 `get_auto_approval_status` 获得 `grant_id`，随后把它传给 `request_command`；没有环境覆盖的受控会话也支持该参数。带环境变量的会话仍逐次审批。

关键原则：

- 审批的是冻结后的请求，而不是一段之后仍可变化的 UI 文本。
- 相同 `client_request_id` 只允许对完全相同参数做幂等重试。
- 自动授权只决定是否跳过人工确认，不改变执行器权限。
- 请求结果必须以最终 `status` 和命令 `exit_code` 为准。
- 授权绑定服务器有效 SSH 配置；队列启动和 SSH 实际执行前重复检查。撤销使未执行的工作失去权限。
- 支持的直接 Git 命令先通过有界 metadata channel 检查远端，GitHub 只走部署策略；元数据读取共享 20 秒期限、每次输出最多 32 KiB。

## 4. SSH 路由

目标服务器可以直接配置为主机名/IP，也可以引用 OpenSSH `Host` 别名。运行时优先使用本地 OpenSSH `ssh -G` 获得有效配置；不可用时使用项目内的受限解析回退。

`ProxyJump` 由 Paramiko 在进程内逐跳建立：

```text
本机
 └─ SSH 跳板 1
     └─ direct-tcpip
         └─ SSH 跳板 2
             └─ direct-tcpip
                 └─ 目标主机
```

每一跳独立处理：

- 主机指纹
- 用户名/端口
- IdentityFile / IdentitiesOnly
- 密码或私钥口令提示
- 连接事件与失败原因

目标连接成功前，不会因为跳板已成功而把目标标记成已连接。

## 5. SSH 连接事件

SSH Gate 不生成假的 `ssh -vvv` 输出，而是把实际协议时点转换成结构化事件。事件存放在请求内的有界队列中，供 UI 和请求详情读取。

事件覆盖：

- DNS 解析
- TCP 建连
- 跳板 channel / ProxyCommand
- SSH 协议版本交换
- 密钥交换与算法结果
- 主机公钥获取与信任校验
- 认证方法与结果
- 连接复用、失败和取消

详细字段与前端映射见 [SSH_CONNECTION_TRACE.md](SSH_CONNECTION_TRACE.md)。

## 6. 输出与终止

命令输出在后端按 stdout/stderr 分别保存。`read_command_output` 使用两套独立 Unicode 字符游标，以便调用方只读取新增内容。

远端命令封装建立独立进程组，并记录 PID、PGID 与启动时间。终止时会重新校验身份后发送 TERM，必要时升级 KILL。此机制只覆盖原进程组；脱离该组的 daemon/session 或 Docker daemon 后台工作不在保证范围。

## 7. 文件传输

SFTP 请求仍进入统一请求状态机；上传准备和下载缓存则属于本机操作。

上传：

```text
调用方数据 / 本地选择器
   -> transfers 本地缓存
   -> 大小 + SHA256 完整性确认
   -> 本地审批
   -> SFTP 写入服务器
```

下载：

```text
服务器 SFTP
   -> transfers 本地缓存
   -> 保存到 Windows / 分块读取给调用方
```

目录上传与下载使用 ZIP 作为本地/远端之间的封装格式，但远端文件访问本身仍由 SFTP 完成。

## 8. 受控会话

受控会话是“上下文记录”，不是持续存在的 shell 进程。其状态仅包含：

- 服务器 ID
- cwd
- 字面环境变量
- revision / 生命周期状态

`exec_in_session` 会把当前上下文复制到新请求中。关闭会话不会自动杀死已经提交的命令。

## 9. 持久状态与临时状态

持久化：

- `config.json`
- `logs/audit.jsonl`
- `transfers/` 中的完成传输缓存
- 当前用户凭据存储

进程内：

- 请求对象和审批票据
- 有期限和次数的临时授权
- 受控会话
- 活跃 SSH 连接池
- 当前 UI 快照和连接事件详情缓存

应用重启后不能依赖旧审批、临时授权或旧会话继续执行。

## 10. 前端数据流

React 前端主要通过 `DesktopAPI.snapshot()` 周期性读取轻量状态；需要更多信息时再读取请求详情。连接事件使用 `connection_event_seq` 判断详情是否需要刷新，避免把完整事件数组塞入每次快照。

前端中的视觉过渡只在两个已观测事件之间插值；协议阶段不会由计时器自行推进，也不会制造百分比进度。
