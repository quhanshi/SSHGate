# SSH Gate · WebView 0.4.2

Windows 本地独立应用，使用 **pywebview + Microsoft Edge WebView2**，Python 依赖由 **uv** 管理。通过 **OpenAI Secure MCP Tunnel** 接入 ChatGPT；SSH 密码、私钥口令、主机指纹确认和写操作审批在 Windows 本机处理。

## 本次改进

0.4.2 新增代理检测、三种出站模式和 HTTPS 诊断；修复首次保存 known_hosts 时缺少 os 导入的问题。运行中任务、文件传输、审批策略及 SSH config / ProxyJump 功能继续保留。

| 测试反馈 | 当前实现 |
| --- | --- |
| 不想一直开启 TUN | 环境/Windows 系统代理检测、常见本地端口验证、手动 HTTP/HTTPS 地址、HTTPS 链路诊断 |
| 运行中任务无法终止 | `terminate_command`；独立远端进程组、PID/PGID/启动时间校验、TERM 后 KILL、终止确认结果 |
| 无文件传输 | SFTP 文件上传/下载、目录 ZIP 打包/解包、分块传输、SHA256 校验、本地保存对话框 |
| 只读识别不足 | 参数级规则扩展到 find/stat/du/df/ps/free/uname、git status/log/diff、docker ps/logs/inspect |
| 查找路径需要多次 ls | `list_directory`、`read_file`、`stat_path`、`find_files` 和完整文件浏览页面 |
| 长期 running 无从判断 | DNS、TCP、SSH、认证、SFTP、目录校验阶段及时间记录；`test_connection` |
| 反复读取全部输出 | stdout/stderr 各自增量游标、等待新输出、运行时长、最后输出时间、PID/PGID、传输进度 |
| 无持久上下文 | 受控会话：明确保存 cwd 和环境变量，创建、更新、执行、关闭；不提供 PTY |
| 自动审批过粗 | 每台服务器的命令类别和绝对目录范围；显式受信任 pytest 授权 |
| 服务器配置反馈不足 | 连接状态、最近诊断、hostname/OS、默认目录验证及配置编辑 |

界面包含概览、服务器连接、命令与审批、文件管理、受控会话、隧道接入、运行设置七个页面。近黑背景、暖白等宽文字、冰蓝与少量琥珀色，缓慢轨道晶格可暂停并遵循系统减少动效设置。`preview/` 使用测试数据。

## 从已有版本升级

1. 停止本地应用与隧道，备份自己的 `config.json`。
2. 把本包 `SSHGate` 内的文件覆盖到现有项目目录，例如 `D:\Work\5\SSHGate`。**保留原有 `config.json`、`bin`、`logs` 和 `transfers`**；不要用 `config.example.json` 替换真实配置。新配置字段有兼容默认值。
3. 双击 `Setup.cmd`，再启动 `Start-App.cmd`。本次显式声明已在锁文件中的 httpx 依赖，没有增加安装包数量；仍由 uv 同步环境。
4. **若之前构建过 EXE，先运行 `Build-App.cmd` 重新构建。** `Start-App.cmd` 优先启动 `dist` 中的 EXE，只覆盖源码不会更新旧 EXE。
5. 在应用中确认版本 **0.4.2**，启动原 Tunnel。当前共有 **23** 个工具，0.4.1 → 0.4.2 工具名称保持不变。从 0.3 或更早升级时重新获取新增工具。可继续使用原连接与 Tunnel ID。

请求、输出和受控会话只在当前进程中保存，重启不恢复旧审批。已完成的上传准备文件及下载缓存会恢复，未完成分块上传会清理。

## Windows 启动与构建

需要 Windows 10/11 和 [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)。首次运行 `Setup.cmd` 会查找或安装 uv、同步 Python 3.12 环境；已有配置会保留，新安装的服务器列表为空。`Start-App.cmd` 打开独立窗口并启动只监听 `127.0.0.1` 的 MCP 服务。

源码启动：

```powershell
uv sync --locked
uv run --locked python -m ssh_gate
```

在 **Windows** 双击 `Build-App.cmd`，或执行：

```powershell
uv sync --locked --group build
uv run --locked --group build pyinstaller --clean --noconfirm SSHGate.spec
```

输出 `dist\SSHGate\SSHGate.exe`；分发整个目录，包括 `_internal`。构建产物无需另装 Python/uv，仍需 WebView2。EXE 默认配置在 `%LOCALAPPDATA%\SSHGate`，同目录已有配置时优先使用；`--config` 可指定位置。项目根目录启动脚本继续使用项目根目录配置。

本包包含源码和 Windows 构建入口，未附已验证的 Windows EXE。

### 目标服务器要求

- Linux、SSH 和 SFTP；当前命令执行包装依赖 `/bin/sh`、`/usr/bin/setsid`、GNU `/usr/bin/timeout`、`/usr/bin/awk`、`/usr/bin/ps` 及 `/proc`。
- 自动命令使用 `/usr/bin/` 下的固定程序。服务器没有相应程序时会返回失败，不能靠不同 PATH 或 shell 别名替换。
- 单文件上传默认不覆盖；显式覆盖要求 SFTP 支持 POSIX rename 扩展。目录 ZIP 上传只允许新建目标目录。
- 不提供交互式 stdin/PTY。需要多轮 sudo、验证码或终端提示的工作请在本地终端处理，不要把密码放到命令参数中。

## 服务器连接与诊断

“服务器连接”页支持搜索、新建、编辑、删除、诊断、断开会话。

- 新建/编辑优先选择 `%USERPROFILE%\.ssh\config` 中具体的 Host；known_hosts 地址作为备用选择，仍用于逐跳指纹校验。配置中的用户名无需重复填写。
- 支持新 IP/域名、本地 SSH Host 别名、SSH config、私钥文件和默认 cwd。已有 SSH 配置中的 ProxyCommand 属于本机可信配置，不能经 MCP 修改。
- 优先尝试 agent/密钥，失败后再尝试本机已保存凭据，最后才弹出密码或私钥口令窗口。登录窗口可选择“记住此凭据”；只有认证成功后才保存，失效凭据会自动清除并重新询问。
- 保存的 SSH 密码/私钥口令使用随机 256 位主密钥和 AES-256-GCM 加密，不进入 `config.json`、MCP 返回、审计或日志。密文位于当前用户数据目录，主密钥位于独立的当前用户配置目录；源码目录误提交不会带上二者。`SSH_GATE_DATA_DIR` / `SSH_GATE_KEY_DIR` 可覆盖路径，便于测试或以后接入系统 Keychain。
- 用户 known_hosts 优先。未知主机需核实真实 SHA256 指纹后选择仅会话信任或保存；已知指纹不匹配直接拒绝。
- `test_connection` 通过真实连接和 SFTP 检查默认目录，读取可用的 hostname、`/etc/os-release`；结果保存在最近诊断中。
- 状态显示 `resolving_dns`、`connecting_tcp`、`handshaking_ssh`、`authenticating`、`awaiting_local_credentials`、`opening_sftp`、`checking_default_cwd` 等阶段。错误带失败阶段。已复用的连接可能跳过部分阶段。
- 有待审、排队、运行请求或受控会话时不能编辑/删除该连接，先处理或关闭它们。

### SSH config 优先与 JumpHost

连接表单新增 **SSH 配置中的 Host**、**重新读取 Host**、**预览 SSH 路由**。选择配置后保留 Host 别名，清空手填 User/Port/IdentityFile 覆盖值；执行时从 config 读取 HostName、User、Port、IdentityFile、IdentitiesOnly 和 ProxyJump。手动填写这些覆盖字段时，才用手填值；跳板使用自己的配置，不继承目标机覆盖。

| 你提供的 Host | 解析目标 | 用户/端口 | 路由 |
| --- | --- | --- | --- |
| `10.208.88.202` | `10.208.88.202` | quhanshi / 11135 | 181 → 目标 |
| `10.208.88.201` | `10.208.88.201` | quhanshi / 12138 | 181 → 目标 |
| `10.208.88.201-Direct` | `10.208.88.201` | quhanshi / 12138 | 直连 |
| `10.208.88.190` | `10.208.88.190` | zhangshaobo / 11135 | 181 → 目标 |

同一 config 中应已有 `Host 181`，填写真实跳板地址、用户名、端口和可用密钥。应用会解析这个别名，不把 181 硬编码为端口或特定 IP。`-Direct` 的 Host 不会因为 HostName 与另一个连接相同而丢失直连配置。

- 优先使用本地 OpenSSH `ssh -G` 解析有效配置，支持 Include、Host 模式、默认值及 OpenSSH 支持的 Match。没有 OpenSSH 时提供常用 Host/Include 的解析回退；复杂 Match exec 会明确要求使用 OpenSSH。
- Host 下拉仅列具体名称，不把 `Host *`/否定模式当成服务器；Include 支持多个文件及模式，并检查循环/规模。读取候选列表不执行 Match exec；实际 OpenSSH 配置解析遵循本机可信配置。
- `ProxyJump` 使用本机 Paramiko 逐跳认证与 SSH `direct-tcpip` 转发，不再转换成 `BatchMode=yes` 的外部 ssh 子进程。支持 `[user@]host[:port]`、IPv6、SSH URI、逗号分隔多跳，最多 8 跳；重复/循环路线会拒绝。
- 每跳分别读取用户名、端口、IdentityFile、IdentitiesOnly 和 known_hosts；未知指纹、本地密码/私钥口令窗口明确标注跳板或目标。认证和转发阶段记录当前节点、跳数和上游，目标认证未完成时不会把“跳板已连上”显示为目标已连接。
- `IdentitiesOnly yes` 只允许该 Host 配置的身份，agent 中无关密钥不会发给服务器；可使用匹配配置公钥的 agent 身份。加密私钥需要时在本地输入口令。密钥文件和密码不会上传到跳板，应用不启用 agent forwarding。
- 跳板后的目标域名交给跳板连接，不要求 Windows 能解析/访问该内网域名。SFTP、执行、输出与终止都走同一目标 SSH 连接。
- 自定义 ProxyCommand 继续作为可信的本地外部代理保留，需自行具备非交互认证。不能在 ProxyJump 链的后续节点混入另一条 ProxyCommand 路由。

已有连接若保存了手填端口/用户名/私钥，在编辑页重新选择该 Host，清除旧覆盖后保存。无需把 SSH 配置复制到应用配置；后续新请求会重新解析本地 config，已提交任务仍使用当时被冻结的路线。

## 命令、增量输出与终止

非自动授权的请求在本地“检查并批准”中展示服务器、目录、时限、完整操作、实际执行内容和摘要。上传还绑定文件大小与 SHA256，会话绑定上下文版本。勾选确认后仅批准这一次；单次审阅票据有效 120 秒。

待审批或排队请求用 `cancel_pending_request` 撤回；运行中的任务用 **`terminate_command(request_id)`**。终止是异步请求，需要继续查询状态。

命令启动在独立进程组中，私有随机控制目录记录 PID 和进程启动时间。终止先验证当前进程身份和 PGID，发送 TERM，仍有活进程则发送 KILL，再检查原进程组。结果中的 `termination.remote_group_terminated=true` 表示该范围已确认停止；无法确认时返回 `termination_unconfirmed`，不会报告为已停止。

**终止范围是原进程组。** 自行 `setsid`/daemonize 的进程、提交给 Docker daemon 的后台工作、其他脱离进程组的任务不在保证范围内。网络中断也可能阻止远端清理。SFTP 终止关闭传输，但已经写入的目录文件可能保留；没有事务回滚。

`get_command_status` 返回 phase/history、运行时长、最后输出时间、PID/PGID、进度、stdout/stderr、结构化 result 和终止确认。`read_command_output` 使用两个独立的 **Unicode 字符游标**：

```text
read_command_output(request_id, stdout_cursor=0, stderr_cursor=0, wait_seconds=20)
下一次分别使用 next_stdout_cursor / next_stderr_cursor
```

该接口在新输出、阶段变化或任务完成时提前返回，底层仍采用等待与轮询，并非 MCP 推送流。文件读取/下载分块的 offset 则是 **字节偏移**。不要把两种游标混用。

输出总量默认 1 MiB，超出后标记截断；增量接口不能恢复已经截断的数据，可改用日志文件下载。UI 分页、复制、导出完整已保存输出，所有远端文字和文件名按文本显示。

一次最多执行一个任务，其他自动请求串行排队。默认审批 600 秒、任务 300 秒、最大时限 3600 秒；最多 20 个等待请求、200 个进程内请求。相同 `client_request_id` 的完全相同重试不会重复执行；参数不同会拒绝。

窗口失去本地心跳超过 5 秒时拒绝新准入。关闭窗口会停止 Tunnel、拒绝等待请求并尝试终止运行任务后关闭 SSH；清理无法确认时不能推定远端任务已停止。

## 自动授权策略

全局“只读自动允许”关闭时所有新远端操作都需本地审批。重新开启不自动批准已经待审的请求。服务器配置中可沿用全局列表，或单独选择类别及绝对目录；未选类别代表该服务器全部人工审批。

| 类别 | 可自动识别的操作 |
| --- | --- |
| `read_fs` | ls/ll/cat/tail/head/pwd/wc/grep/find/stat/du；结构化读取、搜索、下载 |
| `diagnostics` | df/ps/free/uname；连接与默认目录诊断 |
| `git_read` | git status/log/diff 的允许参数 |
| `docker_read` | docker ps/logs/inspect 的允许参数 |
| `python_tests` | 显式本地授权目录中的有限 pytest 参数；不会由全局只读开关默认加入 |

规则解析完整 argv，未知选项保持人工审批。`find -delete/-exec/-execdir/-fprint`、git reset/clean/checkout、git `--ext-diff/--textconv/--output`、docker restart/exec/build 均不会按只读自动执行。管道、重定向、组合脚本、替换和多行命令仍需审批。`ll` 转为固定 `ls -l`；find 的文件名模式可以使用明确引用的通配符，其他 shell 通配符需结构化搜索或审批。

Git 自动命令禁用外部 diff/textconv、fsmonitor、分页器和签名显示，并避免可选索引锁写入。目录范围在执行前通过 SFTP 规范化真实路径校验；普通文件读取参数也检查路径，越界或链接逃逸会拒绝执行。

目录范围限制的是准入与路径检查，**不是操作系统沙箱**。Git 仓库配置、Docker daemon 权限、被授权测试代码能接触的资源仍由服务器账号权限决定。pytest 会执行项目代码，可能修改或删除文件；只对可信项目启用。当前自动 pytest 使用 `/usr/bin/pytest`；自定义 venv 命令可经普通人工审批执行。

## 文件管理与 SFTP 传输

文件管理页提供服务器/路径选择、目录分页、父目录、属性、文件分段预览、文件名搜索、单文件下载、目录 ZIP 下载、本地文件选择上传、ZIP 上传及传输缓存保存/清理。

所有远端文件操作使用 SFTP，不拼接 SCP 或任意 shell。`find_files` 匹配文件名，可用 `*data-evaluation*`；不跟随目录符号链接，最多扫描 5000 项，深度最多 32，返回最多 200 个匹配。目录列表不是固定快照，遍历期间目录变化会影响分页。

- 上传：本地文件选择器或 `begin_upload` + `append_upload_chunk` 准备缓存，先核对大小/SHA256，再由 `upload_file`/`upload_directory` 提交本地审批。准备缓存不会写服务器。
- 单文件：默认禁止覆盖，临时文件上传完成后改名；新文件权限默认 0600，覆盖保留原文件模式。目标父目录必须存在且不能通过链接改写到其他路径。
- 目录：ZIP 所有成员预校验，拒绝绝对路径、`..`、符号链接、重复成员、加密文件与超限展开；只解压到新目录。中途失败可能留下已写部分，错误会说明，不自动删除远端目录。
- 下载：SFTP 读取到 Windows 本地缓存，完成后可用保存对话框保存，或通过 `read_download_chunk` 获取 Base64 数据。
- **下载不会自动变成 ChatGPT 附件。** 分块接口供具有文件重建能力的客户端使用；大文件优先在 Windows 保存后按需要附到聊天中。
- 每文件最多 64 MiB，每块最多 32 KiB；缓存总配额 256 MiB、最多 100 项；目录 ZIP 最多 5000 项、展开数据 64 MiB。需要更大的产物时先分卷或筛选。
- 完成缓存及校验元数据持久存放在配置同级 `transfers`，重启可继续保存/使用；未完成上传会清理。待审/运行中上传文件被租用，不能提前清除。

传输缓存包含真实文件内容，确认无需保留时在页面清理。`index.json` 损坏时应用会明确报错，避免静默丢失配额信息；备份缓存后修复索引或清空整个 `transfers` 再启动。

## 受控会话

会话页支持新建、修改 cwd/环境 JSON、提交命令、关闭。MCP 对应 `create_session / update_session / exec_in_session / list_sessions / close_session`。

创建和上下文修改需本地批准并验证 cwd；每次命令把当前 cwd、字面环境变量和版本冻结到请求中。关闭会话后已提交任务保留当时的审批快照，若要停止仍需终止工具。

这是内存中的受控上下文，不是保留着 shell 进程的终端。每条命令仍启动新 shell，命令中的 `cd`/`export` 不会改写后续会话；请用 `update_session`。重启清除会话。环境变量可能返回在请求审阅中，不要把 SSH 密码或其他秘密放入会话环境。

## MCP 工具列表（23 个）

所有远端异步操作返回 `request_id`，通过状态工具取最终 result。上传准备和读取下载缓存是直接本地操作。

| 类别 | 工具 |
| --- | --- |
| 服务器 | `list_servers`、`test_connection` |
| 命令 | `request_command`、`get_command_status`、`read_command_output`、`cancel_pending_request`、`terminate_command` |
| 文件系统 | `list_directory`、`read_file`、`stat_path`、`find_files` |
| 下载 | `download_file`、`download_directory`、`read_download_chunk` |
| 上传 | `begin_upload`、`append_upload_chunk`、`upload_file`、`upload_directory` |
| 会话 | `create_session`、`update_session`、`exec_in_session`、`list_sessions`、`close_session` |

MCP 不提供远程批准、修改策略、修改服务器配置或输入密码的能力。审批桥仅在当前 WebView 进程内可用，不经 HTTP 或 Tunnel 暴露。

Chat 示例：

> 列出服务器，测试开发服务器连接，然后使用 find_files 在 /data 下搜索 *data-evaluation*。读取找到的目录，不要重复提交已有请求。需要登录或审批时等我在 Windows 操作。

> 运行这条构建命令，使用 read_command_output 的双游标查看增量输出。如果我说停止，用 terminate_command 并检查终止是否确认。

## Secure MCP Tunnel

继续使用原官方客户端和 Tunnel。隧道页支持下载/选择客户端、配置、启动、停止、`/readyz` 健康观察和过滤后的日志。

- 在 [Platform Tunnel 设置](https://platform.openai.com/settings/organization/tunnels) 创建/选择 Tunnel，确保关联目标 ChatGPT 账号/工作区且运行身份有使用权限。
- MCP 默认 `127.0.0.1:8765/mcp`，客户端健康端口默认 8766。可选择记住 Runtime API Key；留空启动时会使用本机凭据仓库中已保存的 Key。Key 仅在本机解密后传入子进程环境，不写入 config.json、命令行、快照或日志。
- 就绪来自客户端 `/readyz` 的成功响应。进程存在并不代表连接成功；网络问题看控制平面日志。
- 使用官方 `CONTROL_PLANE_API_KEY`、`CONTROL_PLANE_TUNNEL_ID`、`MCP_SERVER_URL`、`HEALTH_LISTEN_ADDR`；出站代理使用本地保存的模式，`NO_PROXY` 保证本地地址直连。
- 插件使用 Tunnel 连接；本 MCP 后端没有另加 OAuth。账号可见功能和权限由 OpenAI 管理，应用不能自行开启。

运行期间不能更新客户端或更改隧道配置。修改 MCP 端口前停止隧道并处理未完成任务。旧命令行下载/启动入口保留用于排障。

### 关闭 TUN 后使用代理

推荐在独立应用的“隧道接入 → 出站代理”中设置：

1. 关闭 TUN，让代理软件继续运行，打开它的 **HTTP 或 Mixed 端口**。选择能访问 OpenAI 的节点。
2. 点击“检测代理”，检查来源与 CONNECT 结果。点击“采用”，或手动填写例如 `http://127.0.0.1:7890` / `http://127.0.0.1:7897`，实际端口以你的软件为准。
3. 点击“保存代理设置”，再“测试 HTTPS 连接”。测试成功且 HTTP 401 是正常结果：测试没有发送运行密钥，只验证 HTTPS 链路，不证明账号/Tunnel 权限。
4. 启动原 Tunnel，查看“当前进程”路由及 `/readyz` 就绪状态。隧道正在运行或客户端下载中时不能修改配置，先停止或等待下载完成。

| 模式 | 行为 |
| --- | --- |
| 自动检测（旧配置默认） | 优先环境变量，再读当前 Windows 用户的系统代理，最后检测常见本地端口；没有候选则明确显示直连。已配置但无法连接的代理不会静默换出口 |
| 手动指定 | 使用完整 HTTP/HTTPS URL，优先于继承的环境设置。URL 的 scheme 表示代理协议；即使访问 OpenAI HTTPS，普通 Mixed 端口通常仍填 `http://` |
| 直连 | 清除子进程代理设置，强制直接联网；不修改 Windows 全局代理 |

自动模式的环境变量顺序为 `CONTROL_PLANE_HTTP_PROXY`、`TUNNEL_CLIENT_HTTP_PROXY`、`HTTPS_PROXY`/小写、`HTTP_PROXY`/小写、`ALL_PROXY`/小写，仅接受 HTTP/HTTPS。支持前两项的 `env:变量名` 引用。Windows 读取当前用户的 `ProxyEnable` 和 `ProxyServer`，多协议配置优先 https 项，单地址按 HTTP 代理解释。PAC 自动配置只提示，不执行脚本；请改填实际 HTTP/Mixed 地址。

常见端口检测仅访问 `127.0.0.1` 的 7890、7897、7891、10809、1080、8080、8118、8888、20171。开放端口不代表 HTTP 代理：检测必须收到 CONNECT 响应，200 才标记转发通过。SOCKS-only 端口不支持，需要在代理软件开启 HTTP/Mixed。没有列出的自定义端口可手填。

“测试 HTTPS”在后台运行，显示 TCP、CONNECT、代理/目标 TLS、HTTP 响应与耗时；分别指出认证拒绝（407）、连接超时、证书错误或出口访问限制。TLS 证书始终校验，没有跳过验证选项。目标 `api.openai.com` 通过 CONNECT 交由 HTTP 代理解析，能避免本机目标 DNS 错误；仅检测成功不能证明不间断网络可用性。

配置不保存代理密码。需要认证的代理可在本机启动应用前提供 `HTTPS_PROXY=http://用户名:密码@主机:端口`，采用自动模式；URL 特殊字符需要百分号编码。认证信息仅用于本地子进程/探测器，快照、界面、日志隐藏 userinfo，不发送给 OpenAI。检测中包含认证的首选环境项只能切换到自动模式，不能把密码复制到手动配置。

应用向 Tunnel 子进程设置 `CONTROL_PLANE_HTTP_PROXY`（只代理云控制面）及标准 HTTP(S) 环境变量，清除继承的全局/MCP 显式代理，并设置 `NO_PROXY=127.0.0.1,localhost,::1`；直连模式使用 `NO_PROXY=*`。不会改系统设置，SSH 连接继续按 `.ssh/config` 的直连/ProxyJump 工作。应用内下载官方客户端也传递相同出站设置；Windows PowerShell 下载脚本尚需 Windows 实机复核，建议普通 HTTP/Mixed 地址。

上述保存的配置由 **WebView 应用内** 启动/下载读取。旧 `Start-Tunnel.cmd`、`Download-Tunnel.cmd` 作为终端排障入口，继续沿用其终端环境/系统网络，不读取新代理字段；使用新设置请从应用启动。

官方代理说明：[tunnel-client configuration](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md#outbound-http-proxy)。全局显式代理会忽略 NO_PROXY，因此应用不向本地 MCP 设置全局显式代理。

## 配置、验证与排障

源码配置在项目根目录 `config.json`；审计在配置同级 `logs/audit.jsonl`，只记录 ID、摘要、状态、准入和终止事件，不记录密码、完整命令或输出。配置原子保存；审计失败时不执行新准入。

后端检查：

```powershell
uv run --locked python -m unittest discover -s tests -p "test_*.py" -v
```

这次运行 127 项后端测试：125 项通过，2 项真实 Linux 进程组终止测试因运行环境的 PID 与 `/proc` 视图不一致跳过。真实回环 SSH/SFTP、HTTP MCP 与 HTTP/HTTPS CONNECT 测试通过，19 项 Chromium UI 检查通过。范围及实机验收步骤见 `TEST_REPORT.md`。

- 无法开窗口：安装 WebView2，重跑 Setup，终端源码启动看错误。
- 始终是旧工具/旧界面：确认版本，重建旧 EXE，重启原 Tunnel，再刷新 ChatGPT 插件工具列表。
- 默认 cwd 不存在：运行连接诊断，在本地编辑正确目录。
- 指纹变化：核实服务器身份后按正常 SSH 流程处理 known_hosts，应用不自动覆盖。
- 终止未确认：查看 termination.state/error及服务器实际进程；脱离进程组的任务需单独处理。
- 上传覆盖失败：检查父目录、目标权限及 SFTP POSIX rename 支持；无需覆盖时使用新路径。
- 无法找到 Tunnel：检查目标工作区关联和 Read + Use 权限，就绪不代表 ChatGPT 账号获得授权。

官方资料：[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)、[插件连接](https://developers.openai.com/plugins/deploy/connect-chatgpt)、[tunnel-client](https://github.com/openai/tunnel-client)、[Paramiko SFTP](https://docs.paramiko.org/en/stable/api/sftp.html)、[Git diff](https://git-scm.com/docs/git-diff)、[OpenSSH ssh_config](https://man.openbsd.org/ssh_config)、[pywebview](https://pywebview.flowrl.com/guide/installation.html)、[uv](https://docs.astral.sh/uv/guides/projects/)。

版本：0.4.2，2026-10-01。


## 本机凭据存储

SSH 密码、私钥口令以及 Secure MCP Tunnel 使用的 OpenAI API Key 都不会写入 `config.json`。选择“记住”后，凭据使用随机 256-bit 主密钥和 AES-256-GCM 加密，密文保存在当前用户的数据目录，主密钥保存在独立的当前用户配置目录。运行隧道时 API Key 仅在内存中解密，并通过子进程环境变量传给官方 Tunnel 客户端，不进入命令行参数、快照或日志。

当前 `FileKeyProvider` 的目标是防止配置、项目目录或日志被误提交/误上传；它不用于抵抗已经能以当前用户身份读取本机文件的恶意程序。`KeyProvider` 接口已保留，后续可替换为 Windows DPAPI、macOS Keychain 或 Linux Secret Service。
