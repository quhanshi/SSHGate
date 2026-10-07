# Changelog

## 未发布

- 新增有目录、能力、期限、次数和执行超时范围的临时授权申请、查询、使用与撤销；仅本地预授权或本地审批可以授予，应用重启后失效。
- 新增实际 Git 远端核验：GitHub 副本只检查状态、拉取部署；其他已核验远端支持批准后的 Git 工作流。
- 新增 `bootstrap_repository`：首次 GitHub 部署可安全克隆到空目录，可绑定完整 SHA，并核对 SSH 生效 HostName、隔离 system/global Git 配置。
- 新增 `get_command_history`：按条数读取当前运行期命令历史，`count=0` 返回全部，并支持按 `server_id` 过滤。
- `get_auto_approval_status` 支持 0–20 秒 bounded long-poll；Git 只读检查补充 show、受限 rev-parse 与当前分支查询。
- 审批期限收敛为最多 1 分钟，按住确认统一为 0.5 秒；按钮倒计时从右向左消退，与按住进度相反。
- 主界面按 A 立即批准审批栏最上面一条（不再需要按住）；焦点在输入框、终端、对话框或抽屉中时不响应。
- Git 单独成为 MCP 工具 `request_git_command`（结构化参数）；`request_command` 中的 git 命令改为拒绝并提示。MCP 说明要求远端为 GitHub 时优先使用官方 GitHub 连接器，`inspect_repository` 对 GitHub 远端返回同样的建议。
- 命令模式授权支持本机工作区的 PowerShell 命令：按 PowerShell 规则解析单条字面命令，匹配后以 `&` 调用并对参数加单引号。
- 新增 MCP 工具 `request_pattern_approval`：申请命令模式授权（如 `npm run *`、`make test-*`），本地批准一次后，匹配的单条字面命令在目录、期限和次数内直接放行；通配参数不能是选项、绝对路径或 `..`，包装程序和脚本解释型程序受限。
- 连接策略增加可信测试/部署的显式预授权和 GitHub Enterprise 主机配置，运行设置增加临时授权查看与撤销。
- 补充文件选项路径、递归符号链接、授权失效及 MCP/浏览器集成验证。
- 新增本地 PowerShell 终端（Ctrl+`，最多 4 个会话）：仅本机 WebView 可用，不经 MCP、不产生请求、不写审计或日志。
- 新增“本机工作区”连接类型：MCP 可用现有文件、传输、会话和命令工具操作本机限定目录；文件操作经链接与联接解析后限制在工作区内，PowerShell 命令逐条人工审批并在结束时清理进程树。
- 自绘标题栏：顶部状态栏兼作窗口标题栏，保留系统缩放边框、贴靠、阴影与关闭确认；WebView2 不支持时回退系统标题栏。更换应用图标。
- SSH 连接状态面板：未信任的主机密钥状态固定在滚动区外；底部渐隐仅在下方仍有内容时显示。

## 1.0.0 — 2026-10-04

建立 SSH Gate 的首个统一基线版本。

当前基线包含：SSH/OpenSSH config/ProxyJump 连接管理、本地主机指纹与凭据交互、请求审批和自动只读策略、命令增量输出与终止、SFTP 文件管理与传输、受控会话、真实 SSH 连接事件、React WebView 前端、Secure MCP Tunnel、出站代理检测与本机加密凭据存储。

从本版本开始，长期文档只描述当前支持行为；阶段性实现记录和一次性交付说明不再作为活动文档保留。
