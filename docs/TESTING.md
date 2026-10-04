# SSH Gate 测试说明

本文记录 **1.0.0 基线**的测试结构、当前验证结论和复验方法。它是持续维护的测试文档，不是一次性交付报告。

## 当前基线结果

当前代码在建立 1.0.0 基线前的最近一轮完整验证结果：

| 范围 | 最近确认结果 |
| --- | --- |
| Python 后端完整套件 | 149 项运行，147 项通过，2 项因测试容器 PID namespace 与 `/proc` 视图不一致而跳过，0 失败 |
| SSH 专项 | 44 项通过，0 失败 |
| 前端逻辑单元测试 | 19 项通过，0 失败 |
| 原有浏览器 UI 回归 | 26 项通过 |
| SSH 连接状态浏览器场景 | 11 项通过 |

本次 1.0.0 文档/版本基线整理没有修改业务逻辑；在当前隔离环境中已再次运行 `frontend/npm test`，结果 **19/19 通过**。当前环境没有可离线使用的项目 Python 3.12/MCP/Paramiko 依赖，因此未重新执行完整 Python 套件；这不替代发布前的 Windows/完整依赖复验。

## 后端覆盖

主要覆盖：

- 配置解析、原子写入和边界校验。
- 审批票据、幂等请求、并发状态和本地心跳。
- 只读命令分类、Git/Docker 受限参数、目录范围和 pytest 显式授权。
- SSH 登录、密码/私钥/agent、主机指纹、连接复用和凭据失效。
- OpenSSH config、Include、Host 模式、ProxyJump、多跳、IPv6、ProxyCommand 和循环拒绝。
- 真实回环 Paramiko SSH server、direct-tcpip 与 SFTP 协议。
- DNS/TCP/SSH/认证连接事件、失败分类、指纹和算法结果。
- 命令输出分页与独立 stdout/stderr 游标。
- PID/PGID/启动时间验证、TERM/KILL 终止流程。
- SFTP 目录、stat、文件搜索、分段读取、上传、下载、ZIP、安全校验和缓存恢复。
- 受控会话上下文冻结、revision、关闭与已提交请求关系。
- MCP HTTP 初始化、23 个工具发现、Host/Origin 防护。
- Tunnel 生命周期、代理配置、HTTP/HTTPS CONNECT、TLS 校验和本地健康地址绕过代理。

## 前端覆盖

逻辑测试包括：

- SSH 指纹图与独立 OpenSSH randomart 的一致性。
- 连接事件去重、乱序处理和阶段停滞。
- 主机公钥“已收到”与“已信任”的状态分离。
- ProxyJump 跳板成功不误报目标成功。
- 连接复用、候选地址失败、认证方法失败和最终错误归类。
- 后续 SFTP/默认目录失败不覆盖已经成功的 SSH 连接结论。
- 前端只显示 allowlist 中的连接元数据。
- 密钥/API Key 等文本脱敏，同时保留原始复制偏移。
- 破坏性命令重新分类、终端重复行折叠和有界保留。

浏览器集成测试覆盖：服务器配置、known_hosts、密码输入、审批、终端、文件、上传下载、会话、SSH 路由、Tunnel、代理、设置、缩放、减少动效和窄窗口布局。

## 两项环境相关跳过

完整后端套件中的两项真实进程组测试会在检测到 `os.getpid()` 与 `/proc/self/stat` PID 不一致时跳过：

1. TERM 被忽略后升级 KILL，并清理同进程组子进程。
2. PID 控制记录过期/启动时间不匹配时，不误杀无关进程。

这些测试必须在普通 Linux PID 视图环境中补跑，才能算作完整的真实进程组验证。

## 未由自动测试替代的实机验收

发布前仍应在 Windows 验证：

- Edge WebView2 的窗口、缩放、输入与弹窗层级。
- 真实 `.ssh/config`、known_hosts、私钥和密码认证。
- 至少一条真实 ProxyJump 路线。
- 小型测试文件的 SFTP 上传/下载与 SHA256。
- 一个可安全终止的远端测试命令。
- Tunnel 客户端下载、Runtime API Key、本机 `/readyz`。
- 自动/手动/直连代理模式，尤其是不启用 TUN 的 HTTP/Mixed 代理场景。

## 复验命令

后端：

```powershell
uv sync --locked
uv run --locked python -m unittest discover -s tests -p "test_*.py" -v
uv run --locked python -m unittest discover -s tests -p "test_ssh_*.py" -v
```

前端：

```powershell
cd frontend
npm ci
npm test
npm run build
npx playwright install chromium
npm run test:ui
npm run test:orbit
```

锁文件：

```powershell
uv lock --check --offline
```

静态检查可额外执行 Python 编译和生产 JavaScript 语法检查。

## 测试数据原则

- 自动测试只使用 fixture、回环服务和临时目录。
- 不连接用户真实服务器、不读取用户真实凭据。
- `preview/` 中截图与结果文件属于本地生成的测试数据，默认不入库，也不应包含真实密码、Token 或敏感文件内容。
- 用户真实配置、日志和 `transfers/` 不应作为发布测试夹具提交。
