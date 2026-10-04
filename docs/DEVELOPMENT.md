# SSH Gate 开发说明

本文以 **1.0.0** 为开发基线。

## 环境

后端：

- Python `>=3.11,<3.14`，当前目标 Python 3.12
- uv
- Paramiko 4.x
- FastMCP / MCP SDK
- pywebview 6.x
- cryptography 46.x

前端：

- Node.js 22.18+ 或 24 LTS
- React 19
- TypeScript 5.9
- Vite 7

Windows 桌面运行还需要 Microsoft Edge WebView2 Runtime。

## 常用命令

初始化后端：

```powershell
uv sync --locked
```

源码启动：

```powershell
uv run --locked python -m ssh_gate
```

后端测试：

```powershell
uv run --locked python -m unittest discover -s tests -p "test_*.py" -v
```

前端：

```powershell
cd frontend
npm ci
npm test
npm run build
```

浏览器 UI 测试：

```powershell
npx playwright install chromium
npm run test:ui
npm run test:orbit
```

Windows EXE：

```text
Build-App.cmd
```

## 前端构建产物

`frontend/` 是源码；`ssh_gate/frontend/` 是 Python 应用实际加载的编译静态资源。

修改 React 源码后必须重新生成编译资源：

```text
Build-Frontend.cmd
```

如果用户运行的是已经存在的 `dist\SSHGate\SSHGate.exe`，还需要重新执行 `Build-App.cmd`，否则 EXE 内仍是旧资源。

## 版本号

正式版本号必须同步维护：

- `pyproject.toml` → `project.version`
- `ssh_gate/__init__.py` → `__version__`
- `uv.lock` 中本项目条目
- `frontend/package.json`
- `frontend/package-lock.json`
- `README.md` / `CHANGELOG.md`

1.0.0 已作为统一基线。主文档只描述当前支持行为；兼容性说明只在真正需要支持已发布版本时增加。

## 文档维护规则

活动文档只有：

- 根 `README.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/SSH_CONNECTION_TRACE.md`
- `docs/DEVELOPMENT.md`
- `docs/TESTING.md`
- `frontend/README.md`
- `CHANGELOG.md`

不要重新创建一次性交付 README、本轮测试报告或按开发阶段拆分的并行说明。测试结果更新到 `docs/TESTING.md`，协议或结构变化更新对应长期文档。

## UI 文案规则

用户可见文案使用直接、功能性的产品语言。审批、连接、事件记录和协议阶段都按实际业务含义命名；协议阶段统一为“DNS 解析 / TCP 连接 / SSH 握手 / 密钥交换 / 主机核验 / 身份认证 / 已连接”。不要把设计稿隐喻、开发阶段代号或内部组件名称直接暴露给用户。

内部组件文件名属于实现细节；新增代码优先使用业务语义命名。

## 修改后检查

至少执行与变更范围相符的检查：

- Python 修改：完整 unittest 或相关专项套件。
- SSH/认证修改：`test_ssh_*.py` 和实际协议 fixture。
- MCP 修改：HTTP MCP 工具发现和请求状态测试。
- 前端逻辑修改：`npm test`。
- 前端布局/交互修改：构建正式资源后运行浏览器 UI 测试。
- Tunnel/代理修改：真实回环 HTTP/HTTPS CONNECT fixture。

安全边界变更必须同步检查 `docs/SECURITY.md`。

## 发布检查清单

1. 统一版本号并更新锁文件。
2. 构建正式前端资源。
3. 运行后端、前端逻辑和浏览器测试。
4. 在 Windows WebView2 做基本显示、缩放、登录和本地审批验收。
5. 使用测试服务器验证直连与 ProxyJump。
6. 验证 Tunnel `/readyz`、自动/手动/直连代理模式。
7. 确认包中不包含真实凭据、个人 `config.json`、运行日志、传输缓存和不需要的构建缓存。
8. 更新 `CHANGELOG.md` 和受到影响的长期文档。
