# SSH Gate 前端开发说明

`frontend/` 是 **SSH Gate 1.0.0** 的 React + TypeScript + Vite 源码。桌面运行时仍由 Python + pywebview 提供本地桥接，正式静态资源构建到 `ssh_gate/frontend/`。

## 技术栈

- React 19
- TypeScript 5.9
- Vite 7
- pywebview DesktopAPI
- Canvas 场景绘制

运行已编译应用不需要 Node.js；只有修改 React 源码、重新构建前端或执行前端开发测试时才需要 Node.js。

## 构建

推荐在项目根目录运行：

```text
Build-Frontend.cmd
```

或手动执行：

```powershell
cd frontend
npm ci
npm run build
```

`npm run build` 会先做 TypeScript 检查，再生成静态 HTML/JS/CSS，并更新 `ssh_gate/frontend/`。正式资源不依赖 CDN、远程字体或开发服务器。

如果项目中已经存在 `dist\SSHGate\SSHGate.exe`，构建前端后还需要运行根目录 `Build-App.cmd`，否则旧 EXE 不会自动包含新资源。

## 界面结构

主界面由以下部分组成：

- 顶部连接与 Tunnel 状态栏
- 服务器节点场景
- 只读实时终端
- SSH 连接状态面板
- 请求审批面板
- 命令面板 `Ctrl+K`
- 文件、会话、服务器、Tunnel、代理和设置抽屉
- 主机指纹、凭据输入、请求详情等模态窗口

### 用户文案

正式 UI 使用直接功能名称：

- 请求审批
- SSH 连接状态
- 握手记录 / 连接事件
- DNS 解析 / TCP 连接 / SSH 握手 / 密钥交换 / 主机核验 / 身份认证 / 已连接

内部源码历史名称 `Gate.tsx`、`OrbitPanel.tsx`、`orbitDrawing.ts` 目前保留，不应继续扩散成用户文案。

## 审批交互

- 普通请求按住约 1 秒批准。
- 破坏性请求按住约 1.5 秒批准。
- 计时从取得有效本地审批票据后开始。
- 提前松开、指针离开、切换请求、窗口失焦/隐藏、打开其他模态交互都会取消本次按住进度。
- 后端仍会校验请求摘要和一次性票据，前端计时不是安全边界。

快捷键：

- `J/K`：切换待审批请求
- 按住 `A`：批准当前请求
- `R`：拒绝当前请求
- `Enter`：查看请求详情
- `Ctrl+K`：打开命令面板
- `Esc`：关闭当前面板/弹窗

输入控件、抽屉和模态窗口中不会误触审批快捷键。

## 终端

终端通过后端快照和请求详情增量读取：

- stdout/stderr 保留独立流信息。
- 连续相同输出在同一请求/流内折叠。
- 前端显示层进行秘密文本脱敏，但选择复制仍按原始文本偏移恢复内容。
- 活跃终端保留行数有上限，淘汰内容转为场景背景的有界缓冲。
- 悬停或向上滚动时暂停自动跟随。

后端没有为 stdout/stderr 每个数据块提供统一高精度时间戳，因此前端不能恢复两路输出的绝对原始交错顺序。

## SSH 连接状态

连接状态由后端真实事件驱动。前端不会填入模拟网络延迟或虚构进度百分比。

主要规则：

- 主机公钥收到后仍处于待核验状态。
- 跳板连接成功不等于目标连接成功。
- 连接复用不会重播不存在的握手阶段。
- 后续 SFTP/默认目录诊断失败不会覆盖已成功的 SSH 握手结论。
- 指纹图是视觉辅助，完整 SHA256 指纹仍在核验界面显示。

详见 `../docs/SSH_CONNECTION_TRACE.md`。

## 动效与布局

- 特效档位：`off` / `low` / `standard`。
- 系统减少动态效果时会自动抑制非必要动画。
- 最小窗口按 960 × 680 设计。
- 窄窗口下请求审批区会收起，需要时自动展开。
- 文字缩放支持当前后端配置允许的 90%–130%。

## 桥接边界

前端只能调用 `DesktopAPI` 暴露的本地能力。浏览器独立运行 `npm run dev` 时没有真实桌面权限，不应通过另建 HTTP 控制接口绕过 pywebview 桥接。

用户输入、服务器输出、文件名和日志内容都按文本渲染，不作为 HTML 执行。

## 测试

逻辑测试：

```powershell
npm test
```

正式资源 UI 测试：

```powershell
npx playwright install chromium
npm run test:ui
npm run test:orbit
npm run test:authorizations
```

测试使用正式编译资源和受控 DesktopAPI/ApprovalManager fixture，不连接用户真实服务器或真实 OpenAI 账号。

当前 1.0.0 基线的前端逻辑测试为 **19/19 通过**。完整测试策略和最近基线结果见 `../docs/TESTING.md`。
