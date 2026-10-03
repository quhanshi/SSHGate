# React 场景前端

本目录是 React + TypeScript + Vite 源码。运行时仍使用现有 Python + pywebview；没有新增后端接口。`ssh_gate/frontend` 已附编译资源，普通启动和 EXE 打包不需要 Node。

## 使用与构建

关闭应用，将本替换包的 `SSHGate` 文件夹内容合并到原项目目录。使用原项目的 `Start-App.cmd` 启动；如果已有 `dist` 中的 EXE，该脚本优先启动 EXE，需要先用原项目的 `Build-App.cmd` 重新构建。详细步骤见根目录 `FRONTEND_README.md`。

修改 React 源码后，在项目根目录运行 `Build-Frontend.cmd`，然后重启源码应用或重新构建 EXE。构建需要 Node.js 22.18+ 或 24 LTS。命令行：

```powershell
cd frontend
npm ci
npm run build
npm test
```

`npm run build` 先检查 TypeScript，再生成 IIFE 脚本、CSS 和带原占位符的 HTML，原子替换到 `ssh_gate/frontend`。使用单包、内联脚本和 CSS；保留原 CSP，不依赖外部字体、CDN、开发服务器或新增 HTTP 控制接口。`npm run dev` 仅用于布局调试，独立浏览器不会获得桌面操作权限。

## 设计与交互

- 单场景包含代码地形、粒子服务器节点、只读终端、顶部链路、右侧闸门和底部状态。
- 按住批准：普通请求 1 秒，破坏性请求 1.5 秒。从收到有效审批票据后开始计时。提前松开、指针离开、切换请求、失焦、隐藏窗口或打开抽屉/弹窗会取消进度。后端仍核对请求摘要和一次性票据。
- `J/K` 切换待审，按住 `A` 批准，`R` 拒绝，`Enter` 打开完整请求。输入控件、抽屉与弹窗内不触发审批快捷键。
- `Ctrl+K` 搜索连接、操作和当前会话历史；`Esc` 关闭。节点单击切换终端过滤，右键打开文件、会话、策略或断开。
- 终端显示输出、错误、文件传输和状态；重复行折叠，超过 500 行转入 80 行地形缓冲。悬停或向上滚动暂停跟随；选择复制恢复对应原文。脱敏只改变显示。
- 背景每行文本缓存三档模糊纹理，最多 30fps；隐藏时暂停，关档使用静态画面。系统减少动态效果将标准档降为低档。
- 960px 最小宽度，低于 1280px 闸门折叠；新待审请求自动展开。
- 连接、文件、会话、隧道、代理和设置在工作抽屉中保留原能力。密码与运行密钥输入后立即清空，不加入前端日志。

## 现有接口的边界

节点显示真实连接/执行状态。后端未提供持续 SSH 延迟与 ChatGPT 会话心跳，因此不显示模拟毫秒值，ChatGPT 灯仅表示隧道通路就绪。终端通过现有 `snapshot` 与 `request_detail` 增量读取；后端未记录 stdout/stderr 的逐块统一时间戳，不能恢复两路输出之间精确的原始交错顺序。风险颜色只作提示，放行依据仍是后端策略。

请求与历史保持当前进程范围。实时终端载入活跃请求和最近 24 条完成请求，其余请求仍可在记录抽屉查看。

## 验证

```powershell
cd frontend
npm test
npx playwright install chromium
npm run test:ui
```

先在项目根目录完成 `uv sync --locked`。UI 测试加载正式编译资源并调用真实 DesktopAPI/ApprovalManager；SSH、隧道、凭据和文件对话框均为 fixture，不连接真实服务器或账号。可通过 `SSH_UI_CHROME` 指定浏览器，通过 `SSH_UI_PYTHON` 指定测试 Python。

源码按桥接类型、轮询输出、场景、终端、闸门、工作抽屉和配置抽屉分文件组织。界面状态由 React 维护，Canvas 与按住计时使用独立帧循环；数据内容均按文本渲染。
