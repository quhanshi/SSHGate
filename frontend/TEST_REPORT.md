# React 场景前端验证

验证日期：2026-10-01。范围：新 React 前端及与原 DesktopAPI 的兼容性。

## 结果

| 检查 | 结果 |
| --- | --- |
| 严格 TypeScript 检查与正式 Vite 构建 | 通过 |
| 前端单元测试 | 6 项通过 |
| 正式编译资源的界面交互测试 | 25 项通过，浏览器页面异常 0 项 |
| 原后端回归测试 | 共 127 项：125 项通过、2 项跳过 |
| 原 `ssh_gate` Python 文件逐字节比较 | 全部一致 |

## 交互覆盖

审批包括普通 / 破坏性时长、提前松开、键盘切换、窗口失焦、指针离开、单次票据与拒绝；节点包括过滤与上下文菜单。命令面板验证键盘搜索服务器及打开文件抽屉。

原有能力覆盖 known_hosts、主机指纹确认、本地密码输入、SSH config 跳板预览、服务器策略、目录搜索、读取、下载、上传审批、受控会话、代理检测与采用、隧道启动停止、运行密钥清空、MCP 启停及设置持久化。

边界包括 HTML 样式输出按文本显示、跨行私钥脱敏、选择复制对应原文、1,200 条重复输出准确折叠计数、分页详情、900 条不同输出时终端不超过 500 行且地形缓冲不超过 80 行。标准 / 低 / 关、关档静态 Canvas、减少动态效果、960px 窗口及 130% 字体缩放均已检查。

## 环境与未验证范围

UI 测试在 Linux 的 Chromium 153.0.8010.0 中加载正式编译资源，并通过 stdio 桥调用原 Python DesktopAPI / ApprovalManager。未连接真实 SSH 服务器、真实隧道或 OpenAI 账号，未在 Windows WebView2 中执行，也未生成新的 Windows EXE。

原后端的两个 Linux 子进程终止测试因当前环境的 PID 命名空间与 `/proc` 不一致跳过；原因由原测试记录。其余后端测试通过。完整 UI 检查名称保存在 `preview/ui-test-result.json`。

## 复验

项目根目录先运行 `uv sync --locked`。随后：

```powershell
cd frontend
npm ci
npm run build
npm test
npx playwright install chromium
npm run test:ui
```

如需指定已安装的浏览器或 Python，可设置 `SSH_UI_CHROME`、`SSH_UI_PYTHON`；截图输出可用 `SSH_UI_OUTPUT` 指定。前端构建不会改写任何后端 Python 模块。
