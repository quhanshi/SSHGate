# React 场景前端替换包

保留原设计：Canvas 代码地形、服务器粒子节点、只读实时终端、链路 HUD、按住审批闸门、Ctrl+K 与工作抽屉。实现使用 React + TypeScript + Vite，调用原有 pywebview DesktopAPI。

## 安装

1. 关闭应用。
2. 将压缩包中 `SSHGate` 文件夹的内容复制到原项目根目录，合并文件夹并覆盖同名文件。
3. 本包包含前端、前端构建脚本、测试和说明，不包含后端业务代码、个人配置、日志或 EXE。
4. **如果已有 `dist\SSHGate\SSHGate.exe`，先运行原项目的 `Build-App.cmd` 重新构建，再运行 `Start-App.cmd`。** 原启动脚本会优先启动已有 EXE，覆盖源码资源不会更新旧 EXE 内的界面。
5. 尚未构建 EXE 时，直接使用原项目的 `Start-App.cmd`，它会启动 Python 源码应用。

已附正式编译的 HTML / JS / CSS，运行应用及重新打包 EXE 不需要 Node.js。仅修改 React 源码后才需 Node.js 22.18+ 或 24 LTS，运行新增的 `Build-Frontend.cmd`，然后重启源码应用或重新构建 EXE。

## 使用

- 单击节点过滤终端；再点一次恢复全部。右键打开文件、会话、策略与断开操作。
- 普通请求按住 1 秒批准；破坏性请求按住 1.5 秒。计时从收到有效审批票据后开始；提前松开、离开按钮、切换请求、窗口失焦或隐藏会取消。
- `J/K` 选择待审请求，按住 `A` 批准，`R` 拒绝，`Enter` 查看详情。
- `Ctrl+K` 搜索操作、服务器与本次运行的历史请求，`Esc` 关闭。
- 悬停或向上滚动暂停终端跟随；显示脱敏，选中复制保留对应原文。
- 特效提供关 / 低 / 标准；系统减少动态效果会将标准降为低。最小宽度 960px，低于 1280px 闸门折叠，新请求自动展开。

## 交付与验证

- `frontend/`：React 源码、锁定依赖、构建脚本、单元测试和详细说明。
- `ssh_gate/frontend/`：供原 Python 应用直接加载的编译资源。
- `tests/`：正式资源与真实 DesktopAPI 的界面测试；SSH、隧道和本地文件对话框使用隔离 fixture。
- `preview/scene-*.png`：本次运行截图；`preview/ui-test-result.json`：25 项界面检查结果。
- `frontend/TEST_REPORT.md`：验证结果及环境边界。
- `frontend/THIRD_PARTY_NOTICES.txt`：编译资源中 React / React DOM / Scheduler 的许可。
- `frontend/DELIVERY_MANIFEST.json`：本包文件的 SHA256。

本次同步完成 Python 包、构建、启动和 MCP 服务标识的 SSH Gate 重命名；后端业务接口、SSH 执行、审批策略与隧道行为未改变。

现有后端没有持续 SSH 延迟与 ChatGPT 会话心跳，因此节点显示真实连接状态，未填入模拟毫秒值。实时输出通过现有分页接口增量读取；stdout / stderr 的原始精确交错顺序无法由当前接口恢复。详见 `frontend/README.md`。
