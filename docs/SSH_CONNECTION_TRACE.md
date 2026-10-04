# SSH 连接事件与界面状态

本文定义 **SSH Gate 1.0.0** 的 SSH 连接事件契约，以及前端如何把真实连接状态映射到 UI。

## 设计原则

SSH Gate 直接观察实际 Paramiko/OpenSSH 路由执行过程，不额外建立“诊断用 SSH 连接”，也不伪造 `ssh -vvv` 文本。

前端遵循三条规则：

1. 协议阶段由真实事件驱动，不用计时器虚构进度。
2. 跳板、目标和重试分别建模，不把跳板成功当成目标成功。
3. 连接动画只负责展示已经观测到的状态，不参与协议和安全判断。

## 接口字段

`DesktopAPI.request_detail` / 管理器请求详情包含：

| 字段 | 含义 |
| --- | --- |
| `connection_trace_version` | 当前协议版本，1.0.0 中为 `1` |
| `connection_events` | 按 `seq` 排序的连接事件，最多保留最近 256 条 |
| `connection_event_seq` | 当前请求最后一个事件序号；没有事件时为 0 |
| `connection_events_dropped` | 因容量上限被丢弃的早期事件数量 |

轻量快照只携带 `connection_event_seq`，不反复传输整个事件数组。前端发现序号变化后再读取详情。

事件示例：

```json
{
  "seq": 8,
  "event": "algorithms_negotiated",
  "stage": "key_exchange",
  "attempt": 1,
  "at": "2026-10-04T12:00:00.123+00:00",
  "elapsed_ms": 123.456,
  "hop_elapsed_ms": 123.456,
  "connection_context": {
    "host_alias": "example",
    "hostname": "example.invalid",
    "port": 22,
    "role": "target",
    "hop_index": 1,
    "hop_count": 1,
    "via_host_alias": null
  },
  "data": {
    "kex": "curve25519-sha256@libssh.org",
    "host_key_algorithm": "rsa-sha2-512",
    "cipher_out": "aes128-ctr",
    "cipher_in": "aes128-ctr",
    "mac_out": "hmac-sha2-256",
    "mac_in": "hmac-sha2-256"
  }
}
```

字段语义：

- `at`：UTC 时间。
- `elapsed_ms`：当前路由从开始处理起的单调时钟耗时，包含跳板、重试和等待本地输入，不含请求审批排队。
- `hop_elapsed_ms`：当前跳的累计耗时。
- `attempt`：当前跳的连接尝试编号；复用连接时为 0。
- `connection_context.role`：`jump` 或 `target`。
- cipher/MAC 的方向以客户端为参照。
- `key_type` 表示服务端公钥格式，`host_key_algorithm` 表示实际握手协商算法，两者不能混为同一字段。

## 事件

| 事件 | 含义 |
| --- | --- |
| `connection_started` | 开始处理当前一跳，并检查连接复用 |
| `connection_reused` | 已有连接仍活动且已认证；不会补发不存在的新握手事件 |
| `attempt_started` | 开始新的连接尝试 |
| `credentials_required` | 等待本地密码/私钥口令 |
| `saved_credential_selected` | 选中本机已保存凭据，只暴露凭据模式 |
| `dns_started` / `dns_resolved` | 本机 DNS 开始/完成 |
| `tcp_started` / `tcp_connected` | TCP 候选地址开始/成功 |
| `tcp_address_failed` | 单个地址失败，后续仍可能尝试其他地址 |
| `jump_channel_started` / `jump_channel_opened` | ProxyJump `direct-tcpip` 开始/完成 |
| `proxy_started` / `proxy_process_started` | 本地 ProxyCommand 开始/子进程已启动 |
| `ssh_handshake_started` | 开始 SSH 协议握手 |
| `banner_received` | 收到并校验协议版本串 |
| `key_exchange_started` | 进入密钥交换 |
| `algorithms_negotiated` | KEX、主机密钥、cipher、MAC 等已确定 |
| `host_key_received` | 收到服务端公钥，此时尚不代表已信任 |
| `host_key_confirmation_required` | 未知主机，等待本地用户确认 |
| `host_key_verified` | known_hosts / 本次信任 / 保存信任校验通过 |
| `authentication_started` | 开始用户认证 |
| `authentication_method_started` | 开始具体认证方式 |
| `authentication_method_failed` | 当前方式失败，仍可能尝试其他方式 |
| `authentication_partial` | 仍需继续认证 |
| `authenticated` | Transport 确认认证完成 |
| `authentication_retry` | 准备下一次认证尝试 |
| `connected` | 当前一跳已认证并进入可复用连接池 |
| `connection_failed` | 当前一跳最终失败 |
| `connection_cancelled` | 用户取消或流程被终止 |

`connected` 只表示 **SSH 连接成功**。`test_connection` 随后仍会检查 SFTP 和默认 cwd；后续诊断失败时，UI 应同时保留“SSH 已连接”和“后续诊断失败”两个事实。

## 阶段与失败分类

后端阶段值：

```text
connecting
 dns
 tcp
 proxy
 ssh_banner
 key_exchange
 host_key
 authentication
 connected
```

前端正式 UI 标签：

```text
DNS 解析
TCP 连接
SSH 握手
密钥交换
主机核验
身份认证
已连接
```

常见失败分类：

- `dns_failed`
- `connection_refused`
- `timeout`
- `connection_lost`
- `algorithm_mismatch`
- `protocol_mismatch`
- `host_key_mismatch`
- `host_key_rejected`
- `authentication_failed`
- `proxy_failed`
- `ssh_error`
- `connection_error`
- `cancelled`

未知异常保持通用分类，不根据错误文本猜测成超时或算法冲突。指纹不匹配可以返回实际/期望 SHA256 指纹，但不能泄露密码、私钥内容或认证参数。

## 前端状态映射

主要源码：

- `frontend/src/connection.ts`：事件归约、阶段、失败说明、跳板和尝试隔离。
- `frontend/src/fingerprint.ts` / `components/Fingerprint.tsx`：OpenSSH randomart 算法和 SVG 指纹图。
- `frontend/src/orbitDrawing.ts` / `components/Scene.tsx`：连接路径、途中节点和服务器绘制。
- `components/OrbitPanel.tsx` / `orbit.css`：SSH 连接状态、协议元数据和连接事件列表。
- `useDesktop.ts` / `App.tsx`：快照轮询与详情刷新。

`OrbitPanel`、`orbitDrawing` 等仍是内部源码名称；正式 UI 和长期文档统一使用“SSH 连接状态”“连接事件”等业务术语。

### 状态规则

- 收到服务端公钥不等于信任通过；只有 `host_key_verified` 后才显示已核验。
- 每次重试会清理上一尝试的临时指纹/认证状态。
- ProxyJump 的跳板成功只标记途中节点，不点亮目标服务器。
- `connection_reused` 直接显示复用结果，不重放 DNS/TCP/握手阶段。
- TCP 多地址中的单个失败属于非终态，只有最终失败事件才结束当前跳。
- 取消、终止和最终失败不会补全未发生的成功阶段。
- 连接事件按 `seq` 去重并排序；详情暂未跟上轻量快照时等待下一次轮询，不推测缺失事件。

## 指纹图

前端从标准 SHA256 主机指纹生成与 OpenSSH randomart 兼容的 17 × 9 图形。该图只提供视觉辅助，不能替代完整 SHA256 指纹核验。

无效或不支持的指纹不会生成伪造图形。

## 动效边界

连接路径可以在相邻已观测状态之间做短插值，但：

- 不以定时器推进协议阶段；
- 不显示虚构的百分比；
- 关闭特效时保持静态状态；
- 系统启用“减少动态效果”时关闭非必要插值、呼吸和回弹。

快速握手可能在一次 UI 轮询间完成多个阶段，因此画面不保证逐帧播放每一步；事件记录仍保留实际序列。

## 维护注意

SSH 观测层依赖 Paramiko 4.x 的部分 Transport/SSHClient 内部挂接点，但这些挂接始终调用原实现完成协议和安全校验。升级 Paramiko 时必须运行 SSH 专项协议测试，重点确认：

- 版本串与密钥交换顺序；
- 算法结果字段；
- 未知主机确认和指纹不符；
- 密码/私钥/agent 认证；
- ProxyJump 逐跳归属；
- 连接复用与失败分类。
