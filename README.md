# p2p-friend

`p2p-friend` 是一个面向两端直接文件传输的交互式 P2P 命令行工具，使用方式接近 SFTP。

文件数据通过 **UDP + QUIC** 在两个端点之间直接传输。程序会收集 IPv6、IPv4、多 STUN 映射和可用的 PCP/NAT-PMP/UPnP 端口映射候选；双方同时 QUIC Listen + Dial，并通过带 HMAC 的 UDP punch 学习真实 peer-reflexive 地址。不配置 TURN / relay。

当前网络实现**不是 WebRTC/ICE/DataChannel**：`pion/stun` 只用于 IPv4 STUN 映射发现，实际会话与文件数据由 `quic-go` 的 QUIC/TLS 1.3 承载；项目不使用 TURN 中继。

## 功能

- Linux amd64 / arm64（aarch64）
- Windows amd64
- macOS amd64 / arm64
- IPv6 UDP 直连，并由双方主动发送 UDP 探测以尽量打开有状态 IPv6 防火墙
- IPv4 UDP 直连 / LAN / Multi-STUN 辅助 NAT 打洞
- 安全 UDP punch：session HMAC、时间戳、nonce 重放过滤和 peer-reflexive candidate
- PCP / NAT-PMP / UPnP IGD 显式 UDP 端口映射（可选增强，失败自动降级）
- IPv6 不做地址转换映射；双方通过安全 UDP punch 尽量打开 stateful firewall
- QUIC TLS 1.3、可靠重传、拥塞控制和多 stream
- 1 条主 QUIC（control + 1 data stream）+ 最多 3 条独立 data-only QUIC connection
- v14 多 QUIC striping：最多 4 条独立 QUIC data path、1 MiB pooled chunk、动态共享队列、有界内存重排
- 会话级单传输仲裁：同一时刻只运行一个文件或目录传输任务
- 文件和目录递归传输
- 双向 `put` / `get`
- 远端目录浏览与切换
- 绝对路径、中文和空格路径支持
- 本地 / 远端路径 Tab 补全
- 发送端与接收端 SHA-256 校验
- `Ctrl-C` 只取消当前传输，不退出会话
- `status` 显示实际 QUIC / UDP 链路、端口、候选和传输状态

当前协议使用两类按“用途”命名的识别码：`P2PF-INVITE-...` 是创建方发给对方的**邀请码**，收到后选择“加入连接”；`P2PF-REPLY-...` 是加入方在需要双向 NAT 打洞时发回创建方的**回传码**。

## 建立连接

启动后选择：

```text
1) 创建连接（生成 P2PF-INVITE 邀请码）
2) 加入连接（输入 P2PF-INVITE 邀请码）
3) 退出
```

当前连接流程固定先交换两类识别码，再开始真实 QUIC 建连：

```text
创建方 -> P2PF-INVITE -> 加入方
创建方 <- P2PF-REPLY  <- 加入方
                  ↓
         双方 candidate 已完整交换
                  ↓
      双方同时 QUIC Listen + Dial
                  ↓
 IPv6 / portmap / STUN / host candidates 竞争
                  ↓
 安全 punch 可动态学习 prflx 真实端点
                  ↓
                 QUIC
```

这样不再存在“先尝试 4 秒直连、失败后才显示回传码”的启发式状态机，也避免连接后台握手和用户粘贴回传码同时发生造成的 UI/时序问题。

邀请码和回传码本身都已经是紧凑二进制格式，第二次复制的成本较低。这个固定两步流程换来的是更简单、可预测的连接状态：

- 创建方拿到 `P2PF-REPLY` 前不会开始真实 QUIC 建连。
- 加入方生成并显示 `P2PF-REPLY` 后进入静默等待；创建方粘贴回传码后开始连接。
- 双方都有 globally routable IPv6 时，连接器给 IPv6 一个很短的优先窗口，通常选择 `IPv6-DIRECT`。
- 双方都会主动向对端 IPv6 candidate 发送 UDP 探测；若有状态防火墙允许匹配的返回流量，IPv6 可以继续建立 QUIC。仍不可达时 IPv4 candidate 自动接管，不需要重新交换识别码。
- IPv4 NAT 场景会使用多个 STUN 观察值、host/portmap candidate，并从通过认证的 punch 中动态学习 prflx endpoint。

识别码前缀直接表示用途：收到 `P2PF-INVITE-...` 时选择“加入连接”；收到 `P2PF-REPLY-...` 时说明自己是创建方，应把它粘贴到创建端。

连接过程中的 candidate retry 保持静默。创建/加入角色不再固定 QUIC 握手方向；只有所有直接路径最终都失败时才报告当前 NAT/防火墙没有形成可用直连路径。

## 紧凑识别码

v0.11 将识别码内部从 JSON 改为紧凑二进制格式，再使用 URL-safe Base64 编码。

候选地址不再以字符串和字段名重复保存：

- IPv4 使用 4-byte 地址 + 2-byte 端口。
- IPv6 使用 16-byte 地址 + 2-byte 端口。
- candidate 类型与地址族压缩到标志位。
- 相同 IP:port 的重复 candidate 会合并；若同一 endpoint 同时表现为 host 和 STUN 映射，优先保留 host。
- 继续完整保留 256-bit 会话 token 和 SHA-256 证书指纹，不通过削弱安全参数来缩短识别码。
- loopback、link-local、unspecified 等明显不可用于公网连接的地址不会进入识别码。

因此相比旧版 Base64(JSON)，同样数量的 IPv4 / IPv6 candidate 会明显更短，也更适合在聊天工具中复制。

## 链路类型

连接成功后，prompt 与 `status` 会显示实际选中的链路，例如：

```text
IPv6-DIRECT
IPv6-LAN
IPv4-DIRECT
IPv4-LAN
IPv4-NAT-PUNCH
IPv4-PORTMAP
```

例如：

```text
p2p[IPv4-NAT-PUNCH remote:/path]>
```

`NAT-PUNCH` 表示 UDP NAT hole punching。它不是 TUN；TUN 通常指操作系统虚拟三层网络接口。

## 传输模型

v0.14 在 v0.13 的有界内存流水线上进一步把网络并行从“同一个 QUIC connection 的多 stream”提升为**多个独立 QUIC connection**。

主连接建立并完成 TLS / session-token 认证后，主连接的 dialer 会额外建立最多 3 条 data-only QUIC connection。v0.14.1 起这些 stripe **优先使用独立 UDP source port**，从而形成不同 UDP 5-tuple；目标 endpoint 仍复用主连接已经验证可达的地址，因此不需要重新执行 STUN、punch 或端口映射。若独立 source port 不可用，会自动回退到 v0.14.0 的共享 UDP socket 模式。

```text
主 QUIC UDP port        stripe UDP port #1     stripe UDP port #2/#3
       │                        │                       │
主 QUIC connection       data QUIC #1         data QUIC #2/#3
control + data stream       data stream           data stream
       │                        │                       │
       └─────────────── shared chunk queue ────────────┘
                              │
                    1 MiB pooled chunks
```

每条 QUIC connection 有独立的 QUIC connection state / congestion state。发送端仍然只顺序读取文件一次并同步计算 SHA-256；chunk 进入共享队列后，由当前空闲的 data-connection worker 动态领取，因此较快的连接自然承担更多 chunk，不再做固定 round-robin。

接收端每条 data QUIC 都有独立 reader，但最终仍进入统一的有界 reorder window。v0.14.1 会按文件大小在 64 / 128 / 256 MiB 三档中选择窗口，避免某条 UDP flow 短时变慢后过早把其它 flow 全部反压停住，同时仍保持固定硬上限：

```text
4 x QUIC data readers
          │
          ▼
有界 reorder window（约 64 MiB）
          │
连续 offset 顺序输出
          │
SHA-256 + 顺序 file.Write
          │
OS page cache / dirty pages
          │
磁盘后台 writeback
```

用户态缓存不会随文件大小增长。窗口满后停止继续消费 QUIC data stream，由 QUIC flow control 向发送端施加 backpressure。

application data chunk 仍为最大 1 MiB。QUIC 会按路径 MTU 自动拆包；1 MiB 是应用层 chunk，不是 1 MiB UDP datagram。

如果额外 data QUIC 无法全部建立，主会话不会失败，会自动使用已经成功建立的数据连接继续传输。v0.14.1 与 v0.14.0 保持 v14 wire protocol 兼容。

### 单传输模式

一个 P2P 会话在同一时刻只允许一个 `put` 或 `get` 任务占用传输通道。

如果一端正在传输，另一端再执行新的 `put` / `get`，会直接返回“当前已有传输任务”，不会启动第二条并发文件任务。

这个限制只针对文件传输。传输期间仍可在空闲的一端执行 `status`、目录浏览等控制命令。

## 进度与完整性

只有**发起当前文件操作的一端**显示正常传输进度。被动提供文件或被动接收文件的一端保持安静，避免异步日志打断命令输入。

单文件下载示例：

```text
[GET] file.bin -> /local/path/file.bin (1.0 GiB)
[GET] file.bin                      73.42%  751.8 MiB / 1.0 GiB  42.1 MiB/s
[GET] SHA-256 <hash>  OK
[GET] 完成。
```

目录下载会同时显示“当前文件”和“目录总计”，不会再把目录总大小显示成当前文件大小：

```text
[GET] dir/video.mkv  63.20%  1.9 GiB / 3.0 GiB | 总计 27.40%  4.8 GiB / 17.5 GiB  92.1 MiB/s
```

传输中的进度使用同一终端行刷新；只有当前文件真正完成、切换到下一个文件时才换行。

每个文件都执行端到端校验：

1. 发送端顺序读取文件时同步计算 SHA-256，并把同一份数据送入 QUIC pipeline。
2. 数据通过多条 QUIC stream 发送。
3. 接收端在有界内存中按 offset 重排，只把连续数据顺序写入 `.part`。
4. 接收端顺序写入时同步计算 SHA-256，不再重新读取整个临时文件。
5. 两端 SHA-256 完全一致后才重命名最终文件并报告完成。

## status

执行：

```text
status
```

会显示包括：

- 本机连接角色（创建方 / 加入方）
- 实际链路类型
- QUIC / UDP / TLS 1.3 传输栈
- 本机当前选中的 UDP socket
- 对端当前 UDP endpoint
- QUIC 是监听端还是主动连接端
- IPv4 / IPv6 UDP socket 与监听 / 打洞状态
- 本机 STUN 映射（IPv6 链路时明确标为 IPv4 备用）
- NAT 映射稳定性与显式端口映射信息
- 对端 candidate 类型（HOST / STUN / prflx / portmap）
- 主 QUIC / data stripe connection 数量与 data stream 数量
- 当前是否存在文件传输任务
- 当前发送流水线参数（存在发送任务时）
- 本地 / 远端目录与覆盖策略

连通性检查、NAT 打洞、QUIC 握手和文件传输复用选中的 UDP socket，不额外建立 TCP 文件通道。

## 命令

远端文件系统：

```text
pwd
ls [remote-path]
cd <remote-path|->
```

本地文件系统：

```text
lpwd
lls [local-path]
lcd <local-path|->
```

上传 / 下载：

```text
put <local-path> [remote-path]
get <remote-path> [local-path]
```

其他：

```text
cancel
overwrite on|off
status
help
quit
```

## Tab 补全

```text
cd / ls / get          -> 远端路径
lcd / lls              -> 本地路径
put 第 1 个路径参数    -> 本地路径
put 第 2 个路径参数    -> 远端路径
get 第 2 个路径参数    -> 本地路径
```

包含空格的路径会自动加引号，中文路径无需额外转义。

## 从源码构建

要求 Go 1.26 或兼容版本。

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
```

Linux amd64：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o p2p-friend-linux-amd64 .
```

Linux arm64 / aarch64：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o p2p-friend-linux-arm64 .
```

Windows amd64：

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o p2p-friend-windows-amd64.exe .
```

macOS Intel：

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o p2p-friend-darwin-amd64 .
```

macOS Apple Silicon：

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o p2p-friend-darwin-arm64 .
```

## Release

仓库根目录的 `VERSION` 保存当前发布版本。版本 PR 合并到 `main` 后，GitHub Actions 自动测试并发布：

```text
p2p-friend-linux-amd64
p2p-friend-linux-arm64
p2p-friend-windows-amd64.exe
p2p-friend-darwin-amd64
p2p-friend-darwin-arm64
SHA256SUMS.txt
```

## 安全

- STUN 只用于发现 IPv4 NAT 映射，不承载文件数据。
- QUIC 使用 TLS 1.3 保护链路。
- 连接码包含随机会话 token 和临时证书指纹。
- 文件执行 SHA-256 端到端校验。
- 接收文件先写 `.part`，校验成功后再重命名。
- 成功连接的一方可以在对方当前系统用户权限范围内浏览、读取和写入文件系统。

连接码属于临时访问凭据，只应发送给可信任的人。


## 稳定识别码协议（v0.15+）

v0.15 起外部前缀长期固定为 `P2PF-INVITE-` / `P2PF-REPLY-`。内部不使用 JSON，也没有引入 protobuf 依赖，而是采用更紧凑的稳定 binary envelope：

```text
envelope-version
kind
capability bitmap (uvarint)
candidate count
INVITE: 32-byte session token
REPLY:  16-byte session binding
32-byte TLS certificate fingerprint
length-prefixed candidate records
extension area
```

HOST candidate 会携带网卡 prefix length（例如 IPv4 /24、IPv6 /64），用于给可能的 LAN 路径提供短暂优先级。前缀重叠本身不再被视为“已确认同一局域网”，因为不同 NAT 后的家庭网络经常同时使用 192.168.1.0/24 等私网。

envelope version 描述的是长期二进制格式本身，不等于产品版本号。后续产品版本新增兼容能力时通过 capability bitmap 和可跳过的 record/extension 区域协商，不再因为 v0.15.1、v0.16、v1.x 这样的产品版本变化而自动让识别码失效。

v0.15 是新的稳定协议基线，因此 v0.14.x 与 v0.15 之间不互通；从 v0.15 开始，目标是保持向前兼容。


### v0.15.1 公网/NAT 路径全并发

公网/NAT candidate 继续参与自动竞速；疑似同网段 HOST 路径只获得很短的优先窗口，不会永久屏蔽公网 fallback。stable signal envelope 继续兼容 v0.15.0。


### v0.15.2 加入方等待改为事件驱动

加入方生成 `P2PF-REPLY` 后不再立即启动 LAN/QUIC 连接超时。此时只保持 listener 和必要的低频 authenticated punch 状态，等待创建方真正开始网络活动。

加入方等待期间始终保留 listener，并低频维持必要的 NAT mapping。收到经过 HMAC/nonce/role 校验的对端活动后，切换到正常 candidate race；疑似 LAN 和公网/NAT 路径都保留自动 fallback。

因此“用户还没粘贴回传码”和“链路已经开始建立但失败”被彻底分成两个状态，不再依靠延长 timeout 猜测。


### v0.15.3 路径竞态与 LAN 误判修复

- 修复创建方 `connectQUIC()` 与加入方 `waitConn()` winner 仲裁不一致，避免一端已经开始认证时另一端把同一 QUIC 连接以 `preferred path won` 关闭。
- 私网 HOST prefix 重叠不再直接判定为“同一局域网”；例如两个不同 NAT 后都使用 `192.168.1.0/24` 时，会继续尝试公网 IPv6 / portmap / STUN / NAT punch fallback。
- 疑似 LAN HOST 仍获得很短的建连优先级，真实同局域网场景不会失去快速直连。
- data stripe 独立 UDP source port 失败时，为共享主 UDP socket fallback 预留明确时间预算，减少 `data-stripes=0` 的偶发退化。
