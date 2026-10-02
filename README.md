# p2p-friend

`p2p-friend` 是一个面向两端直接文件传输的交互式 P2P 命令行工具，操作方式接近 SFTP。

v0.7 将数据面升级为 **QUIC/UDP + TLS 1.3 + 多 stream**。程序同时收集 IPv6、IPv4 与 STUN 映射候选，在同一个真实 UDP socket 上进行 IPv6 直连或 IPv4 UDP hole punching；QUIC 直接接管该 socket，从而在支持的平台上保留批量收包、ECN、PMTU 与 Linux UDP GSO 等内核优化。项目不配置 TURN / relay。

## 功能

- Linux / Windows x86-64
- IPv6 ↔ IPv6 UDP 直连
- IPv4 ↔ IPv4 STUN 辅助 UDP NAT 打洞
- QUIC TLS 1.3 加密、可靠重传与拥塞控制
- 1 条 QUIC 控制 stream + 4 条并行 QUIC data stream
- 文件和目录递归传输
- 双向 `put` / `get`
- 远端目录浏览与切换
- 本地 / 远端路径 Tab 补全
- 绝对路径、中文和空格路径支持
- 发送前 SHA-256 计算
- 接收落盘后重新 SHA-256 校验
- `Ctrl-C` 仅取消当前传输，不退出会话

> v0.7 使用 `P2P7-OFFER-...` / `P2P7-ANSWER-...` 信令码，与旧版网络协议不兼容。双方需要使用 v0.7.x。

## 连接流程

v0.7 不需要自建信令服务器。双方通过已有聊天工具手工交换一次 OFFER / ANSWER。

### 创建会话

启动后选择：

```text
1) 创建会话（生成 OFFER）
```

程序收集本机 IPv4 / IPv6 与 STUN 候选，然后输出：

```text
P2P7-OFFER-...
```

将 OFFER 发给另一方。另一方会返回：

```text
P2P7-ANSWER-...
```

将 ANSWER 粘贴回创建方。只有 UDP 路径、QUIC TLS 1.3、会话认证和全部 QUIC stream 建立成功后才进入命令行。

### 加入会话

选择：

```text
2) 加入会话（输入 OFFER / 生成 ANSWER）
```

粘贴 OFFER，程序生成 ANSWER。将 ANSWER 发回创建方，然后等待 UDP 打洞/直连和 QUIC 握手完成。

## 网络模型

v0.7 的数据链路：

```text
IPv6 / IPv4 candidates
        ↓
STUN 映射（IPv4 NAT 场景）
        ↓
同时 UDP hole punching
        ↓
同一个 *net.UDPConn
        ↓
quic-go Transport
        ↓
QUIC TLS 1.3 + loss recovery + congestion control
        ↓
control stream + 4 data streams
```

STUN 只用于发现公网 UDP 映射，不承载文件数据；打洞和 QUIC 使用同一个 UDP socket，因此不会出现“STUN 映射端口和实际传输端口不同”的问题。

IPv6 有可达的 global address 时会直接尝试 QUIC/UDP；IPv4 则同时尝试本地 candidate 与 STUN 映射 candidate。当前仍然不配置 TURN / relay，所有 candidate 都失败时会明确报错。后续 NAT 兼容性可以继续单独增强，不影响 QUIC 文件传输层。

## QUIC 多 stream 与大文件

单个文件按 offset 切成块，由 4 个 worker 同时投递到 4 条独立 QUIC bidirectional stream：

```text
file
 ├─ offset 0       -> data stream 0
 ├─ offset N       -> data stream 1
 ├─ offset 2N      -> data stream 2
 ├─ offset 3N      -> data stream 3
 └─ ...

receiver -> WriteAt(offset) -> .part
```

它和多线程下载的思路相近，但所有 stream 共享一个 QUIC connection 和一个 UDP socket，不需要额外创建多个公网端口。QUIC 负责 ACK、丢包重传、RTT、拥塞控制和流量控制；应用层只负责 chunk 调度、offset 写盘和最终 SHA-256。

应用层数据块提高到 256 KiB；QUIC 再根据 PMTU 分包。在 Linux 和内核支持时，quic-go 直接使用真实 `*net.UDPConn` 可利用 UDP GSO 等内核优化；不支持时自动退回普通 UDP 发送路径。

## 文件完整性

每个文件都执行独立端到端校验：

1. 发送端传输前完整读取文件并计算 SHA-256。
2. 文件块通过多条 data stream 发送。
3. 接收端按 offset 写入 `.part` 临时文件。
4. 所有数据落盘后，接收端重新完整读取临时文件计算 SHA-256。
5. 两端 SHA-256 完全一致后才重命名为最终文件并报告完成。
6. 校验失败、取消或传输异常时不会报告成功，并会尽量清理临时内容。

典型输出：

```text
[HASH] file.bin  SHA-256 <sender-hash>
[VERIFY] /path/to/file.bin  SHA-256 <receiver-hash>  OK
```

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

上传：

```text
put <local-path> [remote-path]
```

下载：

```text
get <remote-path> [local-path]
```

目录会递归传输，远端路径可以使用绝对路径。

## Tab 补全

```text
cd / ls / get          -> 远端路径
lcd / lls              -> 本地路径
put 第 1 个路径参数    -> 本地路径
put 第 2 个路径参数    -> 远端路径
get 第 2 个路径参数    -> 本地路径
overwrite              -> on / off
```

包含空格的路径会自动加引号，中文路径无需额外转义。

命令行编辑还支持：

```text
Left / Right           移动光标
Up / Down              浏览命令历史
Ctrl-A / Ctrl-E        跳到行首 / 行尾
Ctrl-L                 清屏并重绘
Ctrl-C                 取消当前传输；没有传输时清空当前输入
Tab                    路径 / 参数补全
```

## 取消传输

传输过程中按 `Ctrl-C`，或者执行：

```text
cancel
```

只取消当前传输，不关闭 P2P 会话。

接收取消时，程序会尝试删除当前 `.part`、本次新建的文件和本次新建的空目录。自动清理失败时会输出具体路径。

## 覆盖策略

默认禁止覆盖本机已有接收文件：

```text
overwrite off
```

允许覆盖：

```text
overwrite on
```

## 安全模型

- STUN 只用于发现 IPv4 NAT 映射，不承载文件数据
- QUIC 使用 TLS 1.3 保护连接，并负责可靠重传、拥塞控制和流量控制
- 会话信令码包含随机 256-bit token
- QUIC 服务端临时证书通过 OFFER 中的 SHA-256 fingerprint 固定校验
- 1 条 control stream + 4 条 data stream 复用同一个 QUIC/UDP 连接
- 每个文件额外执行 SHA-256 端到端校验
- 接收文件先写 `.part`，校验成功后再重命名
- 默认拒绝通过符号链接写入目标路径

成功连接的一方可以在对方当前系统用户权限范围内浏览、读取和写入文件系统。连接码属于临时访问凭据，只应发送给可信任的人。

## 从源码构建

要求 Go 1.23 或兼容版本。

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
```

Linux：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o p2p-friend-linux-amd64 .
```

Windows：

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o p2p-friend-windows-amd64.exe .
```

## Release

仓库根目录的 `VERSION` 保存当前发布版本。包含新版本号的 PR 合并到 `main` 后，GitHub Actions 会自动运行测试、构建 Linux / Windows 二进制、创建版本 Tag、生成 `SHA256SUMS.txt` 并发布 GitHub Release。
