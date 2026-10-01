# p2p-friend

`p2p-friend` 是一个面向两端直接文件传输的交互式 P2P 命令行工具，操作方式接近 SFTP。

v0.6 将网络层升级为 **UDP + ICE + DTLS + SCTP DataChannel**。程序同时收集 IPv6、IPv4 与 STUN server-reflexive 候选，通过 ICE 选择能够直接通信的 UDP 路径；IPv4 位于常见 NAT 后时会尝试 UDP hole punching。项目不配置 TURN / relay，文件数据不会经过应用层中继服务器。

## 功能

- Linux / Windows x86-64
- IPv6 ↔ IPv6 UDP 直连
- IPv4 ↔ IPv4 STUN / ICE NAT 打洞
- DTLS 加密与 SCTP 可靠传输
- 1 条控制 DataChannel + 4 条并行数据 DataChannel
- 文件和目录递归传输
- 双向 `put` / `get`
- 远端目录浏览与切换
- 本地 / 远端路径 Tab 补全
- 绝对路径、中文和空格路径支持
- 发送前 SHA-256 计算
- 接收落盘后重新 SHA-256 校验
- `Ctrl-C` 仅取消当前传输，不退出会话

> v0.6 使用 `P2P6-OFFER-...` / `P2P6-ANSWER-...` 信令码，与旧版网络协议不兼容。双方需要使用 v0.6.x。

## 连接流程

v0.6 不需要自建信令服务器。双方通过已有聊天工具手工交换一次 OFFER / ANSWER。

### 创建会话

启动后选择：

```text
1) 创建会话（生成 OFFER）
```

程序收集本机 IPv4 / IPv6 与 STUN 候选，然后输出：

```text
P2P6-OFFER-...
```

将 OFFER 发给另一方。另一方会返回：

```text
P2P6-ANSWER-...
```

将 ANSWER 粘贴回创建方。只有 ICE、DTLS、会话认证和全部 DataChannel 建立成功后才进入命令行。

### 加入会话

选择：

```text
2) 加入会话（输入 OFFER / 生成 ANSWER）
```

粘贴 OFFER，程序生成 ANSWER。将 ANSWER 发回创建方，然后等待 ICE 连接建立。

## 网络模型

ICE 会自动尝试可用的 UDP candidate pair：

```text
IPv6 host candidate
IPv4 host candidate
IPv4 server-reflexive candidate (STUN)
```

IPv4 位于 NAT 后时，STUN 只用于发现公网映射地址，ICE 会同时执行 UDP connectivity checks，从而尝试 hole punching。公共 STUN 不承载文件内容。

项目没有配置 TURN。若双方 NAT / 防火墙组合无法建立直接 UDP 路径，程序会明确连接失败，不会退回中继。

## 传输模型

底层链路：

```text
UDP
  -> ICE
  -> DTLS
  -> SCTP DataChannel
  -> p2p-friend protocol
```

UDP 本身允许丢包，但 DataChannel 使用可靠 SCTP 传输，因此丢失的数据会自动重传。程序不会把缺失数据当作成功文件。

v0.6 建立：

```text
control
data-0
data-1
data-2
data-3
```

`control` 用于命令与传输元数据。单个大文件按 offset 分块后在 4 条数据 stream 上并行发送，接收端按 offset 写入同一个临时文件。

这些逻辑 stream 共享同一 ICE/UDP P2P 路径，不强制创建多个公网 UDP 端口，从而减少 NAT 映射数量并优先保证打洞稳定性。多 stream 用于减少单一有序数据流的队头阻塞和提高并行处理能力，但不会突破物理带宽上限。

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

- ICE 只负责建立点对点 UDP 路径
- DTLS 保护链路
- 会话信令码包含随机 256-bit token
- control DataChannel 使用可靠有序模式
- 4 条 data DataChannel 使用可靠乱序模式
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
