# p2p-friend

`p2p-friend` 是一个面向两端直接文件传输的交互式 P2P 命令行工具，操作方式接近 SFTP。

文件数据通过 **UDP + QUIC** 在两个端点之间直接传输。程序会收集 IPv6、IPv4 与 STUN 映射候选，在同一个 UDP socket 上尝试直连或 IPv4 NAT 打洞；不配置 TURN / relay。

## 功能

- Linux amd64
- Windows amd64
- macOS amd64 / arm64
- IPv6 UDP 直连
- IPv4 UDP 直连 / LAN / STUN 辅助 NAT 打洞
- QUIC TLS 1.3、可靠重传、拥塞控制和多 stream
- 1 条控制 stream + 4 条数据 stream
- 自适应 data lane / chunk / pacing
- 文件和目录递归传输
- 双向 `put` / `get`
- 远端目录浏览与切换
- 绝对路径、中文和空格路径支持
- 本地 / 远端路径 Tab 补全
- 发送端与接收端 SHA-256 校验
- `Ctrl-C` 只取消当前传输，不退出会话

## 建立连接

启动后选择：

```text
1) 发起连接（生成连接码）
2) 加入连接（输入连接码）
3) 退出
```

### 发起连接

发起方生成一个统一格式的连接码：

```text
P2PF-...
```

程序在生成连接码后立即启动 QUIC listener，不会等确认码粘贴后才开始监听。

把连接码发给另一方。另一方会返回一个同样以 `P2PF-...` 开头的确认码，将确认码粘贴回发起方即可。

### 加入连接

加入方粘贴连接码后，会生成确认码：

```text
P2PF-...
```

把确认码发回发起方。加入方的连接管理器会持续等待对端真正就绪，而不会因为一次 QUIC candidate 尝试失败就退出。

### 为什么仍然需要两次交换

项目不使用自建信令服务器。IPv4 NAT 打洞时，加入方启动后才知道自己的本地地址和 STUN 映射地址，发起方必须收到这些 candidate 才能进行双向 UDP 打洞。

因此纯手工、无信令服务器模式下，稳定的 NAT P2P 通常需要：

```text
发起方 -> 连接码 -> 加入方
发起方 <- 确认码 <- 加入方
```

`OFFER / ANSWER` 只是内部信令概念，不再暴露给日常交互。

## 连接方式显示

连接成功后，提示符和 `status` 会显示实际使用的链路，例如：

```text
IPv6-DIRECT
IPv6-LAN
IPv4-DIRECT
IPv4-LAN
IPv4-NAT-PUNCH
```

例如：

```text
p2p[IPv4-NAT-PUNCH remote:/path]> 
```

`NAT-PUNCH` 表示 IPv4 UDP NAT hole punching。这里不使用 `TUN`，因为 TUN 通常指虚拟网络接口 / 隧道设备，与 NAT 打洞不是同一个概念。

如果最终连接超时，程序才会提示尝试交换“发起连接 / 加入连接”角色；启动时不再显示固定的网络说明。

## 大文件传输

单个文件按 offset 切块，并行投递到多条 QUIC data stream：

```text
file
 ├─ chunk -> data stream 0
 ├─ chunk -> data stream 1
 ├─ chunk -> data stream 2
 └─ chunk -> data stream 3

receiver -> WriteAt(offset) -> .part
```

发送器会根据实际 QUIC `Write` 背压动态调节：

- 1~4 条 active data lane
- 32~256 KiB application chunk
- 0~2 ms pacing

持续顺畅时逐步升档；出现明显阻塞时降档。QUIC 负责 UDP 丢包重传、RTT、拥塞控制和流量控制。

## 文件完整性

每个文件都执行端到端校验：

1. 发送端传输前计算 SHA-256。
2. 数据通过多条 QUIC stream 传输。
3. 接收端按 offset 写入 `.part` 临时文件。
4. 所有数据落盘后重新读取临时文件计算 SHA-256。
5. 两端校验一致后才重命名为最终文件并报告完成。

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

要求 Go 1.23 或兼容版本。

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

仓库根目录的 `VERSION` 保存当前发布版本。版本 PR 合并到 `main` 后，GitHub Actions 自动测试并同时发布：

```text
p2p-friend-linux-amd64
p2p-friend-windows-amd64.exe
p2p-friend-darwin-amd64
p2p-friend-darwin-arm64
SHA256SUMS.txt
```

## 安全

- STUN 只用于发现 IPv4 NAT 映射，不承载文件数据。
- QUIC 使用 TLS 1.3 保护链路。
- 连接码包含随机会话 token 和临时证书指纹。
- 文件额外执行 SHA-256 端到端校验。
- 接收文件先写 `.part`，校验成功后再重命名。
- 成功连接的一方可以在对方当前系统用户权限范围内浏览、读取和写入文件系统。

连接码属于临时访问凭据，只应发送给可信任的人。
