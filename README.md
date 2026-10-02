# p2p-friend

`p2p-friend` 是一个面向两端直接文件传输的交互式 P2P 命令行工具，使用方式接近 SFTP。

文件数据通过 **UDP + QUIC** 在两个端点之间直接传输。程序会收集 IPv6、IPv4 与 STUN 映射候选，在同一 UDP socket 上尝试直连或 IPv4 NAT 打洞；不配置 TURN / relay。

## 功能

- Linux amd64
- Windows amd64
- macOS amd64 / arm64
- IPv6 UDP 直连
- IPv4 UDP 直连 / LAN / STUN 辅助 NAT 打洞
- QUIC TLS 1.3、可靠重传、拥塞控制和多 stream
- 1 条 control stream + 4 条 data stream
- 自适应 data lane / chunk / pacing
- 会话级单传输仲裁：同一时刻只运行一个文件或目录传输任务
- 文件和目录递归传输
- 双向 `put` / `get`
- 远端目录浏览与切换
- 绝对路径、中文和空格路径支持
- 本地 / 远端路径 Tab 补全
- 发送端与接收端 SHA-256 校验
- `Ctrl-C` 只取消当前传输，不退出会话
- `status` 显示实际 QUIC / UDP 链路、端口、候选和传输状态

当前协议版本使用统一的 `P2PF-...` 连接码前缀。版本与信令类型存放在连接码内部。

## 建立连接

启动后选择：

```text
1) 发起连接（生成连接码）
2) 加入连接（输入连接码）
3) 退出
```

发起连接的一方生成 `P2PF-...` 连接码后立即开始监听真实 QUIC 握手，不会等确认码粘贴后才启动网络监听。

加入连接的一方输入连接码后生成另一个 `P2PF-...` 确认码，将确认码发回即可。

纯手工、无信令服务器模式下，IPv4 NAT 打洞需要双方交换各自启动 UDP socket 后才能得到的 candidate，因此通用 NAT 场景仍需要两次人工交换：

```text
发起端 -> 连接码 -> 加入端
发起端 <- 确认码 <- 加入端
```

连接过程中的 candidate 重试保持静默。只有最终超时才提示交换“发起连接 / 加入连接”角色重试。

## 链路类型

连接成功后，prompt 与 `status` 会显示实际选中的链路，例如：

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

`NAT-PUNCH` 表示 UDP NAT hole punching。它不是 TUN；TUN 通常指操作系统虚拟三层网络接口。

## 传输模型

单个大文件按 offset 切块并行发送：

```text
file
 ├─ chunk -> data stream 0
 ├─ chunk -> data stream 1
 ├─ chunk -> data stream 2
 └─ chunk -> data stream 3

receiver -> WriteAt(offset) -> .part
```

发送器根据实际 QUIC `Write` 背压动态调节：

- 1~4 条 active data lane
- 32~256 KiB application chunk
- 0~2 ms pacing

这些调节是静默的，不会在正常传输过程中不断插入日志。持续顺畅时自动升档，出现明显阻塞时自动降档。

### 单传输模式

一个 P2P 会话在同一时刻只允许一个 `put` 或 `get` 任务占用传输通道。

如果一端正在传输，另一端再执行新的 `put` / `get`，会直接返回“当前已有传输任务”，不会启动第二条并发文件任务。

这个限制只针对文件传输。传输期间仍可在空闲的一端执行 `status`、目录浏览等控制命令。

## 进度与完整性

只有**发起当前文件操作的一端**显示正常传输进度。被动提供文件或被动接收文件的一端保持安静，避免异步日志打断命令输入。

典型下载输出：

```text
[GET] file.bin -> /local/path/file.bin (1.0 GiB)
[GET] file.bin                      73.42%  751.8 MiB / 1.0 GiB  42.1 MiB/s
[GET] file.bin                     100.00%    1.0 GiB / 1.0 GiB  41.8 MiB/s
[GET] SHA-256 <hash>  OK
[GET] 完成。
```

每个文件都执行端到端校验：

1. 发送端传输前计算 SHA-256。
2. 数据通过多条 QUIC stream 发送。
3. 接收端按 offset 写入 `.part` 临时文件。
4. 所有数据落盘后重新读取临时文件计算 SHA-256。
5. 两端校验完全一致后才重命名最终文件并报告完成。

## status

执行：

```text
status
```

会显示包括：

- 实际链路类型
- QUIC / UDP / TLS 1.3 传输栈
- 本机当前选中的 UDP socket
- 对端当前 UDP endpoint
- QUIC 是监听端还是主动连接端
- IPv4 / IPv6 UDP socket 与监听 / 打洞状态
- 本机 STUN 映射
- 对端 candidate 类型
- control / data stream 数量
- 当前是否存在文件传输任务
- 当前发送自适应参数（存在发送任务时）
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

仓库根目录的 `VERSION` 保存当前发布版本。版本 PR 合并到 `main` 后，GitHub Actions 自动测试并发布：

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
- 文件执行 SHA-256 端到端校验。
- 接收文件先写 `.part`，校验成功后再重命名。
- 成功连接的一方可以在对方当前系统用户权限范围内浏览、读取和写入文件系统。

连接码属于临时访问凭据，只应发送给可信任的人。
