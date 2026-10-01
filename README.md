# p2p-friend

一个面向两个人直接传文件的交互式 P2P 命令行工具，操作方式接近 SFTP。

- Linux / Windows x86-64
- 单文件可执行程序
- TLS 1.3 加密
- 不使用 TURN / relay，文件数据点对点直传
- 文件和目录递归传输
- 同一会话内可连续 `put` / `get`
- 双方都可以浏览远端目录并互相传输
- 支持远端绝对路径
- SHA-256 文件完整性校验
- `Ctrl-C` 只取消当前传输，不退出会话
- 取消接收时清理 `.part` 和本次新建文件
- 中文路径支持

> v0.4 使用 `P2P4-...` 会话码，与 P2P3 及更早协议不兼容。双方请使用相同版本。

## 启动

Linux：

```bash
chmod +x ./p2p-friend-linux-amd64
./p2p-friend-linux-amd64
```

Windows：

```powershell
.\p2p-friend-windows-amd64.exe
```

启动菜单：

```text
1) 创建会话（本机监听）
2) 加入会话（本机主动连接）
3) 退出
```

如果 A -> B 可以建立连接，而 B -> A 超时，就让 **B 创建会话，A 加入会话**。连接建立后 TCP/TLS 本身是双向的，双方仍然都能 `put` / `get`。

例如已经确认 Linux -> Windows 可以连接、Windows -> Linux 超时，则应让 Windows 创建会话，Linux 加入。

## SFTP 风格命令

### 远端文件系统

```text
pwd
ls
ls <remote-path>
cd <remote-path>
cd -
```

这些命令操作**对方机器**。

绝对路径也允许，例如从 Linux 浏览 Windows：

```text
ls "D:\BaiduNetdiskDownload"
cd "D:\BaiduNetdiskDownload\【正点原子】RK3568开发板资料（A盘）-基础资料"
pwd
```

从 Windows 浏览 Linux：

```text
ls /home/liyunfeng/Downloads
cd /home/liyunfeng/Downloads
```

### 本地文件系统

本地命令使用 `l` 前缀：

```text
lpwd
lls
lls <local-path>
lcd <local-path>
lcd -
```

因此：

- `ls` = 看对方
- `lls` = 看自己
- `cd` = 改对方的会话目录
- `lcd` = 改自己的本地目录

## put

```text
put <local-path> [remote-path]
```

不指定远端目标时，发送到远端当前目录：

```text
put ./test.txt
put ./build-output
```

指定远端目标：

```text
put ./test.txt "D:\incoming\test.txt"
put ./build-output "D:\incoming\build-output"
```

Linux 远端示例：

```text
put "D:\data\result.zip" /home/liyunfeng/Downloads/result.zip
```

如果指定的目标已存在且是目录，会把源文件/目录放到该目录下面。

## get

```text
get <remote-path> [local-path]
```

远端路径可以是绝对路径：

```text
get "D:\BaiduNetdiskDownload\【正点原子】RK3568开发板资料（A盘）-基础资料\正点原子产品选型手册_20240826.pdf"
```

指定本地保存位置：

```text
get "D:\data\1GGGGG.bin" ./1GGGGG.bin
get /home/liyunfeng/Downloads/kernel.tar.xz "D:\Downdata\kernel.tar.xz"
```

## 取消传输

传输过程中按：

```text
Ctrl-C
```

或者输入：

```text
cancel
```

只会取消当前传输，**不会关闭 P2P 会话**。

P2P4 使用带 transfer ID 的分块帧协议，因此取消后双方仍能继续解析后续命令和传输。

接收端取消时：

- 当前 `.part` 临时文件会删除
- 本次传输中新建且已经完成的文件会回滚删除
- 本次新建的空目录会尽量删除
- 如果自动删除失败，会打印路径和错误，让用户手动清理

如果开启了 `overwrite on` 并且已有文件已经完成覆盖，则无法自动恢复旧内容，程序会明确列出这些路径。

## overwrite

默认禁止覆盖本机已有接收文件：

```text
overwrite off
```

允许覆盖：

```text
overwrite on
```

这是**本机接收策略**。如果你向朋友已有文件的位置 `put`，而朋友没有开启 overwrite，传输会被拒绝，但连接不会断开。

## status

```text
status
```

显示：

- HOST / JOIN 角色
- 本地当前目录
- 对方看到的本机会话目录
- 当前远端目录
- overwrite 状态
- TCP 连接地址
- 活动 transfer ID

## 网络限制

当前版本仍然不使用 STUN / TURN / relay。

至少需要有一个方向可以建立直接 TCP：

- 公网 IPv6 + 入站防火墙允许 TCP 5000
- 同一局域网 / VPN 的私有 IPv4
- 公网 IPv4 / 手工端口映射

公网 IPv6 地址存在并不代表入站一定可达。Windows Defender Firewall、Linux nftables/ufw、路由器 IPv6 防火墙或运营商策略都可能让某一个方向超时。

如果只有 Linux -> Windows 可连接，就固定使用：

```text
Windows: 创建会话
Linux:   加入会话
```

这不会影响 Windows -> Linux 的文件发送，因为文件方向与 TCP 建连方向无关。

## 安全模型

- TLS 1.3
- 临时 ECDSA 证书
- 连接码包含随机 256-bit token
- 连接码固定校验证书 SHA-256 fingerprint
- 每个文件校验 SHA-256
- 接收文件先写 `.part`，校验成功后再 rename
- 默认拒绝通过符号链接写入目标路径

### v0.4 的重要变化

为了支持类似 SFTP 的远端浏览，远端绝对路径不再限制在程序启动目录。

**持有连接码并成功连接的人，可以在当前系统用户权限范围内浏览、读取文件，并通过 `put` 写入指定路径。只把连接码交给可信任的人。**

## 路径补全

v0.4 已经提供远端 `pwd / ls / cd` 和本地 `lpwd / lls / lcd`，因此可以直接浏览后再 `get`。

Tab 路径补全暂未加入。要在 Linux 和 Windows 上同时实现可靠的交互式 Tab completion，需要引入跨平台 raw-terminal/readline 层；这部分会单独处理，不和本次协议重构混在一起。

## Release

推送 `v*` tag 后，GitHub Actions 自动：

1. `go test ./...`
2. `go vet ./...`
3. 构建 Linux amd64
4. 构建 Windows amd64
5. 生成 `SHA256SUMS.txt`
6. 创建 GitHub Release 并上传二进制
