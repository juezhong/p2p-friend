# p2p-friend

一个面向两个人直接传文件的交互式 P2P 命令行工具。

- Linux / Windows x86-64
- 单文件可执行程序
- TLS 1.3 加密
- 不使用文件中继服务器
- 文件和目录递归传输
- 一次连接中可连续传输多个文件/目录
- 双方都可以 `put` 和 `get`
- SHA-256 文件完整性校验
- 中文路径支持

> 当前协议使用 `P2P3-...` 会话码，与早期 v0.1 / v0.2 不兼容。双方应使用相同版本。

## 1. 启动

Linux：

```bash
chmod +x ./p2p-friend-linux-amd64
./p2p-friend-linux-amd64
```

Windows PowerShell / CMD：

```powershell
.\p2p-friend-windows-amd64.exe
```

启动后：

```text
P2P Friend
========================================
1) 创建会话（生成连接码）
2) 加入会话（输入连接码）
3) 退出

请选择 [1/2/3]:
```

不再需要记 `recv`、`send-listen`、`recv-connect` 等参数。

## 2. 创建会话

一方选择：

```text
1) 创建会话（生成连接码）
```

程序使用 TCP 5000，并列出当前机器可用的连接码，例如：

```text
[2408:....]:5000 [global IPv6]
P2P3-xxxxxxxxxxxxxxxxxxxxxxxx
```

优先把 `[global IPv6]` 对应的 `P2P3-...` 发给朋友。

## 3. 加入会话

另一方选择：

```text
2) 加入会话（输入连接码）
```

粘贴连接码即可。

连接成功后双方都会进入：

```text
p2p[HOST|put发送/get接收]>
```

或：

```text
p2p[JOIN|put发送/get接收]>
```

`HOST/JOIN` 只表示谁创建会话、谁加入会话，**与谁发送文件无关**。

## 4. 命令

### put：发送文件或目录

Linux：

```text
put ./linux-src
put ./ubuntu.iso
```

Windows：

```text
put D:\BaiduNetdiskDownload\资料
put "D:\BaiduNetdiskDownload\【正点原子】\产品选型手册.pdf"
```

目录会递归传输。

### get：从对方获取

```text
get test.txt
get 资料目录
get subdir/file.bin
```

`get` 的路径相对于**对方当前目录**。

为避免远程路径越界，`get`：

- 不允许绝对路径
- 不允许 `../`
- 不允许通过符号链接逃出对方当前目录

如果需要获取另一个目录里的文件，让对方先执行 `cd`。

### 本地目录操作

```text
pwd
ls
ls subdir
cd /home/user/Downloads
```

Windows 示例：

```text
cd D:\Downdata
ls
```

这个“当前目录”同时决定：

1. 收到的文件保存到哪里
2. 对方使用 `get` 时可以请求哪个目录树里的内容

因此不要把当前目录设到你不愿意共享读取的目录。

### 同名文件

默认禁止覆盖：

```text
overwrite off
```

需要覆盖时：

```text
overwrite on
```

### 状态 / 帮助 / 退出

```text
status
help
quit
```

`exit` 和 `bye` 也可以退出。

## 5. 网络方向

创建会话的一方负责监听，加入会话的一方主动连接。建立连接后 TCP/TLS 是双向的，因此双方都可以 `put` / `get`，与操作系统无关。

如果某一台机器的公网 IPv6 入站被防火墙阻断，让**能够被直连的一方创建会话**即可。

## 6. 网络限制

当前版本不使用 STUN / TURN / relay。

因此至少需要一个方向可以直接建立 TCP：

- 公网 IPv6 + 入站防火墙允许 TCP 5000
- 同一局域网 / VPN 的私有 IPv4
- 或者公网 IPv4 / 手工端口映射

如果双方都处在无法直接入站的 NAT/防火墙后，当前版本不会通过中继绕过。

## 7. 安全

- TLS 1.3
- 临时 ECDSA 证书
- 连接码包含随机 256-bit token
- 证书使用 SHA-256 fingerprint 固定校验
- 每个文件传输后校验 SHA-256
- 接收路径防止 `../` 越界
- `get` 请求被限制在对方当前目录树
- 符号链接默认拒绝

连接码相当于一次性会话凭据，不要发给无关人员。

## Release

推送 `v*` tag 后，GitHub Actions 会自动：

1. 运行 `go test ./...` 和 `go vet ./...`
2. 构建 Linux amd64 与 Windows amd64
3. 生成 `SHA256SUMS.txt`
4. 创建 GitHub Release 并上传二进制