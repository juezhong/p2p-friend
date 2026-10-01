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
- Tab 自动补全本地/远端路径
- 路径含空格时自动加引号
- Linux / Windows 路径风格自动识别

> v0.5 继续使用 `P2P4-...` 协议，与 v0.4 的网络协议兼容；双方都升级到 v0.5 才能获得 Tab 补全和新版交互体验。P2P3 及更早协议仍不兼容。

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

如果 **A -> B 连接超时**，就让 **B 创建会话、A 加入会话**。也就是：让“超时方向的目标端”负责监听。连接建立后 TCP/TLS 本身是双向的，双方仍然都能 `put` / `get`。

例如 **Windows -> Linux 超时**，就让 **Linux 创建会话、Windows 加入**。反过来，如果 **Linux -> Windows 超时**，就让 **Windows 创建会话、Linux 加入**。

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

## Tab 补全与命令行编辑

v0.5 增加了内置的跨平台命令行编辑器，不依赖外部 readline 动态库。Linux 和 Windows 都可以直接使用 `Tab`。

补全规则：

```text
cd / ls / get          -> 查询并补全远端路径
lcd / lls              -> 补全本地路径
put 第 1 个路径参数    -> 补全本地路径
put 第 2 个路径参数    -> 查询并补全远端路径
get 第 2 个路径参数    -> 补全本地路径
overwrite              -> 补全 on / off
```

例如 Linux 主动连接 Windows 后：

```text
cd D:\Bai<Tab>
```

程序会向 Windows 查询对应目录。如果唯一候选是：

```text
D:\BaiduNetdiskDownload\
```

就会直接补全。多个候选会列出来，再继续输入即可。

路径里有空格时会自动加引号。例如输入：

```text
cd 正<Tab>
```

如果候选为：

```text
正点原子 RK3568资料/
```

命令行会自动变成类似：

```text
cd "正点原子 RK3568资料/"
```

中文路径不需要额外转义。Windows 的 `D:\...` 和 Linux 的 `/home/...` 会按远端系统的路径风格分别处理。

命令行编辑还支持：

```text
Left / Right           移动光标
Up / Down              浏览本次会话命令历史
Ctrl-A / Ctrl-E        跳到行首 / 行尾
Ctrl-L                 清屏并重绘
Ctrl-C                 取消当前传输；没有传输时清空当前输入，不退出
```

## Release

仓库根目录的 `VERSION` 保存当前发布版本，例如：

```text
0.5.0
```

合并一个包含新 `VERSION` 的 PR 到 `main` 后，Release workflow 会自动：

1. 运行 `go test ./...` 和 `go vet ./...`
2. 构建 Linux amd64 / Windows amd64
3. 创建对应的 `v0.5.0` Git tag（如果还不存在）
4. 生成 `SHA256SUMS.txt`
5. 创建 GitHub Release 并上传二进制

仍然支持手工推送 `v*` tag；手工 tag 也会直接走同一套发布流程。
