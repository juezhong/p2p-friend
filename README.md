# p2p-friend

`p2p-friend` 是一个面向两端直接文件传输的交互式 P2P 命令行工具，使用方式接近 SFTP。

文件数据在两个端点之间直接传输，不经过 TURN / relay 中继服务器。建立会话后，双方都可以浏览远端文件系统、上传文件或目录、下载文件或目录，并在同一连接中连续执行多次操作。

## 功能

- Linux / Windows x86-64
- 单文件可执行程序
- TLS 1.3 加密连接
- 文件数据点对点直传
- 文件和目录递归传输
- 双向 `put` / `get`
- 远端目录浏览与切换
- 支持远端绝对路径
- SHA-256 文件完整性校验
- `Ctrl-C` 仅取消当前传输，不退出会话
- 取消接收时自动清理临时文件和本次新建内容
- 中文、空格路径支持
- 本地 / 远端路径 Tab 补全
- Linux / Windows 路径风格自动识别

当前版本使用 `P2P4-...` 连接码。使用不同协议版本的客户端不能互相连接。

## 快速开始

Linux：

```bash
chmod +x ./p2p-friend-linux-amd64
./p2p-friend-linux-amd64
```

Windows：

```powershell
.\p2p-friend-windows-amd64.exe
```

启动后选择：

```text
1) 创建会话（本机监听）
2) 加入会话（本机主动连接）
3) 退出
```

创建会话的一方会生成连接码，将可用的 `P2P4-...` 连接码发送给另一方即可。

### 连接方向

建立 TCP 连接只要求至少有一个方向可达，文件传输方向与 TCP 建连方向无关。

规则很简单：

```text
如果 A -> B 连接超时：
让 B 创建会话，A 加入会话。
```

也就是让“连接失败方向的目标端”负责监听。

连接建立后，双方都可以执行 `put`、`get`、`ls`、`cd` 等命令。

## 命令

### 远端文件系统

```text
pwd
ls
ls <remote-path>
cd <remote-path>
cd -
```

这些命令操作对方机器：

- `pwd`：显示远端当前目录
- `ls`：列出远端目录
- `cd`：切换远端当前目录
- `cd -`：回到远端上一个目录

远端路径可以使用绝对路径：

```text
ls /path/to/directory
cd /path/to/directory
```

Windows 风格：

```text
ls "C:\path\to\directory"
cd "C:\path\to\directory"
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

对应关系：

```text
pwd   -> 远端当前目录
lpwd  -> 本地当前目录

ls    -> 浏览远端
lls   -> 浏览本地

cd    -> 切换远端目录
lcd   -> 切换本地目录
```

## 上传

语法：

```text
put <local-path> [remote-path]
```

上传单个文件：

```text
put ./file.bin
```

上传目录：

```text
put ./directory
```

指定远端目标：

```text
put ./file.bin /remote/path/file.bin
put ./directory /remote/path/directory
```

Windows 远端路径同样支持：

```text
put ./file.bin "C:\remote\path\file.bin"
```

如果省略 `remote-path`，内容会发送到远端当前目录。

## 下载

语法：

```text
get <remote-path> [local-path]
```

下载当前远端目录中的文件：

```text
get file.bin
```

下载远端绝对路径：

```text
get /remote/path/file.bin
```

指定本地保存位置：

```text
get /remote/path/file.bin ./local-file.bin
```

Windows 风格远端路径：

```text
get "C:\remote\path\file.bin"
```

目录同样支持递归下载。

## Tab 补全

程序内置跨平台命令行编辑器，不依赖外部 readline 动态库。

补全规则：

```text
cd / ls / get          -> 远端路径
lcd / lls              -> 本地路径
put 第 1 个路径参数    -> 本地路径
put 第 2 个路径参数    -> 远端路径
get 第 2 个路径参数    -> 本地路径
overwrite              -> on / off
```

按一次 `Tab` 会尝试补全。存在多个候选时会列出候选项，再继续输入即可。

包含空格的路径会自动加引号。中文路径不需要额外转义。

命令行编辑支持：

```text
Left / Right           移动光标
Up / Down              浏览命令历史
Ctrl-A / Ctrl-E        跳到行首 / 行尾
Ctrl-L                 清屏并重绘
Ctrl-C                 取消当前传输；没有传输时清空当前输入
Tab                    路径 / 参数补全
```

## 取消传输

传输过程中按：

```text
Ctrl-C
```

或者执行：

```text
cancel
```

只会取消当前传输，不会关闭 P2P 会话。

P2P4 使用带 transfer ID 的分块帧协议，因此取消一个传输后，同一条 TLS 连接仍可继续执行后续命令和传输。

接收被取消时，程序会尝试清理：

- 当前 `.part` 临时文件
- 本次传输中新建且已完成的文件
- 本次传输中新建的空目录

如果自动清理失败，会打印具体路径和错误，供用户手动处理。

如果开启 `overwrite on` 且原有文件已经被完整覆盖，旧内容无法自动恢复。

## 覆盖策略

默认禁止覆盖本机已有接收文件：

```text
overwrite off
```

允许覆盖：

```text
overwrite on
```

这是本机接收策略。远端向本机写入已有路径时，如果本机没有开启覆盖，传输会被拒绝，但会话保持连接。

## 状态

```text
status
```

可查看当前会话角色、目录状态、覆盖策略、TCP 连接信息和活动传输。

## 网络要求

当前版本不使用 STUN、TURN 或 relay。

至少需要一个方向能够建立直接 TCP 连接，例如：

- 公网 IPv6 且入站防火墙允许 TCP 5000
- 同一局域网 / VPN
- 公网 IPv4
- 手工端口映射

拥有公网 IPv6 地址并不代表入站连接一定可达。主机防火墙、路由器防火墙或运营商网络策略都可能阻止某个方向的连接。

如果某个方向连接超时，按前面的规则交换“创建会话 / 加入会话”角色即可。

## 安全模型

连接和文件传输包含以下保护：

- TLS 1.3
- 临时 ECDSA 证书
- 连接码包含随机 256-bit token
- 使用连接码中的 SHA-256 fingerprint 固定校验证书
- 每个文件单独校验 SHA-256
- 接收文件先写入临时 `.part` 文件，校验成功后再重命名
- 默认拒绝通过符号链接写入目标路径

为了支持 SFTP 风格的远端浏览，成功连接的一方可以在对方当前系统用户权限范围内浏览、读取和写入文件系统。

**连接码相当于临时访问凭据，只应发送给可信任的人。**

## 从源码构建

要求 Go 1.23 或兼容版本。

Linux：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o p2p-friend-linux-amd64 .
```

Windows：

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o p2p-friend-windows-amd64.exe .
```

运行测试：

```bash
go test ./...
go test -race ./...
go vet ./...
```

## Release

仓库根目录的 `VERSION` 保存当前发布版本。

包含新版本号的 PR 合并到 `main` 后，GitHub Actions 会自动：

1. 运行测试和静态检查
2. 构建 Linux amd64 和 Windows amd64
3. 创建对应版本的 Git tag
4. 生成 `SHA256SUMS.txt`
5. 创建 GitHub Release
6. 上传二进制和校验文件

手工推送 `v*` tag 也会进入同一套发布流程。
