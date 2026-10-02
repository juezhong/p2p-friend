package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			printHelp()
			return
		case "-v", "--version", "version":
			fmt.Printf("p2p-friend v%s\n", appVersion)
			return
		default:
			fmt.Fprintf(os.Stderr, "v%s 使用交互模式，请直接运行：%s\n", appVersion, filepath.Base(os.Args[0]))
			os.Exit(2)
		}
	}

	if err := runInteractive(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`p2p-friend v%s - P2P 文件/目录传输

启动后选择：
  1. 创建连接：生成 P2PF-INVITE 邀请码
  2. 加入连接：输入 P2PF-INVITE 邀请码

程序会在同一 UDP socket 上自动尝试 IPv6 / IPv4 直连和 IPv4 NAT 打洞，
使用 QUIC 提供加密、可靠重传、拥塞控制和多 stream 传输。

连接后采用类似 SFTP 的命令：
  pwd / ls / cd         操作远端目录
  lpwd / lls / lcd      操作本地目录
  put <local> [remote]  发送到远端
  get <remote> [local]  获取远端文件/目录
  Tab                   自动补全本地/远端路径
  cancel / Ctrl-C       取消当前传输，不退出会话
  quit / exit           断开并退出

说明：
  * 邀请码使用 P2PF-INVITE-...；只有需要双向 NAT 打洞时才会出现 P2PF-REPLY-... 回传码。
  * IPv6/公网 IPv4 等可直连场景只需交换一次邀请码。
  * 双方都在较严格 IPv4 NAT 后时，无信令服务器模式仍需要回传码返回加入方的公网 UDP candidate。
  * 同一会话一次只运行一个文件/目录传输任务，避免双向任务争抢带宽。
  * IPv6 选中后不执行 NAT 打洞；STUN 只用于预先准备 IPv4 失败回退候选。
  * 不使用 TURN/relay；最终连接失败时会提示交换创建/加入角色重试。
`, appVersion)
}

func runInteractive() error {
	in := bufio.NewReader(os.Stdin)
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get current directory: %w", err)
	}
	cwd, err = filepath.Abs(cwd)
	if err != nil {
		return err
	}

	consolePrintf("\nP2P Friend v%s\n", appVersion)
	consolePrintln("========================================")
	consolePrintln("1) 创建连接（生成 P2PF-INVITE 邀请码）")
	consolePrintln("2) 加入连接（输入 P2PF-INVITE 邀请码）")
	consolePrintln("3) 退出")
	consolePrintln("")

	for {
		consolePrintf("请选择 [1/2/3]: ")
		line, err := in.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		choice := strings.TrimSpace(line)
		switch strings.ToLower(choice) {
		case "1", "host", "create":
			return runHost(in, cwd)
		case "2", "join", "connect":
			return runJoin(in, cwd)
		case "3", "q", "quit", "exit":
			return nil
		default:
			consolePrintln("请输入 1、2 或 3。")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func inputLineReady(in *bufio.Reader, timeout time.Duration) bool {
	if in.Buffered() > 0 {
		return true
	}
	return consoleInputReady(timeout)
}

func runHost(in *bufio.Reader, cwd string) error {
	peer, code, err := createConnectionCode()
	if err != nil {
		return fmt.Errorf("创建 P2P 连接失败: %w", err)
	}

	type connResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan connResult, 1)
	go func() {
		conn, err := peer.acceptQUIC()
		acceptCh <- connResult{conn: conn, err: err}
	}()

	consolePrintf("\n[创建连接] 初始目录: %s\n", cwd)
	consolePrintln("")
	consolePrintln("把下面的 P2PF-INVITE 邀请码发给对方；收到它的人选择“加入连接”：")
	consolePrintln(code)
	consolePrintln("")
	consolePrintln("程序会先尝试只用这个邀请码直接连接；IPv6 / 公网 IPv4 等场景无需第二个码。")
	consolePrintln("如果加入方提示需要双向 NAT 打洞，它会生成 P2PF-REPLY 回传码，再粘贴到这里。")
	consolePrintf("P2PF-REPLY 回传码（仅 NAT 打洞需要）: ")

	for {
		select {
		case res := <-acceptCh:
			consolePrintln("")
			if res.err != nil {
				_ = peer.Close()
				return res.err
			}
			conn := res.conn
			if err := authenticateListener(conn, peer.token, roleHost); err != nil {
				_ = conn.Close()
				return err
			}
			consolePrintf("已建立 P2P 连接：QUIC / %s\n", connectionMode(conn))
			return runPeerShell(conn, "创建方", cwd, in)
		default:
		}

		if !inputLineReady(in, 150*time.Millisecond) {
			continue
		}
		joinCode, err := readSignalLine(in)
		if err != nil {
			_ = peer.Close()
			return err
		}
		if strings.TrimSpace(joinCode) == "" {
			consolePrintf("回传码（仅 NAT 打洞需要）: ")
			continue
		}
		if err := peer.applyConfirmation(joinCode); err != nil {
			consolePrintf("P2PF-REPLY 回传码无效: %v\n", err)
			consolePrintf("回传码（仅 NAT 打洞需要）: ")
			continue
		}
		consolePrintln("[连接] 已接收 P2PF-REPLY 回传码，继续等待 P2P 建连。")
	}
}

func runJoin(in *bufio.Reader, cwd string) error {
	consolePrintln("\n[加入连接] 请粘贴创建方发来的 P2PF-INVITE-... 邀请码。")
	consolePrintf("P2PF-INVITE 邀请码: ")
	code, err := readSignalLine(in)
	if err != nil {
		return err
	}
	if code == "" {
		return errors.New("邀请码为空")
	}
	peer, joinCode, token, err := createJoinConfirmation(code)
	if err != nil {
		return err
	}

	type connResult struct {
		conn net.Conn
		err  error
	}
	connCh := make(chan connResult, 1)
	go func() {
		conn, err := peer.waitConn()
		connCh <- connResult{conn: conn, err: err}
	}()

	consolePrintln("")
	consolePrintln("正在尝试仅使用邀请码直接连接；成功时不需要返回第二个码。")
	select {
	case res := <-connCh:
		if res.err != nil {
			_ = peer.Close()
			return res.err
		}
		if err := authenticateDialer(res.conn, token, roleJoin); err != nil {
			_ = res.conn.Close()
			return err
		}
		consolePrintf("已建立 P2P 连接：QUIC / %s（单邀请码）\n", connectionMode(res.conn))
		return runPeerShell(res.conn, "加入方", cwd, in)
	case <-time.After(4 * time.Second):
	}

	consolePrintln("直连暂未建立；双方可能都在 IPv4 NAT 后。请把下面的 P2PF-REPLY 回传码发回创建方：")
	consolePrintln(joinCode)
	consolePrintln("发送后无需其它操作，程序会继续静默等待连接。")

	res := <-connCh
	if res.err != nil {
		_ = peer.Close()
		return res.err
	}
	if err := authenticateDialer(res.conn, token, roleJoin); err != nil {
		_ = res.conn.Close()
		return err
	}
	consolePrintf("已建立 P2P 连接：QUIC / %s\n", connectionMode(res.conn))
	return runPeerShell(res.conn, "加入方", cwd, in)
}

func connectionMode(conn net.Conn) string {
	if p, ok := conn.(interface{ LinkMode() string }); ok {
		if mode := p.LinkMode(); mode != "" {
			return mode
		}
	}
	return "UDP"
}

func runPeerShell(conn net.Conn, roleName, cwd string, in *bufio.Reader) error {
	s := initPeerSession(conn, roleName, cwd)
	defer s.close(false)
	go s.readLoop()

	if remote, err := s.remotePwd(); err == nil {
		s.setRemoteCwd(remote)
	}

	consolePrintln("")
	consolePrintln("会话已就绪。pwd/ls/cd 操作远端；lpwd/lls/lcd 操作本地。")
	consolePrintln("支持 Tab 补全：远端命令自动查询对方目录，本地命令补全本机路径。")
	consolePrintln("空格会自动转义，中文路径可直接输入/补全；put/get 都支持绝对路径。")
	consolePrintln("Ctrl-C 只取消当前传输，不退出会话。")
	consolePrintln("警告：连接码持有者可访问本进程用户权限范围内的绝对路径。")
	consolePrintln("输入 help 查看命令，status 查看当前 QUIC/UDP 端口和链路。")
	consolePrintln("")

	editor := newLineEditor(s, in)
	restoreConsole := setConsoleWriter(editor)
	defer restoreConsole()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)
	go func() {
		for {
			select {
			case <-s.closed:
				return
			case <-sigCh:
				if s.cancelActive("用户按 Ctrl-C 取消传输") {
					consolePrintln("\n[CANCEL] 已请求取消当前传输，会话保持连接。")
				} else {
					consolePrintln("\n[CANCEL] 当前没有活动传输；要退出请使用 quit/exit。")
				}
			}
		}
	}()

	for {
		select {
		case <-s.closed:
			if !s.remoteBye.Load() {
				consolePrintln("\n[连接] 会话已关闭。")
			}
			return nil
		default:
		}

		line, err := editor.ReadLine(shellPrompt(s))
		if err != nil {
			switch {
			case errors.Is(err, errLineInterrupt):
				if s.cancelActive("用户按 Ctrl-C 取消传输") {
					consolePrintln("[CANCEL] 已请求取消当前传输，会话保持连接。")
				} else {
					consolePrintln("[CANCEL] 当前没有活动传输；要退出请使用 quit/exit。")
				}
				continue
			case errors.Is(err, io.EOF):
				s.close(true)
				consolePrintln("[连接] 会话已正常结束。")
				return nil
			default:
				select {
				case <-s.closed:
					return nil
				default:
				}
				return err
			}
		}

		args, err := parseCommandLine(line)
		if err != nil {
			consolePrintf("命令解析失败: %v\n", err)
			continue
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToLower(args[0])
		switch cmd {
		case "pwd":
			if len(args) != 1 {
				consolePrintln("用法: pwd")
				continue
			}
			p, err := s.remotePwd()
			if err != nil {
				consolePrintf("pwd: %v\n", err)
			} else {
				consolePrintln(p)
			}
		case "ls", "dir":
			if len(args) > 2 {
				consolePrintln("用法: ls [remote-path]")
				continue
			}
			path := ""
			if len(args) == 2 {
				path = args[1]
			}
			if err := s.remoteList(path); err != nil {
				consolePrintf("ls: %v\n", err)
			}
		case "cd":
			if len(args) != 2 {
				consolePrintln("用法: cd <remote-path|->")
				continue
			}
			if err := s.remoteCd(args[1]); err != nil {
				consolePrintf("cd: %v\n", err)
			}
		case "lpwd":
			consolePrintln(s.getLocalCwd())
		case "lls", "ldir":
			if len(args) > 2 {
				consolePrintln("用法: lls [local-path]")
				continue
			}
			path := ""
			if len(args) == 2 {
				path = args[1]
			}
			if err := s.localList(path); err != nil {
				consolePrintf("lls: %v\n", err)
			}
		case "lcd":
			if len(args) != 2 {
				consolePrintln("用法: lcd <local-path|->")
				continue
			}
			if err := s.localCd(args[1]); err != nil {
				consolePrintf("lcd: %v\n", err)
			}
		case "put":
			if len(args) < 2 || len(args) > 3 {
				consolePrintln("用法: put <local-path> [remote-path]")
				continue
			}
			remoteDest := ""
			if len(args) == 3 {
				remoteDest = args[2]
			}
			if err := s.put(args[1], remoteDest); err != nil {
				if errors.Is(err, context.Canceled) {
					consolePrintf("[PUT] 已取消: %v\n", err)
				} else {
					consolePrintf("[PUT] 失败: %v\n", err)
				}
			} else {
				consolePrintln("[PUT] 完成。")
			}
		case "get":
			if len(args) < 2 || len(args) > 3 {
				consolePrintln("用法: get <remote-path> [local-path]")
				continue
			}
			localDest := ""
			if len(args) == 3 {
				localDest = args[2]
			}
			if err := s.get(args[1], localDest); err != nil {
				if errors.Is(err, context.Canceled) {
					consolePrintf("[GET] 已取消: %v\n", err)
				} else {
					consolePrintf("[GET] 失败: %v\n", err)
				}
			} else {
				consolePrintln("[GET] 完成。")
			}
		case "cancel":
			if s.cancelActive("用户执行 cancel") {
				consolePrintln("[CANCEL] 已请求取消当前传输。")
			} else {
				consolePrintln("[CANCEL] 当前没有活动传输。")
			}
		case "overwrite":
			if len(args) != 2 {
				consolePrintln("用法: overwrite on|off")
				continue
			}
			if err := s.setOverwrite(args[1]); err != nil {
				consolePrintln(err.Error())
			}
		case "status":
			s.status()
		case "help", "?":
			printShellHelp()
		case "quit", "exit", "bye":
			s.close(true)
			consolePrintln("[连接] 会话已正常结束。")
			return nil
		default:
			consolePrintf("未知命令: %s（输入 help 查看命令）\n", args[0])
		}
	}
}

func printShellHelp() {
	consolePrintln(`远端命令（类似 SFTP）：
  pwd                         显示远端当前目录
  ls [remote-path]            查看远端目录/文件，支持绝对路径
  cd <remote-path|->          修改远端当前目录，cd - 返回上一个目录

本地命令：
  lpwd                        显示本地当前目录
  lls [local-path]            查看本地目录/文件
  lcd <local-path|->          修改本地当前目录，lcd - 返回上一个目录

传输：
  put <local> [remote]        发送文件/目录；remote 可为绝对路径
  get <remote> [local]        获取文件/目录；remote 可为绝对路径
  cancel                      取消当前传输
  Ctrl-C                      等同 cancel，不退出会话

补全与编辑：
  Tab                         自动补全命令和路径
  cd/ls/get                   补全远端路径
  lcd/lls                     补全本地路径
  put 第1参数                 补全本地路径
  put 第2参数                 补全远端路径
  get 第2参数                 补全本地路径
  ↑/↓                         浏览本次会话命令历史
  ←/→                         移动光标

路径含空格时，补全会自动加引号；中文路径可直接补全。
Windows 的 D:\... 路径和 Linux 的 /home/... 路径都会按远端系统风格处理。

其他：
  overwrite on|off            是否允许覆盖本机已有接收文件（默认 off）
  status                      显示 QUIC/UDP 端口、链路、传输状态和目录
  help                        显示帮助
  quit / exit                 断开并退出

安全提示：远端绝对路径访问不限制在初始目录；请只把连接码交给可信任的人。`)
}
