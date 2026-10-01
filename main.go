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
	fmt.Printf(`p2p-friend v%s - 直接 P2P 文件/目录传输

启动后选择：
  1. 创建会话（本机监听，需要对方能直连本机）
  2. 加入会话（本机主动连接）

连接后采用类似 SFTP 的命令：
  pwd / ls / cd       操作远端目录
  lpwd / lls / lcd    操作本地目录
  put <local> [remote] 发送到远端，可指定远端绝对路径
  get <remote> [local] 获取远端文件/目录，可使用远端绝对路径
  cancel              取消当前传输
  Ctrl-C              取消当前传输，不退出会话
  quit / exit          断开并退出

注意：
  * P2P4 连接码允许会话双方浏览和访问对方当前用户有权限访问的绝对路径。
  * 不使用 TURN/relay；文件数据始终点对点直传。
  * 如果一个方向 IPv6 TCP 超时，让能够被直连的一方创建会话，另一方加入。
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
	consolePrintln("1) 创建会话（本机监听）")
	consolePrintln("2) 加入会话（本机主动连接）")
	consolePrintln("3) 退出")
	consolePrintln("")
	consolePrintln("连接提示：如果 A→B 能连接而 B→A 超时，就让 B 创建会话、A 加入。")
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

func runHost(in *bufio.Reader, cwd string) error {
	ln, token, fingerprintHex, err := openTLSListener(":" + defaultPort)
	if err != nil {
		return fmt.Errorf("创建会话失败（TCP %s）：%w", defaultPort, err)
	}
	defer ln.Close()

	consolePrintf("\n[创建会话] 初始目录: %s\n", cwd)
	consolePrintf("[创建会话] 会话端口: %s\n\n", defaultPort)
	if err := printConnectionCodes(ln, token, fingerprintHex); err != nil {
		return err
	}
	consolePrintln("把上面一个可用的 P2P4-... 连接码发给朋友。")
	consolePrintln("等待朋友加入...（这里 Ctrl-C 会结束等待）")

	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept peer: %w", err)
	}
	if err := authenticateListener(conn, token, roleHost); err != nil {
		conn.Close()
		return err
	}
	consolePrintf("\n已建立直接加密连接：%s <-> %s\n", conn.LocalAddr(), conn.RemoteAddr())
	return runPeerShell(conn, "HOST", cwd, in)
}

func runJoin(in *bufio.Reader, cwd string) error {
	consolePrintln("\n[加入会话] 请粘贴朋友发来的 P2P4-... 连接码。")
	consolePrintf("连接码: ")
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return errors.New("连接码为空")
	}

	conn, token, err := dialPeer(code)
	if err != nil {
		return err
	}
	if err := authenticateDialer(conn, token, roleJoin); err != nil {
		conn.Close()
		return err
	}
	consolePrintf("\n已建立直接加密连接：%s <-> %s\n", conn.LocalAddr(), conn.RemoteAddr())
	return runPeerShell(conn, "JOIN", cwd, in)
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
	consolePrintln("put/get 都支持绝对路径；Ctrl-C 只取消当前传输，不退出会话。")
	consolePrintln("警告：连接码持有者可访问本进程用户权限范围内的绝对路径。")
	consolePrintln("输入 help 查看命令。")
	consolePrintln("")

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

	lines := make(chan string)
	readErr := make(chan error, 1)
	go func() {
		for {
			line, err := in.ReadString('\n')
			if len(line) > 0 {
				lines <- line
			}
			if err != nil {
				readErr <- err
				return
			}
		}
	}()

	for {
		remote := s.getRemoteCwd()
		if remote == "" {
			remote = "?"
		}
		consolePrintf("p2p[%s remote:%s]> ", s.roleName, remote)
		var line string
		select {
		case <-s.closed:
			consolePrintln("\n连接已关闭。")
			return nil
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				_ = s.writeFrame(frameBye, 0, nil)
				return nil
			}
			return err
		case line = <-lines:
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
					consolePrintf("[SEND] 已取消: %v\n", err)
				} else {
					consolePrintf("[SEND] 失败: %v\n", err)
				}
			} else {
				consolePrintln("[SEND] 完成。")
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
			_ = s.writeFrame(frameBye, 0, nil)
			s.close(false)
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

其他：
  overwrite on|off            是否允许覆盖本机已有接收文件（默认 off）
  status                      显示连接和目录状态
  help                        显示帮助
  quit / exit                 断开并退出

示例：
  ls "D:\\BaiduNetdiskDownload"
  cd "D:\\BaiduNetdiskDownload\\【正点原子】"
  get "D:\\BaiduNetdiskDownload\\manual.pdf" ./manual.pdf
  put ./build.tar "D:\\incoming\\build.tar"

安全提示：远端绝对路径访问不再限制在初始目录；请只把连接码交给可信任的人。`)
}
