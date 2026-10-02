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
	fmt.Printf(`p2p-friend v%s - UDP P2P 文件/目录传输

启动后选择：
  1. 创建会话：生成 OFFER，收到朋友的 ANSWER 后建立连接
  2. 加入会话：输入 OFFER，生成 ANSWER 发回创建方

连接阶段会自动收集 IPv6 / IPv4 UDP 候选并执行 UDP 连通性检查；
IPv4 位于 NAT 后时会通过 STUN 辅助 UDP hole punching，不使用 TURN/relay。
只有 ICE、DTLS 和数据通道全部建立成功后才进入文件命令行。

连接后采用类似 SFTP 的命令：
  pwd / ls / cd         操作远端目录
  lpwd / lls / lcd      操作本地目录
  put <local> [remote]  发送到远端
  get <remote> [local]  获取远端文件/目录
  Tab                   自动补全本地/远端路径
  cancel / Ctrl-C       取消当前传输，不退出会话
  quit / exit           断开并退出

传输：
  * 底层是 UDP + QUIC（TLS 1.3、可靠重传、拥塞控制、多 stream）。
  * 4 条 QUIC data stream 并行传输，UDP 丢包由 QUIC 自动重传。
  * 发送文件前计算 SHA-256；接收端落盘后重新计算，匹配才报告完成。
  * 不配置 TURN/relay；全部候选失败时会明确报连接失败。
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
	consolePrintln("1) 创建会话（生成 OFFER）")
	consolePrintln("2) 加入会话（输入 OFFER / 生成 ANSWER）")
	consolePrintln("3) 退出")
	consolePrintln("")
	consolePrintln("网络：同一 UDP socket 自动尝试 IPv6 直连与 IPv4 STUN/NAT 打洞，传输使用 QUIC；不使用 TURN/relay。")
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
	peer, offer, err := createHostOffer()
	if err != nil {
		return fmt.Errorf("创建 UDP/QUIC 会话失败: %w", err)
	}
	consolePrintf("\n[创建会话] 初始目录: %s\n", cwd)
	consolePrintln("[创建会话] 已收集 IPv6 / IPv4 / STUN 候选。")
	consolePrintln("")
	consolePrintln("把下面的 OFFER 发给朋友：")
	consolePrintln(offer)
	consolePrintln("")
	consolePrintln("朋友会返回一个 P2P7-ANSWER-...，粘贴后开始 UDP/QUIC 连通性检查。")
	consolePrintf("ANSWER: ")
	answer, err := readSignalLine(in)
	if err != nil {
		_ = peer.Close()
		return err
	}
	if answer == "" {
		_ = peer.Close()
		return errors.New("ANSWER 为空")
	}
	consolePrintln("正在建立 P2P UDP 连接（IPv6 direct / IPv4 hole punching）...")
	conn, token, err := peer.acceptAnswer(answer)
	if err != nil {
		_ = peer.Close()
		return err
	}
	if err := authenticateListener(conn, token, roleHost); err != nil {
		_ = conn.Close()
		return err
	}
	consolePrintln("已建立 P2P UDP 加密连接：QUIC + TLS 1.3，多数据 stream 已就绪。")
	return runPeerShell(conn, "HOST", cwd, in)
}

func runJoin(in *bufio.Reader, cwd string) error {
	consolePrintln("\n[加入会话] 请粘贴朋友发来的 P2P7-OFFER-...。")
	consolePrintf("OFFER: ")
	offer, err := readSignalLine(in)
	if err != nil {
		return err
	}
	if offer == "" {
		return errors.New("OFFER 为空")
	}
	peer, answer, token, err := createJoinAnswer(offer)
	if err != nil {
		return err
	}
	consolePrintln("")
	consolePrintln("把下面的 ANSWER 发回创建方：")
	consolePrintln(answer)
	consolePrintln("")
	consolePrintln("等待创建方粘贴 ANSWER，并自动执行 UDP/QUIC 连通性检查...")
	conn, err := peer.waitConn()
	if err != nil {
		_ = peer.Close()
		return err
	}
	if err := authenticateDialer(conn, token, roleJoin); err != nil {
		_ = conn.Close()
		return err
	}
	consolePrintln("已建立 P2P UDP 加密连接：QUIC + TLS 1.3，多数据 stream 已就绪。")
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
	consolePrintln("支持 Tab 补全：远端命令自动查询对方目录，本地命令补全本机路径。")
	consolePrintln("空格会自动转义，中文路径可直接输入/补全；put/get 都支持绝对路径。")
	consolePrintln("Ctrl-C 只取消当前传输，不退出会话。")
	consolePrintln("警告：连接码持有者可访问本进程用户权限范围内的绝对路径。")
	consolePrintln("输入 help 查看命令。")
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
			consolePrintln("\n连接已关闭。")
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
				_ = s.writeFrame(frameBye, 0, nil)
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
  status                      显示连接和目录状态
  help                        显示帮助
  quit / exit                 断开并退出

安全提示：远端绝对路径访问不限制在初始目录；请只把连接码交给可信任的人。`)
}
