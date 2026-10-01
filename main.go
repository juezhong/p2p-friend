package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
			fmt.Printf("p2p-friend v%s
", appVersion)
			return
		default:
			fmt.Fprintf(os.Stderr, "v%s 已改为交互模式，请直接运行：%s
", appVersion, filepath.Base(os.Args[0]))
			os.Exit(2)
		}
	}

	if err := runInteractive(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v
", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`p2p-friend v%s - 直接 P2P 文件/目录传输

直接运行程序，然后选择：
  1. 创建会话（生成连接码）
  2. 加入会话（输入连接码）

连接后双方都可使用：
  put <path>   发送本地文件/目录给对方
  get <path>   从对方当前目录获取文件/目录
  ls [path]    查看本地目录
  cd <path>    修改本地当前目录
  pwd          显示本地当前目录
  overwrite on|off  是否允许覆盖收到的同名文件
  help         显示命令帮助
  quit / exit  断开并退出

说明：
  * 目录会递归传输。
  * 文件数据通过 TLS/TCP 在两台机器之间直接传输，不经过中继。
  * get 只能访问对方“当前目录”及其子目录，不能使用绝对路径或 ../ 越界。
  * 创建会话的一方需要能够被另一方直接连接；公网 IPv6 仍可能受主机/路由器防火墙影响。
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

	consolePrintf("
P2P Friend v%s
", appVersion)
	consolePrintln("========================================")
	consolePrintln("1) 创建会话（生成连接码）")
	consolePrintln("2) 加入会话（输入连接码）")
	consolePrintln("3) 退出")
	consolePrintln("")

	for {
		consolePrintf("请选择 [1/2/3]: ")
		line, err := in.ReadString('
')
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
	listenAddr := ":" + defaultPort
	ln, token, fingerprintHex, err := openTLSListener(listenAddr)
	if err != nil {
		return fmt.Errorf("创建会话失败（TCP %s）：%w", defaultPort, err)
	}
	defer ln.Close()

	consolePrintf("
[创建会话] 本地目录: %s
", cwd)
	consolePrintf("[创建会话] 会话端口: %s

", defaultPort)
	if err := printConnectionCodes(ln, token, fingerprintHex); err != nil {
		return err
	}
	consolePrintln("把上面一个可用的 P2P3-... 连接码发给朋友。")
	consolePrintln("等待朋友加入...（Ctrl+C 可取消）")

	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept peer: %w", err)
	}
	if err := authenticateListener(conn, token, roleHost); err != nil {
		conn.Close()
		return err
	}
	consolePrintf("
已建立直接加密连接：%s <-> %s
", conn.LocalAddr(), conn.RemoteAddr())
	return runPeerShell(conn, "HOST", cwd, in)
}

func runJoin(in *bufio.Reader, cwd string) error {
	consolePrintln("
[加入会话] 请粘贴朋友发来的 P2P3-... 连接码。")
	consolePrintf("连接码: ")
	line, err := in.ReadString('
')
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
	consolePrintf("
已建立直接加密连接：%s <-> %s
", conn.LocalAddr(), conn.RemoteAddr())
	return runPeerShell(conn, "JOIN", cwd, in)
}

func runPeerShell(conn net.Conn, roleName, cwd string, in *bufio.Reader) error {
	s := &peerSession{
		conn:     conn,
		br:       bufio.NewReaderSize(conn, copyBufferSize),
		bw:       bufio.NewWriterSize(conn, copyBufferSize),
		cwd:      cwd,
		roleName: roleName,
		closed:   make(chan struct{}),
	}
	defer s.close(false)

	go s.readLoop()

	consolePrintln("")
	consolePrintln("会话已就绪。双方都可以连续发送/接收，quit/exit 才退出。")
	consolePrintln("  put <path>  = 发送本地文件/目录")
	consolePrintln("  get <path>  = 从对方当前目录获取")
	consolePrintln("  help        = 查看全部命令")
	consolePrintln("")

	lines := make(chan string)
	readErr := make(chan error, 1)
	go func() {
		for {
			line, err := in.ReadString('
')
			if err != nil {
				if len(line) > 0 {
					lines <- line
				}
				readErr <- err
				return
			}
			lines <- line
		}
	}()

	for {
		consolePrintf("p2p[%s|put发送/get接收]> ", s.roleName)
		select {
		case <-s.closed:
			consolePrintln("
连接已关闭。")
			return nil
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				_ = s.sendBye()
				return nil
			}
			return err
		case line := <-lines:
			cmd, arg := splitCommand(line)
			if cmd == "" {
				continue
			}
			switch strings.ToLower(cmd) {
			case "put":
				if arg == "" {
					consolePrintln("用法: put <本地文件或目录>")
					continue
				}
				if err := s.put(arg); err != nil {
					consolePrintf("[SEND] 失败: %v
", err)
				} else {
					consolePrintln("[SEND] 完成。")
				}
			case "get":
				if arg == "" {
					consolePrintln("用法: get <对方当前目录下的相对路径>")
					continue
				}
				if err := s.requestGet(arg); err != nil {
					consolePrintf("[GET] 请求失败: %v
", err)
				} else {
					consolePrintf("[GET] 已请求: %s
", arg)
				}
			case "pwd":
				consolePrintln(s.getCwd())
			case "cd":
				if arg == "" {
					consolePrintln("用法: cd <本地目录>")
					continue
				}
				if err := s.changeDir(arg); err != nil {
					consolePrintf("cd: %v
", err)
				} else {
					consolePrintf("本地目录: %s
", s.getCwd())
				}
			case "ls", "dir":
				if err := s.listLocal(arg); err != nil {
					consolePrintf("ls: %v
", err)
				}
			case "overwrite":
				if err := s.setOverwrite(arg); err != nil {
					consolePrintln(err.Error())
				}
			case "status":
				consolePrintf("角色: %s
", s.roleName)
				consolePrintf("本地目录: %s
", s.getCwd())
				consolePrintf("覆盖同名文件: %s
", onOff(s.getOverwrite()))
				consolePrintf("连接: %s <-> %s
", conn.LocalAddr(), conn.RemoteAddr())
			case "help", "?":
				printShellHelp()
			case "quit", "exit", "bye":
				_ = s.sendBye()
				s.close(false)
				return nil
			default:
				consolePrintf("未知命令: %s（输入 help 查看命令）
", cmd)
			}
		}
	}
}

func printShellHelp() {
	consolePrintln(`命令：
  put <path>          发送本地文件或目录，目录自动递归
  get <path>          获取对方当前目录中的文件或目录
  ls [path]           查看本地目录
  cd <path>           修改本地当前目录
  pwd                 显示本地当前目录
  overwrite on|off    允许/禁止覆盖收到的同名文件（默认 off）
  status              显示当前会话状态
  help                显示帮助
  quit / exit         断开并退出

注意：
  get 的路径必须是对方当前目录下的相对路径，禁止绝对路径和 ../。
  对方执行 cd 后，会改变其可被 get 的目录范围，也会改变其接收文件的位置。`)
}

func splitCommand(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	idx := strings.IndexAny(line, " 	")
	if idx < 0 {
		return line, ""
	}
	cmd := line[:idx]
	arg := strings.TrimSpace(line[idx+1:])
	if len(arg) >= 2 {
		if (arg[0] == '"' && arg[len(arg)-1] == '"') || (arg[0] == ''' && arg[len(arg)-1] == ''') {
			arg = arg[1 : len(arg)-1]
		}
	}
	return cmd, arg
}
