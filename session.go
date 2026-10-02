package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

func initPeerSession(conn net.Conn, roleName, cwd string) *peerSession {
	coordinator := roleName == "发起方" || roleName == "HOST" || roleName == "A"
	if p, ok := conn.(interface{ TransferCoordinator() bool }); ok {
		coordinator = p.TransferCoordinator()
	}
	s := &peerSession{
		conn:       conn,
		br:         bufio.NewReaderSize(conn, chunkSize*2),
		bw:         bufio.NewWriterSize(conn, chunkSize*2),
		closed:     make(chan struct{}),
		pendingRPC: make(map[uint64]chan rpcResponse),
		pendingGet: make(map[uint64]*pendingGet),
		outbound:   make(map[uint64]*outboundTransfer),
		inbound:    make(map[uint64]*inboundTransfer),
		localCwd:   cwd,
		serveCwd:   cwd,
		roleName:             roleName,
		linkMode:             connectionMode(conn),
		transferCoordinator: coordinator,
	}
	attachDataLanes(s, conn)
	return s
}

func (s *peerSession) readLoop() {
	defer s.close(false)
	for {
		f, err := readFrame(s.br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.reportTransportError("连接", err)
			}
			return
		}
		switch f.Type {
		case frameRPCRequest:
			go s.handleRPCRequest(f.ID, f.Payload)
		case frameRPCResponse:
			if err := s.handleRPCResponse(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] RPC 响应无效: %v\n", err)
				return
			}
		case frameTransferStart:
			if err := s.handleTransferStart(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 传输开始无效: %v\n", err)
				return
			}
		case frameEntryStart:
			if err := s.handleEntryStart(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 文件项无效: %v\n", err)
				return
			}
		case frameEntryReady:
			s.handleEntryReady(f.ID, f.Payload)
		case frameData:
			if err := s.handleTransferData(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 数据帧无效: %v\n", err)
				return
			}
		case frameEntryEnd:
			if err := s.handleEntryEnd(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 文件结束帧无效: %v\n", err)
				return
			}
		case frameTransferEnd:
			if err := s.handleTransferEnd(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 传输结束帧无效: %v\n", err)
				return
			}
		case frameCancel:
			if err := s.handleCancel(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 取消帧无效: %v\n", err)
				return
			}
		case frameTransferResult:
			if err := s.handleTransferResult(f.ID, f.Payload); err != nil {
				consolePrintf("[协议] 传输结果无效: %v\n", err)
				return
			}
		case frameBye:
			consolePrintln("[连接] 对方已退出会话。")
			return
		default:
			consolePrintf("[协议] 未知帧类型: %d\n", f.Type)
			return
		}
	}
}

func (s *peerSession) handleRPCRequest(id uint64, payload []byte) {
	var req rpcRequest
	if err := decodeJSON(payload, &req); err != nil {
		_ = s.writeJSONFrame(frameRPCResponse, id, rpcResponse{OK: false, Error: err.Error()})
		return
	}
	resp := rpcResponse{}
	switch req.Op {
	case "transfer_acquire":
		resp = s.handleTransferAcquire(req)
	case "transfer_release":
		resp = s.handleTransferRelease(req)
	case "pwd":
		resp.OK = true
		resp.Cwd = s.getServeCwd()
	case "ls":
		path, entries, err := listPath(s.getServeCwd(), req.Path)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		resp.OK = true
		resp.Cwd = path
		resp.Entries = entries
	case "cd":
		cur, prev := s.getServeDirs()
		next, nextPrev, err := changeDir(cur, prev, req.Path)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		s.setServeDirs(next, nextPrev)
		resp.OK = true
		resp.Cwd = next
	case "get":
		passiveLease := false
		if !s.transferCoordinator {
			s.notePassiveTransfer("GET", req.Path)
			passiveLease = true
		}
		source, err := cleanExistingPath(s.getServeCwd(), req.Path)
		if err != nil {
			if passiveLease {
				s.releasePassiveTransfer()
			}
			resp.Error = err.Error()
			break
		}
		if _, _, _, err := buildEntries(source); err != nil {
			if passiveLease {
				s.releasePassiveTransfer()
			}
			resp.Error = err.Error()
			break
		}
		tid := s.nextTransferID()
		resp.OK = true
		resp.TransferID = tid
		resp.Name = filepath.Base(filepath.Clean(source))
		if err := s.writeJSONFrame(frameRPCResponse, id, resp); err != nil {
			return
		}
		go func() {
			_ = s.sendTransfer(source, "", id, false, tid)
			if passiveLease {
				s.releasePassiveTransfer()
			}
		}()
		return
	default:
		resp.Error = "unknown RPC: " + req.Op
	}
	if !resp.OK && resp.Error == "" {
		resp.Error = "operation failed"
	}
	_ = s.writeJSONFrame(frameRPCResponse, id, resp)
}

func (s *peerSession) handleRPCResponse(id uint64, payload []byte) error {
	var resp rpcResponse
	if err := decodeJSON(payload, &resp); err != nil {
		return err
	}
	s.pendingMu.Lock()
	ch := s.pendingRPC[id]
	s.pendingMu.Unlock()
	if ch != nil {
		select {
		case ch <- resp:
		default:
		}
	}
	return nil
}

func (s *peerSession) callRPC(op, path string, timeout time.Duration) (rpcResponse, error) {
	id := s.nextRequestID()
	return s.callRPCWithID(id, op, path, timeout)
}

func (s *peerSession) callRPCWithID(id uint64, op, path string, timeout time.Duration) (rpcResponse, error) {
	return s.callRPCRequest(id, rpcRequest{Op: op, Path: path}, timeout)
}

func (s *peerSession) callRPCRequest(id uint64, req rpcRequest, timeout time.Duration) (rpcResponse, error) {
	var zero rpcResponse
	ch := make(chan rpcResponse, 1)
	s.pendingMu.Lock()
	s.pendingRPC[id] = ch
	s.pendingMu.Unlock()
	defer func() {
		s.pendingMu.Lock()
		delete(s.pendingRPC, id)
		s.pendingMu.Unlock()
	}()
	if err := s.writeJSONFrame(frameRPCRequest, id, req); err != nil {
		return zero, err
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	select {
	case resp := <-ch:
		if !resp.OK {
			if resp.Error == "" {
				resp.Error = "remote operation failed"
			}
			return resp, errors.New(resp.Error)
		}
		return resp, nil
	case <-s.closed:
		return zero, errors.New("connection closed")
	case <-time.After(timeout):
		return zero, fmt.Errorf("remote %s timeout", req.Op)
	}
}

func (s *peerSession) remotePwd() (string, error) {
	resp, err := s.callRPC("pwd", "", 10*time.Second)
	if err != nil {
		return "", err
	}
	s.setRemoteCwd(resp.Cwd)
	return resp.Cwd, nil
}

func (s *peerSession) remoteList(path string) error {
	resp, err := s.callRPC("ls", path, 15*time.Second)
	if err != nil {
		return err
	}
	consolePrintf("远端: %s\n", resp.Cwd)
	printEntries(resp.Entries)
	return nil
}

func (s *peerSession) remoteCd(path string) error {
	resp, err := s.callRPC("cd", path, 15*time.Second)
	if err != nil {
		return err
	}
	s.setRemoteCwd(resp.Cwd)
	consolePrintf("远端目录: %s\n", resp.Cwd)
	return nil
}

func (s *peerSession) get(remotePath, localDest string) error {
	if strings.TrimSpace(remotePath) == "" {
		return errors.New("get 需要远端路径")
	}
	leaseID, err := s.acquireTransferLease("GET", remotePath)
	if err != nil {
		return err
	}
	defer s.releaseTransferLease(leaseID)

	id := s.nextRequestID()
	pg := &pendingGet{dest: localDest, done: make(chan error, 1)}
	s.pendingMu.Lock()
	s.pendingGet[id] = pg
	s.pendingMu.Unlock()
	resp, err := s.callRPCWithID(id, "get", remotePath, 30*time.Second)
	if err != nil {
		s.pendingMu.Lock()
		delete(s.pendingGet, id)
		s.pendingMu.Unlock()
		return err
	}
	if resp.TransferID == 0 {
		s.pendingMu.Lock()
		delete(s.pendingGet, id)
		s.pendingMu.Unlock()
		return errors.New("remote get did not return a transfer id")
	}
	consolePrintf("[GET] %s -> %s\n", remotePath, localDisplay(localDest))
	select {
	case err := <-pg.done:
		return err
	case <-s.closed:
		return errors.New("connection closed during get")
	}
}

func localDisplay(dest string) string {
	if dest == "" {
		return "<local cwd>"
	}
	return dest
}

func (s *peerSession) getLocalCwd() string {
	s.localMu.RLock()
	defer s.localMu.RUnlock()
	return s.localCwd
}

func (s *peerSession) getLocalDirs() (string, string) {
	s.localMu.RLock()
	defer s.localMu.RUnlock()
	return s.localCwd, s.localPrevCwd
}

func (s *peerSession) setLocalDirs(cur, prev string) {
	s.localMu.Lock()
	s.localCwd = cur
	s.localPrevCwd = prev
	s.localMu.Unlock()
}

func (s *peerSession) getServeCwd() string {
	s.serveMu.RLock()
	defer s.serveMu.RUnlock()
	return s.serveCwd
}

func (s *peerSession) getServeDirs() (string, string) {
	s.serveMu.RLock()
	defer s.serveMu.RUnlock()
	return s.serveCwd, s.servePrevCwd
}

func (s *peerSession) setServeDirs(cur, prev string) {
	s.serveMu.Lock()
	s.serveCwd = cur
	s.servePrevCwd = prev
	s.serveMu.Unlock()
}

func (s *peerSession) setRemoteCwd(cwd string) {
	s.remoteMu.Lock()
	s.remoteCwd = cwd
	s.remoteMu.Unlock()
}

func (s *peerSession) getRemoteCwd() string {
	s.remoteMu.RLock()
	defer s.remoteMu.RUnlock()
	return s.remoteCwd
}

func (s *peerSession) getOverwrite() bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.overwrite
}

func (s *peerSession) setOverwrite(arg string) error {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "1", "yes", "true":
		s.stateMu.Lock()
		s.overwrite = true
		s.stateMu.Unlock()
		consolePrintln("本机接收覆盖: on")
		return nil
	case "off", "0", "no", "false":
		s.stateMu.Lock()
		s.overwrite = false
		s.stateMu.Unlock()
		consolePrintln("本机接收覆盖: off")
		return nil
	default:
		return errors.New("用法: overwrite on|off")
	}
}

func (s *peerSession) localCd(path string) error {
	cur, prev := s.getLocalDirs()
	next, nextPrev, err := changeDir(cur, prev, path)
	if err != nil {
		return err
	}
	s.setLocalDirs(next, nextPrev)
	consolePrintf("本地目录: %s\n", next)
	return nil
}

func (s *peerSession) localList(path string) error {
	resolved, entries, err := listPath(s.getLocalCwd(), path)
	if err != nil {
		return err
	}
	consolePrintf("本地: %s\n", resolved)
	printEntries(entries)
	return nil
}

func printEntries(entries []remoteEntry) {
	for _, e := range entries {
		if e.Dir {
			consolePrintf("<DIR>       %s\n", e.Name)
		} else {
			consolePrintf("%10s  %s\n", humanBytes(e.Size), e.Name)
		}
	}
}

func (s *peerSession) close(sendBye bool) {
	clearDataState(s)
	s.closeOnce.Do(func() {
		if sendBye {
			_ = s.writeFrame(frameBye, 0, nil)
		}
		_ = s.conn.Close()
		close(s.closed)
	})
}

func (s *peerSession) status() {
	consolePrintln("=== Session Status ===")
	consolePrintf("链路: %s\n", s.linkMode)
	consolePrintln("传输栈: QUIC / UDP / TLS 1.3")
	if p, ok := s.conn.(interface{ ConnectionInfo() quicConnectionInfo }); ok {
		info := p.ConnectionInfo()
		consolePrintf("QUIC 连接方式: %s\n", info.QUICRole)
		consolePrintf("本机选中 UDP: %s\n", info.LocalUDP)
		consolePrintf("对端选中 UDP: %s\n", info.RemoteUDP)
		consolePrintf("对端 candidate: %s\n", info.RemoteCandidateType)
		if info.QUICRole == "主动连接端" {
			consolePrintf("主动连接源端口: %s\n", info.LocalUDP)
		} else {
			consolePrintf("当前监听/传输端口: %s\n", info.LocalUDP)
		}
		consolePrintln("UDP sockets:")
		for _, ep := range info.Sockets {
			consolePrintf("  - %s\n", formatSocketStatus(ep))
		}
		if len(info.STUNMappings) > 0 {
			consolePrintln("本机 STUN 映射:")
			for _, addr := range info.STUNMappings {
				consolePrintf("  - %s\n", addr)
			}
		}
		consolePrintf("QUIC streams: control=1, data=%d\n", info.Streams)
		consolePrintln("端口关系: 连通性检查、NAT 打洞、QUIC 握手和文件传输复用选中的 UDP socket。")
	} else {
		consolePrintf("连接: %s <-> %s\n", s.conn.LocalAddr(), s.conn.RemoteAddr())
	}

	lease := s.leaseSnapshot()
	if lease.ID == 0 {
		consolePrintln("传输任务: idle")
	} else {
		consolePrintf("传输任务: busy / %s / %s / %s / %s\n",
			displayLeaseOwner(lease.Owner), lease.Kind, displayLeasePath(lease.Path), time.Since(lease.Since).Round(time.Second))
	}
	tuning := s.currentTuning()
	if tuning.lanes > 0 {
		consolePrintf("发送自适应: lanes=%d, chunk=%s, pacing=%s\n",
			tuning.lanes, humanBytes(int64(tuning.chunkSize)), tuning.pace)
	}

	consolePrintf("本地目录: %s\n", s.getLocalCwd())
	consolePrintf("对方看到的本机目录: %s\n", s.getServeCwd())
	remote := s.getRemoteCwd()
	if remote == "" {
		remote = "<unknown>"
	}
	consolePrintf("远端目录: %s\n", remote)
	consolePrintf("本机接收覆盖: %s\n", onOff(s.getOverwrite()))
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func parseCommandLine(line string) ([]string, error) {
	rs := []rune(strings.TrimSpace(line))
	if len(rs) == 0 {
		return nil, nil
	}
	var args []string
	var b strings.Builder
	quote := rune(0)
	have := false

	flush := func() {
		if have || b.Len() > 0 {
			args = append(args, b.String())
			b.Reset()
			have = false
		}
	}

	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if quote != 0 {
			if r == quote {
				quote = 0
				have = true
				continue
			}
			// 引号内保留反斜杠本身，避免破坏 Windows 路径 D:\dir\file。
			b.WriteRune(r)
			have = true
			continue
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		have = true
		switch r {
		case '\'', '"':
			quote = r
		case '\\':
			// 未加引号时只把“反斜杠 + 空白/引号”当作转义。
			// 其它反斜杠按字面保留，这样 Windows 路径无需双写。
			if i+1 < len(rs) {
				n := rs[i+1]
				if unicode.IsSpace(n) || n == '\'' || n == '"' {
					b.WriteRune(n)
					i++
					continue
				}
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, errors.New("引号没有闭合")
	}
	flush()
	return args, nil
}

func formatJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
