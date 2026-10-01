package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
)

func initPeerSession(conn net.Conn, roleName, cwd string) *peerSession {
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
		roleName:   roleName,
	}
	return s
}

func (s *peerSession) readLoop() {
	defer s.close(false)
	for {
		f, err := readFrame(s.br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosedErr(err) {
				consolePrintf("\n[连接] 读取失败: %v\n", err)
			}
			return
		}
		switch f.Type {
		case frameRPCRequest:
			go s.handleRPCRequest(f.ID, f.Payload)
		case frameRPCResponse:
			if err := s.handleRPCResponse(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] RPC 响应无效: %v\n", err)
				return
			}
		case frameTransferStart:
			if err := s.handleTransferStart(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 传输开始无效: %v\n", err)
				return
			}
		case frameEntryStart:
			if err := s.handleEntryStart(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 文件项无效: %v\n", err)
				return
			}
		case frameData:
			if err := s.handleTransferData(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 数据帧无效: %v\n", err)
				return
			}
		case frameEntryEnd:
			if err := s.handleEntryEnd(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 文件结束帧无效: %v\n", err)
				return
			}
		case frameTransferEnd:
			if err := s.handleTransferEnd(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 传输结束帧无效: %v\n", err)
				return
			}
		case frameCancel:
			if err := s.handleCancel(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 取消帧无效: %v\n", err)
				return
			}
		case frameTransferResult:
			if err := s.handleTransferResult(f.ID, f.Payload); err != nil {
				consolePrintf("\n[协议] 传输结果无效: %v\n", err)
				return
			}
		case frameBye:
			consolePrintln("\n[连接] 对方已退出会话。")
			return
		default:
			consolePrintf("\n[协议] 未知帧类型: %d\n", f.Type)
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
		source, err := cleanExistingPath(s.getServeCwd(), req.Path)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		if _, _, _, err := buildEntries(source); err != nil {
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
			if err := s.sendTransfer(source, "", id, false, tid); err != nil && !errors.Is(err, context.Canceled) {
				consolePrintf("\n[GET->SEND] 失败: %v\n", err)
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
	if err := s.writeJSONFrame(frameRPCRequest, id, rpcRequest{Op: op, Path: path}); err != nil {
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
		return zero, fmt.Errorf("remote %s timeout", op)
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
	s.closeOnce.Do(func() {
		if sendBye {
			_ = s.writeFrame(frameBye, 0, nil)
		}
		_ = s.conn.Close()
		close(s.closed)
	})
}

func (s *peerSession) status() {
	consolePrintf("角色: %s\n", s.roleName)
	consolePrintf("本地目录: %s\n", s.getLocalCwd())
	consolePrintf("对方看到的本机目录: %s\n", s.getServeCwd())
	remote := s.getRemoteCwd()
	if remote == "" {
		remote = "<unknown>"
	}
	consolePrintf("远端目录: %s\n", remote)
	consolePrintf("本机接收覆盖: %s\n", onOff(s.getOverwrite()))
	consolePrintf("连接: %s <-> %s\n", s.conn.LocalAddr(), s.conn.RemoteAddr())
	consolePrintf("活动传输 ID: %v\n", s.debugActiveTransfers())
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func parseCommandLine(line string) ([]string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	var args []string
	var b strings.Builder
	var quote rune
	have := false
	for _, r := range line {
		if quote != 0 {
			if r == quote {
				quote = 0
				have = true
				continue
			}
			b.WriteRune(r)
			have = true
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			have = true
		case ' ', '\t':
			if have || b.Len() > 0 {
				args = append(args, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteRune(r)
			have = true
		}
	}
	if quote != 0 {
		return nil, errors.New("引号没有闭合")
	}
	if have || b.Len() > 0 {
		args = append(args, b.String())
	}
	return args, nil
}

func formatJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
