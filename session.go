package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (s *peerSession) put(path string) error {
	full, err := resolveLocalPath(s.getCwd(), path)
	if err != nil {
		return err
	}
	return s.sendPath(full, "SEND")
}

func (s *peerSession) requestGet(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("empty path")
	}
	if filepath.IsAbs(filepath.FromSlash(path)) || filepath.VolumeName(filepath.FromSlash(path)) != "" {
		return errors.New("get 只接受对方当前目录下的相对路径")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return errors.New("get 不允许使用 ../ 越出对方当前目录")
	}
	return s.writeMessage(func(w *bufio.Writer) error {
		if err := w.WriteByte(msgGetRequest); err != nil {
			return err
		}
		return writeText(w, filepath.ToSlash(clean))
	})
}

func (s *peerSession) sendPath(fullPath, prefix string) error {
	entries, total, err := buildEntries(fullPath)
	if err != nil {
		return err
	}
	label := filepath.Base(filepath.Clean(fullPath))

	return s.writeMessage(func(w *bufio.Writer) error {
		if err := w.WriteByte(msgTransfer); err != nil {
			return err
		}
		if err := writeText(w, label); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint64(total)); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
		consolePrintf("[%s] %s (%s)\n", prefix, fullPath, humanBytes(total))
		return sendSessionWriter(w, entries, total, "["+prefix+"]")
	})
}

func (s *peerSession) sendRequested(request string) {
	base := s.getCwd()
	full, err := safeRequestedPath(base, request)
	if err != nil {
		_ = s.sendError(fmt.Sprintf("get %q 被拒绝: %v", request, err))
		return
	}
	consolePrintf("\n[GET->SEND] 对方请求: %s\n", request)
	if err := s.sendPath(full, "GET->SEND"); err != nil {
		_ = s.sendError(fmt.Sprintf("无法发送 %q: %v", request, err))
		consolePrintf("[GET->SEND] 失败: %v\n", err)
		return
	}
	consolePrintln("[GET->SEND] 完成。")
}

func (s *peerSession) sendError(text string) error {
	return s.writeMessage(func(w *bufio.Writer) error {
		if err := w.WriteByte(msgError); err != nil {
			return err
		}
		return writeText(w, text)
	})
}

func (s *peerSession) sendBye() error {
	return s.writeMessage(func(w *bufio.Writer) error {
		return w.WriteByte(msgBye)
	})
}

func (s *peerSession) writeMessage(fn func(*bufio.Writer) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.closed:
		return errors.New("connection is closed")
	default:
	}
	if err := fn(s.bw); err != nil {
		s.close(false)
		return err
	}
	if err := s.bw.Flush(); err != nil {
		s.close(false)
		return err
	}
	return nil
}

func (s *peerSession) readLoop() {
	defer s.close(false)
	for {
		typ, err := s.br.ReadByte()
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosedErr(err) {
				consolePrintf("\n[连接] 读取失败: %v\n", err)
			}
			return
		}
		switch typ {
		case msgTransfer:
			label, err := readText(s.br)
			if err != nil {
				consolePrintf("\n[RECV] 无法读取传输信息: %v\n", err)
				return
			}
			var total uint64
			if err := binary.Read(s.br, binary.BigEndian, &total); err != nil {
				consolePrintf("\n[RECV] 无法读取文件大小: %v\n", err)
				return
			}
			if total > uint64(^uint64(0)>>1) {
				consolePrintln("\n[RECV] 传输大小超过实现限制。")
				return
			}
			out := s.getCwd()
			consolePrintf("\n[RECV] %s -> %s\n", label, out)
			if err := receiveSessionReader(s.br, out, s.getOverwrite(), int64(total), "[RECV]"); err != nil {
				consolePrintf("\n[RECV] 失败: %v\n", err)
				consolePrintln("[RECV] 为避免协议流错位，本次连接将关闭。")
				return
			}
			consolePrintln("[RECV] 完成。")
		case msgGetRequest:
			request, err := readText(s.br)
			if err != nil {
				consolePrintf("\n[GET] 无法读取请求: %v\n", err)
				return
			}
			go s.sendRequested(request)
		case msgError:
			text, err := readText(s.br)
			if err != nil {
				consolePrintf("\n[PEER] 无法读取错误信息: %v\n", err)
				return
			}
			consolePrintf("\n[PEER] %s\n", text)
		case msgBye:
			consolePrintln("\n[连接] 对方已退出会话。")
			return
		default:
			consolePrintf("\n[连接] 未知协议消息: %d\n", typ)
			return
		}
	}
}

func (s *peerSession) close(sendBye bool) {
	s.closeOnce.Do(func() {
		if sendBye {
			_ = s.sendBye()
		}
		_ = s.conn.Close()
		close(s.closed)
	})
}

func (s *peerSession) getCwd() string {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.cwd
}

func (s *peerSession) getOverwrite() bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.overwrite
}

func (s *peerSession) changeDir(path string) error {
	full, err := resolveLocalPath(s.getCwd(), path)
	if err != nil {
		return err
	}
	st, err := os.Stat(full)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("not a directory: %s", path)
	}
	s.stateMu.Lock()
	s.cwd = full
	s.stateMu.Unlock()
	return nil
}

func (s *peerSession) setOverwrite(arg string) error {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "1", "yes", "true":
		s.stateMu.Lock()
		s.overwrite = true
		s.stateMu.Unlock()
		consolePrintln("覆盖同名文件: on")
		return nil
	case "off", "0", "no", "false":
		s.stateMu.Lock()
		s.overwrite = false
		s.stateMu.Unlock()
		consolePrintln("覆盖同名文件: off")
		return nil
	default:
		return errors.New("用法: overwrite on|off")
	}
}

func (s *peerSession) listLocal(arg string) error {
	path := s.getCwd()
	var err error
	if strings.TrimSpace(arg) != "" {
		path, err = resolveLocalPath(path, arg)
		if err != nil {
			return err
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		consolePrintf("%10s  %s\n", humanBytes(st.Size()), filepath.Base(path))
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			consolePrintf("?          %s\n", e.Name())
			continue
		}
		if e.IsDir() {
			consolePrintf("<DIR>      %s%c\n", e.Name(), os.PathSeparator)
		} else {
			consolePrintf("%10s  %s\n", humanBytes(info.Size()), e.Name())
		}
	}
	return nil
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
