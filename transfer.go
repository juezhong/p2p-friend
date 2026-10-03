package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

func (s *peerSession) put(localPath, remoteDest string) error {
	base := s.getLocalCwd()
	source, err := cleanExistingPath(base, localPath)
	if err != nil {
		return err
	}
	leaseID, err := s.acquireTransferLease("PUT", localPath)
	if err != nil {
		return err
	}
	defer s.releaseTransferLease(leaseID)
	return s.sendTransfer(source, remoteDest, 0, true, 0)
}

// sendTransfer 同时服务 PUT 和远端 GET：GET 请求到达文件所在端后，仍复用同一套
// “发送端 -> 接收端”传输状态机。requestID!=0 表示这是响应远端 GET 的被动发送。
func (s *peerSession) sendTransfer(source, remoteDest string, requestID uint64, foreground bool, fixedID uint64) error {
	s.sendGate.Lock()
	defer s.sendGate.Unlock()

	entries, total, isDir, err := buildEntries(source)
	if err != nil {
		return err
	}

	if foreground {
		consolePrintf("[PUT] %s -> %s (%s)\n", source, remoteDisplay(remoteDest), humanBytes(total))
	}

	id := fixedID
	if id == 0 {
		id = s.nextTransferID()
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	ot := &outboundTransfer{
		id: id, ctx: ctx, cancel: cancel,
		result: make(chan transferResult, 1),
		done:   make(chan error, 1),
	}
	setOutboundReady(ot)
	s.transferMu.Lock()
	s.outbound[id] = ot
	s.transferMu.Unlock()
	defer func() {
		clearOutboundReady(ot)
		s.transferMu.Lock()
		delete(s.outbound, id)
		s.transferMu.Unlock()
		if foreground {
			s.clearForeground("send", id)
		}
	}()

	if foreground {
		s.setForeground("send", id)
	}
	name := filepath.Base(filepath.Clean(source))
	meta := transferStart{Name: name, Dest: remoteDest, Total: total, IsDir: isDir, RequestID: requestID}
	if err := s.writeJSONFrame(frameTransferStart, id, meta); err != nil {
		return fmt.Errorf("send transfer start: %w", err)
	}

	prefix := "[PUT]"
	if requestID != 0 {
		prefix = "[SEND]"
	}
	p := &progress{
		Start: time.Now(), LastPrint: time.Now(), Total: total,
		Prefix: prefix, Silent: !foreground, Multi: isDir,
	}
	defer p.closeLine()
	defer s.clearCurrentTuning()

	for _, e := range entries {
		if cause := context.Cause(ctx); cause != nil {
			return s.finishCancelledOutbound(ot, cause)
		}
		start := entryStart{Path: e.RelPath, Mode: uint32(e.Mode.Perm()), Size: e.Size, Dir: e.IsDir}
		if err := s.writeJSONFrame(frameEntryStart, id, start); err != nil {
			return fmt.Errorf("send entry start %s: %w", e.RelPath, err)
		}
		if e.IsDir {
			continue
		}
		// 接收端先创建/校验目标路径并回复 EntryReady，再开始发送该文件数据，
		// 避免发送端已经大量写入 QUIC 后才发现目标不可写。
		if err := s.waitEntryReady(ot, e.RelPath); err != nil {
			if cause := context.Cause(ctx); cause != nil {
				return s.finishCancelledOutbound(ot, cause)
			}
			return err
		}

		p.beginFile(e.RelPath, e.Size)
		sum, err := s.sendFileStriped(ctx, id, e.FullPath, e.Size, p)
		if err != nil {
			if cause := context.Cause(ctx); cause != nil {
				return s.finishCancelledOutbound(ot, cause)
			}
			return fmt.Errorf("send %s: %w", e.RelPath, err)
		}
		p.print(true)
		if foreground {
			consolePrintf("[PUT] SHA-256 %s  %x\n", e.RelPath, sum)
		}
		if err := s.writeFrame(frameEntryEnd, id, sum); err != nil {
			return fmt.Errorf("send checksum %s: %w", e.RelPath, err)
		}
	}

	if err := s.writeJSONFrame(frameTransferEnd, id, transferEnd{}); err != nil {
		return fmt.Errorf("send transfer end: %w", err)
	}
	return s.waitTransferResult(ot)
}

func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 1024*1024)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (s *peerSession) waitEntryReady(ot *outboundTransfer, path string) error {
	for {
		select {
		case got := <-getOutboundReady(ot):
			if got == path {
				return nil
			}
		case <-ot.ctx.Done():
			return context.Cause(ot.ctx)
		case <-s.closed:
			return errors.New("connection closed while waiting receiver")
		case <-time.After(20 * time.Second):
			return fmt.Errorf("timeout waiting receiver to prepare %s", path)
		}
	}
}

func (s *peerSession) sendFileStriped(ctx context.Context, id uint64, path string, size int64, p *progress) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ds := dataState(s)
	if ds == nil || len(ds.lanes) == 0 {
		h := sha256.New()
		buf := make([]byte, maxDataChunkSize)
		var off int64
		for off < size {
			select {
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			default:
			}
			want := int64(len(buf))
			if size-off < want {
				want = size - off
			}
			n, rerr := f.Read(buf[:want])
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return nil, rerr
			}
			if n == 0 {
				return nil, io.ErrUnexpectedEOF
			}
			_, _ = h.Write(buf[:n])
			if err := s.writeDataChunk(id, off, buf[:n]); err != nil {
				return nil, err
			}
			off += int64(n)
			p.addBytes(int64(n))
		}
		return h.Sum(nil), nil
	}

	profile := fastTransferProfile(len(ds.lanes))
	s.setCurrentTuning(profile)
	defer s.clearCurrentTuning()

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	type laneJob struct {
		chunk preparedDataChunk
	}
	jobs := make(chan laneJob, profile.lanes*sendQueueDepthPerLane)
	errCh := make(chan error, profile.lanes)
	var workers sync.WaitGroup
	for lane := 0; lane < profile.lanes; lane++ {
		workers.Add(1)
		go func(lane int) {
			defer workers.Done()
			for job := range jobs {
				if context.Cause(ctx) != nil {
					releaseDataBuffer(job.chunk.buf)
					continue
				}
				err := s.writePreparedDataChunkOnLane(lane, id, job.chunk)
				releaseDataBuffer(job.chunk.buf)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel(err)
					continue
				}
				p.addBytes(int64(job.chunk.payloadLen))
			}
		}(lane)
	}

	jobsClosed := false
	defer func() {
		if !jobsClosed {
			close(jobs)
		}
		workers.Wait()
	}()

	h := sha256.New()
	var off int64
	for off < size {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		buf := acquireDataBuffer()
		want := int64(maxDataChunkSize)
		if size-off < want {
			want = size - off
		}
		n, rerr := f.Read(buf[dataHeaderSize:dataHeaderSize+int(want)])
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			releaseDataBuffer(buf)
			return nil, rerr
		}
		if n == 0 {
			releaseDataBuffer(buf)
			return nil, io.ErrUnexpectedEOF
		}
		_, _ = h.Write(buf[dataHeaderSize : dataHeaderSize+n])

		job := laneJob{chunk: preparedDataChunk{buf: buf, offset: off, payloadLen: n}}
		select {
		case jobs <- job:
			off += int64(n)
		case <-ctx.Done():
			releaseDataBuffer(buf)
			return nil, context.Cause(ctx)
		}
	}

	close(jobs)
	jobsClosed = true
	workers.Wait()

	select {
	case werr := <-errCh:
		if werr != nil {
			return nil, werr
		}
	default:
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	return h.Sum(nil), nil
}

func (s *peerSession) handleEntryReady(id uint64, payload []byte) {
	s.transferMu.Lock()
	ot := s.outbound[id]
	s.transferMu.Unlock()
	if ot == nil {
		return
	}
	ch := getOutboundReady(ot)
	if ch == nil {
		return
	}
	select {
	case ch <- string(payload):
	default:
	}
}

func (s *peerSession) finishCancelledOutbound(ot *outboundTransfer, cause error) error {
	reason := "传输已取消"
	if cause != nil {
		reason = cause.Error()
	}
	_ = s.writeJSONFrame(frameTransferEnd, ot.id, transferEnd{Cancelled: true, Error: reason})
	resErr := s.waitTransferResult(ot)
	if resErr != nil && !errors.Is(resErr, context.Canceled) {
		return fmt.Errorf("%s: %w", reason, resErr)
	}
	return fmt.Errorf("%w: %s", context.Canceled, reason)
}

func (s *peerSession) waitTransferResult(ot *outboundTransfer) error {
	select {
	case res := <-ot.result:
		if res.OK {
			return nil
		}
		if res.Cancelled {
			if res.Error == "" {
				res.Error = "peer cancelled transfer"
			}
			return fmt.Errorf("%w: %s", context.Canceled, res.Error)
		}
		if res.Error == "" {
			res.Error = "peer rejected transfer"
		}
		return errors.New(res.Error)
	case <-s.closed:
		return errors.New("connection closed before transfer result")
	case <-time.After(30 * time.Second):
		return errors.New("timeout waiting for transfer result")
	}
}

func remoteDisplay(dest string) string {
	if dest == "" {
		return "<remote cwd>"
	}
	return dest
}

func (s *peerSession) handleTransferStart(id uint64, payload []byte) error {
	var meta transferStart
	if err := decodeJSON(payload, &meta); err != nil {
		return err
	}
	if meta.Name == "" || meta.Total < 0 {
		return errors.New("invalid transfer metadata")
	}

	base := s.getServeCwd()
	dest := meta.Dest
	if meta.RequestID != 0 {
		s.pendingMu.Lock()
		pg := s.pendingGet[meta.RequestID]
		s.pendingMu.Unlock()
		if pg == nil {
			_ = s.writeJSONFrame(frameCancel, id, transferEnd{Cancelled: true, Error: "unexpected get transfer"})
			return nil
		}
		base = s.getLocalCwd()
		dest = pg.dest
	}

	root, err := resolveReceiveRoot(base, dest, meta.Name)
	activeUI := meta.RequestID != 0
	recvPrefix := "[RECV]"
	if activeUI {
		recvPrefix = "[GET]"
	}
	if !s.transferCoordinator && !activeUI {
		s.notePassiveTransfer("PUT", meta.Name)
	}
	t := &inboundTransfer{
		id:         id,
		meta:       meta,
		targetRoot: root,
		progress: &progress{
			Start: time.Now(), LastPrint: time.Now(), Total: meta.Total,
			Prefix: recvPrefix, Silent: !activeUI, Multi: meta.IsDir,
		},
		getReqID: meta.RequestID,
	}
	if err != nil {
		t.cancelled = true
		t.cancelWhy = err.Error()
	}
	s.transferMu.Lock()
	if _, exists := s.inbound[id]; exists {
		s.transferMu.Unlock()
		return fmt.Errorf("duplicate transfer id: %d", id)
	}
	s.inbound[id] = t
	s.transferMu.Unlock()

	if meta.RequestID != 0 {
		s.setForeground("recv", id)
	}
	t.mu.Lock()
	cancelled := t.cancelled
	cancelWhy := t.cancelWhy
	t.mu.Unlock()
	if cancelled {
		_ = s.writeJSONFrame(frameCancel, id, transferEnd{Cancelled: true, Error: cancelWhy})
		return nil
	}
	if meta.RequestID != 0 {
		consolePrintf("[GET] %s -> %s (%s)\n", meta.Name, root, humanBytes(meta.Total))
	}
	return nil
}

func (s *peerSession) handleEntryStart(id uint64, payload []byte) error {
	t := s.getInbound(id)
	if t == nil {
		return fmt.Errorf("entry for unknown transfer %d", id)
	}
	var e entryStart
	if err := decodeJSON(payload, &e); err != nil {
		s.cancelInbound(id, "invalid entry metadata: "+err.Error(), false)
		return nil
	}

	t.mu.Lock()
	if t.cancelled {
		t.mu.Unlock()
		return nil
	}
	if t.currentFile != nil {
		t.markCancelledLocked("new entry arrived before previous file finished")
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}
	dst, err := transferEntryDestination(t.targetRoot, t.meta.Name, e.Path)
	if err != nil {
		t.markCancelledLocked(err.Error())
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}

	if e.Dir {
		created, err := ensureReceiveDir(dst, os.FileMode(e.Mode))
		if err != nil {
			t.markCancelledLocked(err.Error())
			reason := t.cancelWhy
			t.mu.Unlock()
			go s.sendCancel(id, reason)
			return nil
		}
		t.createdDirs = append(t.createdDirs, created...)
		t.mu.Unlock()
		return nil
	}

	if e.Size < 0 {
		t.markCancelledLocked("negative file size")
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}
	createdParents, err := ensureReceiveDir(filepath.Dir(dst), 0o755)
	if err != nil {
		t.markCancelledLocked(err.Error())
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}
	t.createdDirs = append(t.createdDirs, createdParents...)

	existed := false
	if st, err := os.Lstat(dst); err == nil {
		existed = true
		if st.Mode()&os.ModeSymlink != 0 {
			t.markCancelledLocked("refusing to overwrite symlink: " + dst)
			reason := t.cancelWhy
			t.mu.Unlock()
			go s.sendCancel(id, reason)
			return nil
		}
		if st.IsDir() {
			t.markCancelledLocked("destination is a directory: " + dst)
			reason := t.cancelWhy
			t.mu.Unlock()
			go s.sendCancel(id, reason)
			return nil
		}
		if !s.getOverwrite() {
			t.markCancelledLocked("目标已存在: " + dst + "（接收方可执行 overwrite on 后重试）")
			reason := t.cancelWhy
			t.mu.Unlock()
			go s.sendCancel(id, reason)
			return nil
		}
	} else if !os.IsNotExist(err) {
		t.markCancelledLocked(err.Error())
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".p2p-friend-*.part")
	if err != nil {
		t.markCancelledLocked(err.Error())
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}
	if err := tmp.Truncate(e.Size); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		t.markCancelledLocked(err.Error())
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}
	t.currentPath = dst
	t.currentFile = tmp
	t.currentTemp = tmp.Name()
	t.currentRemaining = e.Size
	startInboundData(s, id, t, e.Size, tmp)
	t.currentMode = os.FileMode(e.Mode)
	t.progress.beginFile(e.Path, e.Size)
	if existed {
		t.overwritten = append(t.overwritten, dst)
	}
	t.mu.Unlock()

	return s.writeFrame(frameEntryReady, id, []byte(e.Path))
}

func (s *peerSession) handleTransferData(id uint64, payload []byte) error {
	if len(payload) < 8 {
		return errors.New("data frame missing offset")
	}
	offset := int64(binary.BigEndian.Uint64(payload[:8]))
	return s.handleTransferDataAt(id, offset, payload[8:])
}

func (s *peerSession) handleTransferDataAt(id uint64, offset int64, payload []byte) error {
	if len(payload) > maxDataChunkSize {
		return fmt.Errorf("data chunk too large: %d", len(payload))
	}
	buf := acquireDataBuffer()
	copy(buf[dataHeaderSize:], payload)
	return s.handleTransferDataOwned(id, offset, buf, len(payload))
}

func (s *peerSession) handleEntryEnd(id uint64, payload []byte) error {
	t := s.getInbound(id)
	if t == nil {
		return fmt.Errorf("entry end for unknown transfer %d", id)
	}

	t.mu.Lock()
	if t.cancelled {
		t.cleanupCurrentLocked()
		t.mu.Unlock()
		return nil
	}
	st := getInboundData(t)
	if t.currentFile == nil || st == nil {
		t.markCancelledLocked("file end without active file")
		reason := t.cancelWhy
		t.mu.Unlock()
		go s.sendCancel(id, reason)
		return nil
	}
	done := st.done
	t.mu.Unlock()

	select {
	case <-done:
	case <-time.After(90 * time.Second):
		s.cancelInbound(id, "timeout waiting for parallel data streams", true)
		return nil
	case <-s.closed:
		return errors.New("connection closed while receiving file")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancelled {
		t.cleanupCurrentLocked()
		return nil
	}
	st = getInboundData(t)
	if st == nil {
		t.markCancelledLocked("data state missing")
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	written, actual, writeErr := st.result()
	if writeErr != nil || written != t.currentRemaining {
		if writeErr == nil {
			writeErr = fmt.Errorf("file ended with %d/%d bytes", written, t.currentRemaining)
		}
		t.markCancelledLocked(writeErr.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	if len(payload) != sha256.Size {
		t.markCancelledLocked("invalid SHA-256 length")
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}

	path := t.currentPath
	tmp := t.currentTemp
	mode := t.currentMode
	f := t.currentFile
	if err := f.Sync(); err != nil {
		t.markCancelledLocked(err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	t.progress.print(true)
	if !equalBytes(actual, payload) {
		if !t.progress.Silent {
			consolePrintf("%s SHA-256 %x  FAIL（发送端 %x）\n", t.progress.Prefix, actual, payload)
		}
		t.markCancelledLocked("SHA-256 mismatch for " + path)
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	if !t.progress.Silent {
		consolePrintf("%s SHA-256 %x  OK\n", t.progress.Prefix, actual)
	}

	if err := f.Chmod(mode.Perm()); err != nil && runtime.GOOS != "windows" {
		t.markCancelledLocked(err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	if err := f.Close(); err != nil {
		t.currentFile = nil
		t.markCancelledLocked(err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	t.currentFile = nil

	existed := false
	if st, err := os.Lstat(path); err == nil {
		existed = true
		if st.IsDir() {
			t.markCancelledLocked("cannot overwrite directory with file: " + path)
			go s.sendCancel(id, t.cancelWhy)
			return nil
		}
		if err := os.Remove(path); err != nil {
			t.markCancelledLocked("remove existing file: " + err.Error())
			go s.sendCancel(id, t.cancelWhy)
			return nil
		}
	} else if !os.IsNotExist(err) {
		t.markCancelledLocked(err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	if err := os.Rename(tmp, path); err != nil {
		t.markCancelledLocked("finalize file: " + err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	t.currentTemp = ""
	t.currentPath = ""
	t.currentRemaining = 0
	clearInboundData(t)
	if !existed {
		t.createdFiles = append(t.createdFiles, path)
	}
	return nil
}

func (s *peerSession) handleTransferEnd(id uint64, payload []byte) error {
	t := s.getInbound(id)
	if t == nil {
		return fmt.Errorf("transfer end for unknown transfer %d", id)
	}
	var end transferEnd
	if len(payload) > 0 {
		if err := decodeJSON(payload, &end); err != nil {
			end.Cancelled = true
			end.Error = "invalid transfer end: " + err.Error()
		}
	}

	t.mu.Lock()
	if end.Cancelled && !t.cancelled {
		t.markCancelledLocked(end.Error)
	}
	if t.currentFile != nil || t.currentTemp != "" {
		t.cleanupCurrentLocked()
	}
	if t.cancelled {
		t.rollbackCreatedLocked()
	}
	cancelled := t.cancelled
	reason := t.cancelWhy
	overwrote := append([]string(nil), t.overwritten...)
	t.progress.closeLine()
	t.mu.Unlock()

	res := transferResult{OK: !cancelled, Cancelled: cancelled, Error: reason}
	if err := s.writeJSONFrame(frameTransferResult, id, res); err != nil {
		return err
	}

	s.transferMu.Lock()
	delete(s.inbound, id)
	s.transferMu.Unlock()
	if t.getReqID != 0 {
		s.pendingMu.Lock()
		pg := s.pendingGet[t.getReqID]
		delete(s.pendingGet, t.getReqID)
		s.pendingMu.Unlock()
		if pg != nil {
			if cancelled {
				pg.done <- fmt.Errorf("%w: %s", context.Canceled, reason)
			} else {
				pg.done <- nil
			}
		}
	}
	s.clearForeground("recv", id)

	if !s.transferCoordinator && t.getReqID == 0 {
		s.releasePassiveTransfer()
	}
	if !t.progress.Silent && cancelled && len(overwrote) > 0 {
		consolePrintf("%s 注意：overwrite on 时已完成覆盖的文件无法自动恢复：\n", t.progress.Prefix)
		for _, p := range overwrote {
			consolePrintf("  %s\n", p)
		}
	}
	return nil
}

func (s *peerSession) handleTransferResult(id uint64, payload []byte) error {
	var res transferResult
	if err := decodeJSON(payload, &res); err != nil {
		return err
	}
	s.transferMu.Lock()
	ot := s.outbound[id]
	s.transferMu.Unlock()
	if ot != nil {
		select {
		case ot.result <- res:
		default:
		}
	}
	return nil
}

func (s *peerSession) handleCancel(id uint64, payload []byte) error {
	var end transferEnd
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &end)
	}
	reason := end.Error
	if reason == "" {
		reason = "对方取消传输"
	}
	s.transferMu.Lock()
	ot := s.outbound[id]
	s.transferMu.Unlock()
	if ot != nil {
		ot.cancel(errors.New(reason))
	}
	return nil
}

func (s *peerSession) cancelActive(reason string) bool {
	s.fgMu.Lock()
	fg := s.foreground
	s.fgMu.Unlock()
	if fg.id != 0 {
		if fg.direction == "send" {
			s.transferMu.Lock()
			ot := s.outbound[fg.id]
			s.transferMu.Unlock()
			if ot != nil {
				ot.cancel(errors.New(reason))
				return true
			}
		}
		if fg.direction == "recv" {
			return s.cancelInbound(fg.id, reason, true)
		}
	}

	s.transferMu.Lock()
	var inID uint64
	for id := range s.inbound {
		inID = id
		break
	}
	var out *outboundTransfer
	if inID == 0 {
		for _, t := range s.outbound {
			out = t
			break
		}
	}
	s.transferMu.Unlock()
	if inID != 0 {
		return s.cancelInbound(inID, reason, true)
	}
	if out != nil {
		out.cancel(errors.New(reason))
		return true
	}
	return false
}

func (s *peerSession) cancelInbound(id uint64, reason string, notifyPeer bool) bool {
	t := s.getInbound(id)
	if t == nil {
		return false
	}
	t.mu.Lock()
	if t.cancelled {
		t.mu.Unlock()
		return true
	}
	t.markCancelledLocked(reason)
	t.rollbackCreatedLocked()
	t.mu.Unlock()
	if notifyPeer {
		s.sendCancel(id, reason)
	}
	return true
}

func (s *peerSession) sendCancel(id uint64, reason string) {
	_ = s.writeJSONFrame(frameCancel, id, transferEnd{Cancelled: true, Error: reason})
}

func (s *peerSession) getInbound(id uint64) *inboundTransfer {
	s.transferMu.Lock()
	defer s.transferMu.Unlock()
	return s.inbound[id]
}

func (t *inboundTransfer) markCancelledLocked(reason string) {
	if t.cancelled {
		return
	}
	if reason == "" {
		reason = "传输已取消"
	}
	t.cancelled = true
	t.cancelWhy = reason
	t.cleanupCurrentLocked()
}

func (t *inboundTransfer) cleanupCurrentLocked() {
	clearInboundData(t)
	if t.currentFile != nil {
		_ = t.currentFile.Close()
		t.currentFile = nil
	}
	if t.currentTemp != "" {
		if err := os.Remove(t.currentTemp); err != nil && !os.IsNotExist(err) {
			consolePrintf("%s 无法删除临时文件 %s，请手动删除：%v\n", t.progress.Prefix, t.currentTemp, err)
		}
		t.currentTemp = ""
	}
	t.currentPath = ""
	t.currentHash = nil
	t.currentRemaining = 0
}

func (t *inboundTransfer) rollbackCreatedLocked() {
	t.cleanupCurrentLocked()
	for i := len(t.createdFiles) - 1; i >= 0; i-- {
		p := t.createdFiles[i]
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			consolePrintf("%s 无法删除已接收文件 %s，请手动删除：%v\n", t.progress.Prefix, p, err)
		}
	}
	for i := len(t.createdDirs) - 1; i >= 0; i-- {
		p := t.createdDirs[i]
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			// 非空目录可能包含传输前已有内容，不能强制递归删除。
			consolePrintf("%s 目录未自动删除 %s：%v\n", t.progress.Prefix, p, err)
		}
	}
	t.createdFiles = nil
	t.createdDirs = nil
}

func ensureReceiveDir(path string, mode os.FileMode) ([]string, error) {
	if err := ensureNoSymlinkParents(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to use symlinked directory: %s", path)
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("destination exists and is not a directory: %s", path)
		}
		return nil, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	var missing []string
	cur := path
	for {
		if st, err := os.Lstat(cur); err == nil {
			if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
				return nil, fmt.Errorf("invalid parent directory: %s", cur)
			}
			break
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		missing = append(missing, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	if err := os.MkdirAll(path, mode.Perm()); err != nil {
		return nil, err
	}
	// rollback 时按反向删除；这里保存从父到子的顺序。
	for i, j := 0, len(missing)-1; i < j; i, j = i+1, j-1 {
		missing[i], missing[j] = missing[j], missing[i]
	}
	return missing, nil
}

func ensureNoSymlinkParents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	vol := filepath.VolumeName(abs)
	rest := abs[len(vol):]
	parts := splitPathParts(rest)
	current := vol + string(os.PathSeparator)
	if vol == "" && !filepath.IsAbs(abs) {
		current = ""
	}
	for _, part := range parts {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlinked directory: %s", current)
		}
	}
	return nil
}

func splitPathParts(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		sep := r == '/' || r == '\\'
		if !sep && start < 0 {
			start = i
		}
		if sep && start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *peerSession) setForeground(direction string, id uint64) {
	s.fgMu.Lock()
	s.foreground = foregroundTransfer{direction: direction, id: id}
	s.fgMu.Unlock()
}

func (s *peerSession) clearForeground(direction string, id uint64) {
	s.fgMu.Lock()
	if s.foreground.direction == direction && s.foreground.id == id {
		s.foreground = foregroundTransfer{}
	}
	s.fgMu.Unlock()
}

func (s *peerSession) debugActiveTransfers() []uint64 {
	s.transferMu.Lock()
	defer s.transferMu.Unlock()
	ids := make([]uint64, 0, len(s.inbound)+len(s.outbound))
	for id := range s.inbound {
		ids = append(ids, id)
	}
	for id := range s.outbound {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
