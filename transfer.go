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
	hashes := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		sum, err := fileSHA256(e.FullPath)
		if err != nil {
			return fmt.Errorf("hash %s: %w", e.FullPath, err)
		}
		hashes[e.RelPath] = sum
		if foreground {
			consolePrintf("[PUT] SHA-256 %s  %x\n", e.RelPath, sum)
		}
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
		Prefix: prefix, Silent: !foreground,
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
		if err := s.waitEntryReady(ot, e.RelPath); err != nil {
			if cause := context.Cause(ctx); cause != nil {
				return s.finishCancelledOutbound(ot, cause)
			}
			return err
		}

		p.Current = e.RelPath
		p.CurrentDone = 0
		p.CurrentSize = e.Size
		if err := s.sendFileStriped(ctx, id, e.FullPath, e.Size, p); err != nil {
			if cause := context.Cause(ctx); cause != nil {
				return s.finishCancelledOutbound(ot, cause)
			}
			return fmt.Errorf("send %s: %w", e.RelPath, err)
		}
		p.print(true)
		if err := s.writeFrame(frameEntryEnd, id, hashes[e.RelPath]); err != nil {
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

func (s *peerSession) sendFileStriped(ctx context.Context, id uint64, path string, size int64, p *progress) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	ds := dataState(s)
	maxLanes := 1
	if ds != nil && len(ds.lanes) > 0 {
		maxLanes = len(ds.lanes)
	}
	tuner := currentTransferTuner(maxLanes)
	nextOff := int64(0)
	for nextOff < size {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}

		profile := tuner.current()
		if ds == nil || len(ds.lanes) == 0 {
			profile.lanes = 1
		}
		s.setCurrentTuning(profile)

		type chunkJob struct {
			lane int
			off  int64
			data []byte
		}
		jobs := make([]chunkJob, 0, profile.lanes)
		for lane := 0; lane < profile.lanes && nextOff < size; lane++ {
			nwant := int64(profile.chunkSize)
			if size-nextOff < nwant {
				nwant = size - nextOff
			}
			buf := make([]byte, int(nwant))
			n, rerr := f.ReadAt(buf, nextOff)
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return rerr
			}
			if n == 0 {
				return io.ErrUnexpectedEOF
			}
			buf = buf[:n]
			jobs = append(jobs, chunkJob{lane: lane, off: nextOff, data: buf})
			nextOff += int64(n)
		}

		start := time.Now()
		errCh := make(chan error, len(jobs))
		var wg sync.WaitGroup
		for _, job := range jobs {
			job := job
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ds == nil || len(ds.lanes) == 0 {
					errCh <- s.writeDataChunk(id, job.off, job.data)
					return
				}
				errCh <- s.writeDataChunkOnLane(job.lane, id, job.off, job.data)
			}()
		}
		wg.Wait()
		close(errCh)

		var batchErr error
		for werr := range errCh {
			if werr != nil && batchErr == nil {
				batchErr = werr
			}
		}
		elapsed := time.Since(start)
		newProfile, _ := tuner.observe(elapsed, batchErr)
		s.setCurrentTuning(newProfile)
		if batchErr != nil {
			return batchErr
		}

		var batchBytes int64
		for _, job := range jobs {
			batchBytes += int64(len(job.data))
		}
		p.Done += batchBytes
		p.CurrentDone += batchBytes
		p.print(false)

		if newProfile.pace > 0 {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-time.After(newProfile.pace):
			}
		}
	}
	return nil
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
			Prefix: recvPrefix, Silent: !activeUI,
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
	resetInboundData(t, e.Size)
	t.currentMode = os.FileMode(e.Mode)
	t.progress.Current = e.Path
	t.progress.CurrentDone = 0
	t.progress.CurrentSize = e.Size
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
	t := s.getInbound(id)
	if t == nil {
		return fmt.Errorf("data for unknown transfer %d", id)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancelled {
		return nil
	}
	if t.currentFile == nil {
		t.markCancelledLocked("data arrived without active file")
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	if offset < 0 || offset+int64(len(payload)) > t.currentRemaining {
		t.markCancelledLocked("received data outside declared file range")
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	st := getInboundData(t)
	if st == nil {
		t.markCancelledLocked("data state missing")
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	if old, exists := st.chunks[offset]; exists {
		if old != len(payload) {
			t.markCancelledLocked("duplicate chunk has different size")
			go s.sendCancel(id, t.cancelWhy)
		}
		return nil
	}
	if _, err := t.currentFile.WriteAt(payload, offset); err != nil {
		t.markCancelledLocked("write failed: " + err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	st.chunks[offset] = len(payload)
	st.received += int64(len(payload))
	t.progress.Done += int64(len(payload))
	t.progress.CurrentDone += int64(len(payload))
	t.progress.print(false)
	if st.received == t.currentRemaining {
		st.once.Do(func() { close(st.done) })
	} else if st.received > t.currentRemaining {
		t.markCancelledLocked("received more bytes than declared")
		go s.sendCancel(id, t.cancelWhy)
	}
	return nil
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
	if st == nil || st.received != t.currentRemaining {
		received := int64(0)
		if st != nil {
			received = st.received
		}
		t.markCancelledLocked(fmt.Sprintf("file ended with %d/%d bytes", received, t.currentRemaining))
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
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.markCancelledLocked(err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 1024*1024)); err != nil {
		t.markCancelledLocked("verify read failed: " + err.Error())
		go s.sendCancel(id, t.cancelWhy)
		return nil
	}
	actual := h.Sum(nil)
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
	if !t.progress.Silent {
		if cancelled {
			consolePrintf("%s 已取消: %s\n", t.progress.Prefix, reason)
			if len(overwrote) > 0 {
				consolePrintf("%s 注意：overwrite on 时已完成覆盖的文件无法自动恢复：\n", t.progress.Prefix)
				for _, p := range overwrote {
					consolePrintf("  %s\n", p)
				}
			}
		} else {
			consolePrintf("%s 完成。\n", t.progress.Prefix)
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
