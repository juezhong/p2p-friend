package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	resilientDataLanes       = 4
	resilientRepairBackoff   = 500 * time.Millisecond
	resilientInitialWait     = 4 * time.Second
	resilientAckStep         = 2 * 1024 * 1024
	resilientAckTimeout       = 5 * time.Second
	resilientFailureThreshold = 3

	// v0.16.0 固定 4 MiB stop-and-wait 窗口会让低 RTT 的 Linux LAN
	// 在每 4 MiB 都停下来等待 ACK，破坏 v0.15.3 的深流水。
	// v0.16.1 对本地高速链路恢复 64 MiB 有界 flight window。
	resilientDefaultWindowBytes = 8 * 1024 * 1024
	resilientLANWindowBytes     = 64 * 1024 * 1024
	resilientLANMaxWindowBytes  = 256 * 1024 * 1024
	resilientWANMaxWindowBytes  = 128 * 1024 * 1024
	resilientAckSampleBytes     = 32 * 1024 * 1024
	resilientLaneWriteTimeout   = 30 * time.Second
)

type managedDataLane struct {
	index int
	qc    *quic.Conn
	lane  io.ReadWriteCloser
	owner io.Closer
	mu    sync.Mutex
}

type resilientStripeState struct {
	rc     *rtcConn
	token  []byte
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.RWMutex
	slots   map[int]*managedDataLane
	notify  chan struct{}
	session *peerSession
}

var resilientStripes sync.Map

func resilientStripeStateFor(c *rtcConn) *resilientStripeState {
	if c == nil {
		return nil
	}
	v, _ := resilientStripes.Load(c)
	if v == nil {
		return nil
	}
	return v.(*resilientStripeState)
}

func closeResilientStripeState(c *rtcConn) {
	v, ok := resilientStripes.LoadAndDelete(c)
	if !ok {
		return
	}
	st := v.(*resilientStripeState)
	st.cancel()
	st.mu.Lock()
	for idx, lane := range st.slots {
		delete(st.slots, idx)
		_ = lane.lane.Close()
		_ = lane.qc.CloseWithError(0, "normal shutdown")
		if lane.owner != nil {
			_ = lane.owner.Close()
		}
	}
	st.mu.Unlock()
}

func (st *resilientStripeState) signal() {
	select {
	case st.notify <- struct{}{}:
	default:
	}
}

func (st *resilientStripeState) count() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.slots)
}

func (st *resilientStripeState) lanes() []io.ReadWriteCloser {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]io.ReadWriteCloser, 0, len(st.slots))
	for i := 1; i <= resilientDataLanes; i++ {
		if lane := st.slots[i]; lane != nil {
			out = append(out, lane.lane)
		}
	}
	return out
}

func (st *resilientStripeState) quics() []*quic.Conn {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*quic.Conn, 0, len(st.slots))
	for i := 1; i <= resilientDataLanes; i++ {
		if lane := st.slots[i]; lane != nil {
			out = append(out, lane.qc)
		}
	}
	return out
}

func (st *resilientStripeState) snapshot() []*managedDataLane {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*managedDataLane, 0, len(st.slots))
	for i := 1; i <= resilientDataLanes; i++ {
		if lane := st.slots[i]; lane != nil {
			out = append(out, lane)
		}
	}
	return out
}

func (st *resilientStripeState) setSession(s *peerSession) {
	st.mu.Lock()
	st.session = s
	lanes := make([]io.ReadWriteCloser, 0, len(st.slots))
	for _, lane := range st.slots {
		lanes = append(lanes, lane.lane)
	}
	st.mu.Unlock()
	for _, lane := range lanes {
		go s.dataLaneReadLoop(lane)
	}
}

func (st *resilientStripeState) install(index int, qc *quic.Conn, lane io.ReadWriteCloser, owner io.Closer) {
	if index < 1 || index > resilientDataLanes || qc == nil || lane == nil {
		if qc != nil {
			_ = qc.CloseWithError(0, "invalid data lane")
		}
		if owner != nil {
			_ = owner.Close()
		}
		return
	}
	var old *managedDataLane
	var s *peerSession
	st.mu.Lock()
	old = st.slots[index]
	st.slots[index] = &managedDataLane{index: index, qc: qc, lane: lane, owner: owner}
	s = st.session
	st.mu.Unlock()
	if old != nil {
		_ = old.lane.Close()
		_ = old.qc.CloseWithError(0, "data lane replaced")
		if old.owner != nil {
			_ = old.owner.Close()
		}
	}
	if s != nil {
		go s.dataLaneReadLoop(lane)
	}
	st.signal()
}

func (st *resilientStripeState) failLane(target io.ReadWriteCloser, reason error) {
	if target == nil {
		return
	}
	var failed *managedDataLane
	st.mu.Lock()
	for idx, lane := range st.slots {
		if lane.lane == target {
			failed = lane
			delete(st.slots, idx)
			break
		}
	}
	st.mu.Unlock()
	if failed == nil {
		return
	}
	_ = failed.lane.Close()
	if failed.qc != nil {
		_ = failed.qc.CloseWithError(0, "data lane failed")
	}
	if failed.owner != nil {
		_ = failed.owner.Close()
	}
	if reason != nil {
		consolePrintf("[数据链路] lane %d 失效，主控制连接保持，正在重建: %v\n", failed.index, reason)
	}
	st.signal()
}

func (st *resilientStripeState) waitForLanes(ctx context.Context) ([]*managedDataLane, error) {
	for {
		if lanes := st.snapshot(); len(lanes) > 0 {
			return lanes, nil
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-st.ctx.Done():
			return nil, errors.New("data lane manager closed")
		case <-st.notify:
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (st *resilientStripeState) writeChunk(ctx context.Context, preferred int, frame []byte) error {
	for {
		lanes, err := st.waitForLanes(ctx)
		if err != nil {
			return err
		}
		var lastErr error
		for step := 0; step < len(lanes); step++ {
			lane := lanes[(preferred+step)%len(lanes)]
			lane.mu.Lock()
			if d, ok := lane.lane.(interface{ SetWriteDeadline(time.Time) error }); ok {
				_ = d.SetWriteDeadline(time.Now().Add(resilientLaneWriteTimeout))
			}
			n, werr := lane.lane.Write(frame)
			if d, ok := lane.lane.(interface{ SetWriteDeadline(time.Time) error }); ok {
				_ = d.SetWriteDeadline(time.Time{})
			}
			lane.mu.Unlock()
			if werr == nil && n == len(frame) {
				return nil
			}
			if werr == nil {
				werr = io.ErrShortWrite
			}
			lastErr = werr
			st.failLane(lane.lane, werr)
		}
		if lastErr != nil {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}

func startResilientDataStripes(c *rtcConn, token []byte) int {
	if c == nil || len(token) != 32 {
		return 0
	}
	if old := resilientStripeStateFor(c); old != nil {
		return old.count()
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &resilientStripeState{
		rc: c, token: append([]byte(nil), token...),
		ctx: ctx, cancel: cancel, slots: make(map[int]*managedDataLane),
		notify: make(chan struct{}, 1),
	}
	resilientStripes.Store(c, st)

	// data-only QUIC 是数据面优化，不允许阻塞 control session / shell 就绪。
	// 主 QUIC 认证完成后立即返回；accept/dial 在后台并行建立，真正开始文件传输时
	// waitForLanes() 会等待至少一条可用 lane，其余 lane 可继续热插入。
	go func() {
		c.peer.primaryAcceptWG.Wait()
		if c.outbound {
			for i := 1; i <= resilientDataLanes; i++ {
				go st.repairLoop(i)
			}
		} else {
			st.acceptLoop()
		}
	}()
	return st.count()
}

func (st *resilientStripeState) repairLoop(index int) {
	ep := st.rc.selectedEndpoint()
	remote, _ := st.rc.qc.RemoteAddr().(*net.UDPAddr)
	if ep == nil || remote == nil {
		return
	}
	for {
		select {
		case <-st.ctx.Done():
			return
		default:
		}
		st.mu.RLock()
		_, exists := st.slots[index]
		st.mu.RUnlock()
		if exists {
			select {
			case <-st.ctx.Done():
				return
			case <-st.notify:
			case <-time.After(time.Second):
			}
			continue
		}

		tryCtx, cancel := context.WithTimeout(st.ctx, dataStripeDedicatedWait)
		qc, lane, owner, err := st.rc.dialOneDataStripe(tryCtx, ep, remote, st.token, byte(index), true)
		cancel()
		if err != nil && st.ctx.Err() == nil {
			tryCtx, cancel = context.WithTimeout(st.ctx, dataStripeSetupWait)
			qc, lane, owner, err = st.rc.dialOneDataStripe(tryCtx, ep, remote, st.token, byte(index), false)
			cancel()
		}
		if err == nil {
			st.install(index, qc, &quicStreamConn{lane}, owner)
			continue
		}
		select {
		case <-st.ctx.Done():
			return
		case <-time.After(resilientRepairBackoff):
		}
	}
}

func (st *resilientStripeState) acceptLoop() {
	ep := st.rc.selectedEndpoint()
	if ep == nil || ep.listener == nil {
		return
	}
	primaryRemote, _ := st.rc.qc.RemoteAddr().(*net.UDPAddr)
	for {
		qc, err := ep.listener.Accept(st.ctx)
		if err != nil {
			return
		}
		stripeRemote, _ := qc.RemoteAddr().(*net.UDPAddr)
		if primaryRemote == nil || stripeRemote == nil || !stripeRemote.IP.Equal(primaryRemote.IP) {
			_ = qc.CloseWithError(0, "unexpected stripe endpoint")
			continue
		}
		index, lane, err := acceptResilientStripe(st.ctx, qc, st.token)
		if err != nil {
			_ = qc.CloseWithError(0, "invalid data stripe")
			continue
		}
		st.install(index, qc, lane, nil)
	}
}

func acceptResilientStripe(ctx context.Context, qc *quic.Conn, token []byte) (int, io.ReadWriteCloser, error) {
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		return 0, nil, err
	}
	header := make([]byte, 2+len(token))
	if _, err := io.ReadFull(st, header); err != nil {
		return 0, nil, err
	}
	if header[0] != dataStripeTag {
		return 0, nil, errors.New("not a data stripe")
	}
	index := int(header[1])
	if index < 1 || index > resilientDataLanes {
		return 0, nil, fmt.Errorf("invalid data stripe index %d", index)
	}
	if !equalBytes(header[2:], token) {
		return 0, nil, errors.New("data stripe token mismatch")
	}
	if _, err := st.Write([]byte("OK")); err != nil {
		return 0, nil, err
	}
	return index, &quicStreamConn{st}, nil
}

type transferAckState struct {
	fileID uint64
	acked  atomic.Int64
	notify chan struct{}
}

func newTransferAckState(fileID uint64) *transferAckState {
	return &transferAckState{fileID: fileID, notify: make(chan struct{}, 1)}
}

func (s *peerSession) registerTransferAck(id, fileID uint64) *transferAckState {
	st := newTransferAckState(fileID)
	s.ackMu.Lock()
	s.pendingAck[id] = st
	s.ackMu.Unlock()
	return st
}

func (s *peerSession) unregisterTransferAck(id uint64, st *transferAckState) {
	s.ackMu.Lock()
	if s.pendingAck[id] == st {
		delete(s.pendingAck, id)
	}
	s.ackMu.Unlock()
}

func (s *peerSession) handleDataAck(id uint64, payload []byte) error {
	if len(payload) != 16 {
		return errors.New("invalid data ack")
	}
	fileID := binary.BigEndian.Uint64(payload[:8])
	acked := int64(binary.BigEndian.Uint64(payload[8:16]))
	s.ackMu.Lock()
	st := s.pendingAck[id]
	s.ackMu.Unlock()
	if st == nil || st.fileID != fileID || acked < 0 {
		return nil
	}
	for {
		old := st.acked.Load()
		if acked <= old || st.acked.CompareAndSwap(old, acked) {
			break
		}
	}
	select {
	case st.notify <- struct{}{}:
	default:
	}
	return nil
}

func (s *peerSession) sendDataAck(id, fileID uint64, next int64) error {
	var payload [16]byte
	binary.BigEndian.PutUint64(payload[:8], fileID)
	binary.BigEndian.PutUint64(payload[8:16], uint64(next))
	return s.writeFrame(frameDataAck, id, payload[:])
}

type resilientTransferTuner struct {
	levels       []transferTuningProfile
	level        int
	failures     int
	badWindows   int
	baselineBps  float64
}

func newResilientTransferTuner(goos string, maxLanes int) *resilientTransferTuner {
	if maxLanes < 1 {
		maxLanes = 1
	}
	if maxLanes > resilientDataLanes {
		maxLanes = resilientDataLanes
	}
	raw := []transferTuningProfile{
		{chunkSize: 128 * 1024, lanes: 1, pace: 200 * time.Microsecond},
		{chunkSize: 128 * 1024, lanes: 2, pace: 100 * time.Microsecond},
		{chunkSize: 256 * 1024, lanes: 3, pace: 50 * time.Microsecond},
		{chunkSize: 512 * 1024, lanes: 4, pace: 25 * time.Microsecond},
		{chunkSize: 1024 * 1024, lanes: 4},
	}
	levels := make([]transferTuningProfile, 0, len(raw))
	for _, p := range raw {
		if p.lanes <= maxLanes {
			levels = append(levels, p)
		}
	}
	if len(levels) == 0 {
		levels = append(levels, raw[0])
	}
	start := 0
	if goos == "windows" && len(levels) > 1 {
		start = 1
	} else if goos != "windows" {
		start = len(levels) - 1
	}
	return &resilientTransferTuner{levels: levels, level: start}
}

func (t *resilientTransferTuner) current() transferTuningProfile {
	if t.level < 0 {
		t.level = 0
	}
	if t.level >= len(t.levels) {
		t.level = len(t.levels) - 1
	}
	return t.levels[t.level]
}


func resilientFlightWindowBytes(goos, linkMode string) int64 {
	if goos == "linux" && strings.HasSuffix(linkMode, "-LAN") {
		return resilientLANWindowBytes
	}
	return resilientDefaultWindowBytes
}

func resilientSendQueueDepth(goos, linkMode string, lanes int) int {
	if lanes < 1 {
		lanes = 1
	}
	// 队列只负责让磁盘/hash/QUIC worker 解耦；真正的可靠飞行窗口由累计 ACK 限制。
	// Linux/macOS 可更积极，Windows 仍保留较小上限避免 Winsock UDP 突发队列退化。
	switch {
	case goos == "linux" && strings.HasSuffix(linkMode, "-LAN"):
		return lanes * 32
	case goos != "windows":
		return lanes * 8
	default:
		return lanes * 4
	}
}

func (t *resilientTransferTuner) observe(bytes int64, elapsed time.Duration, failed bool) (transferTuningProfile, bool) {
	old := t.current()
	if failed {
		t.failures++
		if t.failures >= resilientFailureThreshold && t.level > 0 {
			t.level--
			t.failures = 0
			t.badWindows = 0
			return t.current(), true
		}
		return old, false
	}
	t.failures = 0
	if elapsed <= 0 || bytes <= 0 {
		return old, false
	}
	rate := float64(bytes) / elapsed.Seconds()
	if t.baselineBps == 0 {
		t.baselineBps = rate
	} else {
		if rate < t.baselineBps*0.80 {
			t.badWindows++
		} else {
			t.badWindows = 0
		}
		t.baselineBps = t.baselineBps*0.7 + rate*0.3
	}
	if t.badWindows >= resilientFailureThreshold && t.level > 0 {
		t.level--
		t.badWindows = 0
		return t.current(), true
	}
	if t.badWindows == 0 && t.level+1 < len(t.levels) {
		t.level++
		return t.current(), true
	}
	return old, false
}



type resilientFlowTuner struct {
	current   int64
	min       int64
	max       int64
	baseline  float64
	bad       int
	failures  int
}

func newResilientFlowTuner(goos, linkMode string) *resilientFlowTuner {
	initial := resilientDefaultWindowBytes
	maxWindow := resilientWANMaxWindowBytes
	if strings.HasSuffix(linkMode, "-LAN") {
		initial = resilientLANWindowBytes
		maxWindow = resilientLANMaxWindowBytes
	}
	// Windows 也参与同一套自适应，但从更小的 WAN 窗口起步，
	// 避免瞬间向 Winsock 填入过多 UDP 数据。
	if goos == "windows" && !strings.HasSuffix(linkMode, "-LAN") {
		initial = 8 * 1024 * 1024
	}
	return &resilientFlowTuner{
		current: int64(initial),
		min:     int64(resilientDefaultWindowBytes),
		max:     int64(maxWindow),
	}
}

func (t *resilientFlowTuner) observe(bytes int64, elapsed time.Duration, failed bool) (int64, bool) {
	old := t.current
	if failed {
		t.failures++
		if t.failures >= resilientFailureThreshold && t.current > t.min {
			t.current /= 2
			if t.current < t.min {
				t.current = t.min
			}
			t.failures = 0
			t.bad = 0
		}
		return t.current, t.current != old
	}
	t.failures = 0
	if bytes <= 0 || elapsed <= 0 {
		return t.current, false
	}
	rate := float64(bytes) / elapsed.Seconds()
	if t.baseline == 0 {
		t.baseline = rate
		if t.current < t.max {
			t.current *= 2
			if t.current > t.max {
				t.current = t.max
			}
		}
		return t.current, t.current != old
	}
	if rate < t.baseline*0.80 {
		t.bad++
	} else {
		t.bad = 0
		// 只要扩窗后吞吐没有明显恶化，就继续向上探测，直到链路不再受应用窗口限制。
		if t.current < t.max {
			t.current *= 2
			if t.current > t.max {
				t.current = t.max
			}
		}
	}
	t.baseline = t.baseline*0.70 + rate*0.30
	if t.bad >= resilientFailureThreshold && t.current > t.min {
		t.current /= 2
		if t.current < t.min {
			t.current = t.min
		}
		t.bad = 0
	}
	return t.current, t.current != old
}

type resilientSendChunk struct {
	frame  []byte
	size   int
	offset int64
}

func newResilientChunk(id, fileID uint64, offset int64, payloadLen int) resilientSendChunk {
	frame := make([]byte, resilientDataHeaderSize+payloadLen)
	binary.BigEndian.PutUint64(frame[0:8], id)
	binary.BigEndian.PutUint64(frame[8:16], fileID)
	binary.BigEndian.PutUint64(frame[16:24], uint64(offset))
	binary.BigEndian.PutUint32(frame[24:28], uint32(payloadLen))
	return resilientSendChunk{frame: frame, size: payloadLen, offset: offset}
}

func buildResilientChunk(id, fileID uint64, offset int64, payload []byte) resilientSendChunk {
	chunk := newResilientChunk(id, fileID, offset, len(payload))
	copy(chunk.frame[resilientDataHeaderSize:], payload)
	return chunk
}

func (s *peerSession) sendResilientBatch(
	ctx context.Context,
	manager *resilientStripeState,
	chunks []resilientSendChunk,
	workers int,
	pace time.Duration,
) error {
	if workers < 1 {
		workers = 1
	}
	if workers > len(chunks) {
		workers = len(chunks)
	}
	if workers < 1 {
		return nil
	}
	jobs := make(chan int, workers)
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for idx := range jobs {
				if err := manager.writeChunk(ctx, worker, chunks[idx].frame); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if pace > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(pace):
					}
				}
			}
		}(w)
	}
	for i := range chunks {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return context.Cause(ctx)
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}


func (s *peerSession) readAndSendResilientWindow(
	ctx context.Context,
	manager *resilientStripeState,
	f *os.File,
	h io.Writer,
	id, fileID uint64,
	windowStart, windowEnd int64,
	profile transferTuningProfile,
) ([]resilientSendChunk, error) {
	workers := profile.lanes
	if workers < 1 {
		workers = 1
	}
	queueDepth := resilientSendQueueDepth(runtime.GOOS, s.linkMode, workers)
	jobs := make(chan resilientSendChunk, queueDepth)
	errCh := make(chan error, workers)

	sendCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for chunk := range jobs {
				if context.Cause(sendCtx) != nil {
					continue
				}
				if err := manager.writeChunk(sendCtx, worker, chunk.frame); err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel(err)
					continue
				}
				if profile.pace > 0 {
					select {
					case <-sendCtx.Done():
						return
					case <-time.After(profile.pace):
					}
				}
			}
		}(w)
	}

	chunks := make([]resilientSendChunk, 0, int((windowEnd-windowStart)/int64(profile.chunkSize))+1)
	for off := windowStart; off < windowEnd; {
		if cause := context.Cause(sendCtx); cause != nil {
			close(jobs)
			wg.Wait()
			return nil, cause
		}
		want := int64(profile.chunkSize)
		if want <= 0 || want > maxDataChunkSize {
			want = maxDataChunkSize
		}
		if windowEnd-off < want {
			want = windowEnd - off
		}

		chunk := newResilientChunk(id, fileID, off, int(want))
		payload := chunk.frame[resilientDataHeaderSize:]
		n, rerr := f.ReadAt(payload, off)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			close(jobs)
			wg.Wait()
			return nil, rerr
		}
		if n != len(payload) {
			close(jobs)
			wg.Wait()
			return nil, io.ErrUnexpectedEOF
		}
		if _, err := h.Write(payload); err != nil {
			close(jobs)
			wg.Wait()
			return nil, err
		}

		chunks = append(chunks, chunk)
		select {
		case jobs <- chunk:
			off += int64(n)
		case <-sendCtx.Done():
			close(jobs)
			wg.Wait()
			return nil, context.Cause(sendCtx)
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return chunks, err
	default:
	}
	if cause := context.Cause(sendCtx); cause != nil {
		return chunks, cause
	}
	return chunks, nil
}

func (s *peerSession) waitResilientAck(
	ctx context.Context,
	ack *transferAckState,
	want int64,
	progressFrom *int64,
	p *progress,
) error {
	timer := time.NewTimer(resilientAckTimeout)
	defer timer.Stop()
	for {
		got := ack.acked.Load()
		if got > *progressFrom {
			p.addBytes(got - *progressFrom)
			*progressFrom = got
		}
		if got >= want {
			return nil
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-s.closed:
			if err := s.terminalTransportError(); err != nil {
				return err
			}
			return errors.New("control connection closed")
		case <-ack.notify:
		case <-timer.C:
			return context.DeadlineExceeded
		}
	}
}


func (s *peerSession) sendFileResilientSliding(
	ctx context.Context,
	manager *resilientStripeState,
	id, fileID uint64,
	path string,
	size int64,
	p *progress,
) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if size == 0 {
		return h.Sum(nil), nil
	}

	ack := s.registerTransferAck(id, fileID)
	defer s.unregisterTransferAck(id, ack)

	tuner := newResilientTransferTuner(runtime.GOOS, resilientDataLanes)
	flow := newResilientFlowTuner(runtime.GOOS, s.linkMode)

	var activeLanes atomic.Int64
	var chunkBytes atomic.Int64
	var paceNanos atomic.Int64

	publish := func(profile transferTuningProfile) {
		if profile.lanes < 1 {
			profile.lanes = 1
		}
		if profile.chunkSize < 1 {
			profile.chunkSize = 128 * 1024
		}
		profile.queueDepth = resilientSendQueueDepth(runtime.GOOS, s.linkMode, profile.lanes)
		profile.flightBytes = flow.current
		activeLanes.Store(int64(profile.lanes))
		chunkBytes.Store(int64(profile.chunkSize))
		paceNanos.Store(int64(profile.pace))
		s.setCurrentTuning(profile)
	}

	profile := tuner.current()
	publish(profile)

	// channel 容量使用平台允许的最大 worker 深度；实际飞行数据仍严格受 ACK window 限制。
	queueDepth := resilientSendQueueDepth(runtime.GOOS, s.linkMode, resilientDataLanes)
	jobs := make(chan resilientSendChunk, queueDepth)
	errCh := make(chan error, resilientDataLanes)
	sendCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var workers sync.WaitGroup
	for worker := 0; worker < resilientDataLanes; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for chunk := range jobs {
				for int64(worker) >= activeLanes.Load() {
					select {
					case <-sendCtx.Done():
						return
					case <-time.After(time.Millisecond):
					}
				}
				if err := manager.writeChunk(sendCtx, worker, chunk.frame); err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel(err)
					return
				}
				if pace := time.Duration(paceNanos.Load()); pace > 0 {
					select {
					case <-sendCtx.Done():
						return
					case <-time.After(pace):
					}
				}
			}
		}(worker)
	}
	defer func() {
		close(jobs)
		workers.Wait()
	}()

	var (
		nextOffset    int64
		progressAck   int64
		sampleAck     int64
		sampleStarted = time.Now()
		outstanding   []resilientSendChunk
		head          int
		retries       int
	)

	releaseAcked := func(acked int64) {
		for head < len(outstanding) {
			ch := &outstanding[head]
			if ch.offset+int64(ch.size) > acked {
				break
			}
			ch.frame = nil
			head++
		}
		if head > 1024 && head*2 > len(outstanding) {
			outstanding = append([]resilientSendChunk(nil), outstanding[head:]...)
			head = 0
		}
	}

	updateFromAck := func(acked int64) {
		if acked > progressAck {
			p.addBytes(acked - progressAck)
			progressAck = acked
		}
		releaseAcked(acked)

		if acked-sampleAck >= resilientAckSampleBytes || acked == size {
			now := time.Now()
			bytes := acked - sampleAck
			elapsed := now.Sub(sampleStarted)
			if bytes > 0 && elapsed > 0 {
				if next, changed := tuner.observe(bytes, elapsed, false); changed {
					profile = next
				}
				// 正常自适应调节属于内部传输策略，不刷用户终端。
				// 当前 lanes/chunk/queue/flight 仍可通过 status 查看。
				flow.observe(bytes, elapsed, false)
				publish(profile)
			}
			sampleAck = acked
			sampleStarted = now
		}
	}

	retransmitOutstanding := func() error {
		acked := ack.acked.Load()
		releaseAcked(acked)
		for i := head; i < len(outstanding); i++ {
			ch := outstanding[i]
			if ch.frame == nil || ch.offset+int64(ch.size) <= acked {
				continue
			}
			select {
			case jobs <- ch:
			case <-sendCtx.Done():
				return context.Cause(sendCtx)
			}
		}
		return nil
	}

	waitForAckProgress := func(previous int64) error {
		timer := time.NewTimer(resilientAckTimeout)
		defer timer.Stop()
		for {
			got := ack.acked.Load()
			if got > previous {
				updateFromAck(got)
				return nil
			}
			select {
			case <-sendCtx.Done():
				return context.Cause(sendCtx)
			case <-s.closed:
				if err := s.terminalTransportError(); err != nil {
					return err
				}
				return errors.New("control connection closed")
			case <-ack.notify:
			case <-timer.C:
				return context.DeadlineExceeded
			}
		}
	}

	for nextOffset < size {
		if cause := context.Cause(sendCtx); cause != nil {
			return nil, cause
		}
		select {
		case err := <-errCh:
			if err != nil {
				return nil, err
			}
		default:
		}

		acked := ack.acked.Load()
		updateFromAck(acked)

		if nextOffset-acked >= flow.current {
			if err := waitForAckProgress(acked); err != nil {
				retries++
				if next, changed := tuner.observe(0, 0, true); changed {
					profile = next
				}
				// 连续失败触发的自动降档同样保持静默；真正的 lane 故障、
				// 重建/重传失败仍由数据链路错误路径报告。
				flow.observe(0, 0, true)
				publish(profile)
				if retries >= 20 {
					return nil, fmt.Errorf("data plane failed after repeated retransmit attempts: %w", err)
				}
				if rerr := retransmitOutstanding(); rerr != nil {
					return nil, rerr
				}
				continue
			}
			retries = 0
			continue
		}

		want := chunkBytes.Load()
		if want <= 0 || want > maxDataChunkSize {
			want = maxDataChunkSize
		}
		if size-nextOffset < want {
			want = size - nextOffset
		}

		chunk := newResilientChunk(id, fileID, nextOffset, int(want))
		payload := chunk.frame[resilientDataHeaderSize:]
		n, rerr := f.ReadAt(payload, nextOffset)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return nil, rerr
		}
		if n != len(payload) {
			return nil, io.ErrUnexpectedEOF
		}
		if _, err := h.Write(payload); err != nil {
			return nil, err
		}

		outstanding = append(outstanding, chunk)
		select {
		case jobs <- chunk:
			nextOffset += int64(n)
		case <-sendCtx.Done():
			return nil, context.Cause(sendCtx)
		}
	}

	for ack.acked.Load() < size {
		acked := ack.acked.Load()
		updateFromAck(acked)
		if err := waitForAckProgress(acked); err != nil {
			retries++
			if next, changed := tuner.observe(0, 0, true); changed {
				profile = next
			}
			flow.observe(0, 0, true)
			publish(profile)
			if retries >= 20 {
				return nil, fmt.Errorf("data plane failed waiting final ack: %w", err)
			}
			if rerr := retransmitOutstanding(); rerr != nil {
				return nil, rerr
			}
			continue
		}
		retries = 0
	}
	updateFromAck(size)
	return h.Sum(nil), nil
}

// sendFileResilient 实现 v0.16 的可靠数据面。
// 主 QUIC 只负责 ACK / RPC / session control；文件块仅发送到可重建 data QUIC。
// 每个窗口只有收到接收端“已顺序写盘”的累计 ACK 才会推进。若某条 data QUIC
// 在 Write 成功后才丢包/断开，ACK 会停住，整个未确认窗口会自动重传到当前健康链路。
func (s *peerSession) sendFileResilient(
	ctx context.Context,
	id, fileID uint64,
	path string,
	size int64,
	p *progress,
) ([]byte, error) {
	rc, ok := s.conn.(*rtcConn)
	if !ok || !rc.ResilientDataV16() {
		return nil, errors.New("resilient data plane unavailable")
	}
	manager := resilientStripeStateFor(rc)
	if manager == nil {
		return nil, errors.New("resilient data lane manager unavailable")
	}
	return s.sendFileResilientSliding(ctx, manager, id, fileID, path, size, p)
}
