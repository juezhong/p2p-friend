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
	resilientAckTimeout      = 5 * time.Second
	resilientWindowBytes     = 4 * 1024 * 1024
	resilientFailureThreshold = 3
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
	_ = failed.qc.CloseWithError(0, "data lane failed")
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
			n, werr := lane.lane.Write(frame)
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

	c.peer.primaryAcceptWG.Wait()
	if c.outbound {
		for i := 1; i <= resilientDataLanes; i++ {
			go st.repairLoop(i)
		}
	} else {
		go st.acceptLoop()
	}

	deadline := time.NewTimer(resilientInitialWait)
	defer deadline.Stop()
	for st.count() == 0 {
		select {
		case <-st.notify:
		case <-deadline.C:
			return 0
		case <-ctx.Done():
			return 0
		}
	}
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


type resilientSendChunk struct {
	frame []byte
	size  int
}

func buildResilientChunk(id, fileID uint64, offset int64, payload []byte) resilientSendChunk {
	frame := make([]byte, resilientDataHeaderSize+len(payload))
	binary.BigEndian.PutUint64(frame[0:8], id)
	binary.BigEndian.PutUint64(frame[8:16], fileID)
	binary.BigEndian.PutUint64(frame[16:24], uint64(offset))
	binary.BigEndian.PutUint32(frame[24:28], uint32(len(payload)))
	copy(frame[resilientDataHeaderSize:], payload)
	return resilientSendChunk{frame: frame, size: len(payload)}
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
	profile := tuner.current()
	s.setCurrentTuning(profile)

	var (
		windowStart int64
		progressAck int64
		consecutiveFailures int
	)
	for windowStart < size {
		if cause := context.Cause(ctx); cause != nil {
			return nil, cause
		}
		select {
		case <-s.closed:
			if err := s.terminalTransportError(); err != nil {
				return nil, err
			}
			return nil, errors.New("control connection closed")
		default:
		}

		profile = tuner.current()
		s.setCurrentTuning(profile)
		windowEnd := windowStart + resilientWindowBytes
		if windowEnd > size {
			windowEnd = size
		}

		chunks := make([]resilientSendChunk, 0, int((windowEnd-windowStart)/int64(profile.chunkSize))+1)
		for off := windowStart; off < windowEnd; {
			want := int64(profile.chunkSize)
			if want <= 0 || want > maxDataChunkSize {
				want = maxDataChunkSize
			}
			if windowEnd-off < want {
				want = windowEnd - off
			}
			payload := make([]byte, int(want))
			n, rerr := f.ReadAt(payload, off)
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return nil, rerr
			}
			if n != len(payload) {
				return nil, io.ErrUnexpectedEOF
			}
			_, _ = h.Write(payload)
			chunks = append(chunks, buildResilientChunk(id, fileID, off, payload))
			off += int64(n)
		}

		windowStarted := time.Now()
		for {
			attemptCtx, cancel := context.WithTimeout(ctx, resilientAckTimeout)
			sendErr := s.sendResilientBatch(attemptCtx, manager, chunks, profile.lanes, profile.pace)
			cancel()
			if sendErr == nil {
				sendErr = s.waitResilientAck(ctx, ack, windowEnd, &progressAck, p)
			}
			if sendErr == nil {
				consecutiveFailures = 0
				if next, changed := tuner.observe(windowEnd-windowStart, time.Since(windowStarted), false); changed {
					s.setCurrentTuning(next)
					consolePrintf("[传输] 自适应升档: %d lane, chunk=%s, pacing=%s\n",
						next.lanes, humanBytes(int64(next.chunkSize)), next.pace)
				}
				break
			}

			consecutiveFailures++
			if next, changed := tuner.observe(0, 0, true); changed {
				profile = next
				s.setCurrentTuning(next)
				consolePrintf("[传输] 连续失败达到阈值，自动降档: %d lane, chunk=%s, pacing=%s\n",
					next.lanes, humanBytes(int64(next.chunkSize)), next.pace)
			}
			if consecutiveFailures >= 20 {
				return nil, fmt.Errorf("data plane failed after repeated rebuild/retransmit attempts: %w", sendErr)
			}
			consolePrintf("[传输] 未确认窗口 %s-%s，重建数据链路并重传（%d/%d）\n",
				humanBytes(windowStart), humanBytes(windowEnd), consecutiveFailures, 20)
			select {
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			case <-s.closed:
				if err := s.terminalTransportError(); err != nil {
					return nil, err
				}
				return nil, errors.New("control connection closed")
			case <-time.After(150 * time.Millisecond):
			}
		}
		windowStart = windowEnd
	}
	return h.Sum(nil), nil
}
