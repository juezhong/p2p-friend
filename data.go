package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	frameEntryReady = byte(11)
	dataHeaderSize  = 20

	// v14 继续使用 1 MiB application chunk。QUIC 仍会按路径 MTU 分包；这里的较大 chunk
	// 只是减少应用层 Write / allocation / copy 次数。
	maxDataChunkSize   = 1024 * 1024
	maxDataConnections = 4
	primaryDataStreams = 1
	parallelLanes       = maxDataConnections

	// QUIC 本身已经有拥塞控制和发送缓存。应用层只保留很浅的预取队列，
	// 避免 Windows/Winsock 在多 QUIC lane 下被 64 MiB 级突发写入压满 UDP send queue。
	sendQueueDepthPerLane = 2

	// 接收端允许更大的有界乱序窗口，避免多 UDP flow 中某一条暂时变慢时
	// 过早把其它 flow 全部反压停住。仍然有硬上限，不随超大文件无限增长。
	minReceiveWindowChunks = 64
	midReceiveWindowChunks = 128
	maxReceiveWindowChunks = 256
)

type transferTuningProfile struct {
	chunkSize int
	lanes     int
	pace      time.Duration
}

// adaptiveTransferTuner 保留用于测试和未来低带宽自适应策略。
// v13 大文件热路径默认直接使用 1 MiB / 全 data lanes / 无人工 pacing。
type adaptiveTransferTuner struct {
	goos     string
	maxLanes int

	levels []transferTuningProfile
	level  int

	windowBytes   int64
	windowElapsed time.Duration

	baselineBps float64
	bestBps     float64
	probeBase   float64
	probing     bool
	stable      int
	cooldown    int
}

func transferTuningLevels(maxLanes int) []transferTuningProfile {
	if maxLanes < 1 {
		maxLanes = 1
	}
	raw := []transferTuningProfile{
		{chunkSize: 64 * 1024, lanes: 1, pace: 250 * time.Microsecond},
		{chunkSize: 128 * 1024, lanes: 1},
		{chunkSize: 128 * 1024, lanes: 2},
		{chunkSize: 192 * 1024, lanes: 3},
		{chunkSize: 256 * 1024, lanes: 4},
	}
	out := make([]transferTuningProfile, 0, len(raw))
	for _, p := range raw {
		if p.lanes <= maxLanes {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = append(out, transferTuningProfile{chunkSize: 64 * 1024, lanes: 1})
	}
	return out
}

func newAdaptiveTransferTuner(goos string, maxLanes int) *adaptiveTransferTuner {
	levels := transferTuningLevels(maxLanes)
	if goos == "windows" {
		for i := range levels {
			switch levels[i].lanes {
			case 3:
				levels[i].pace = 50 * time.Microsecond
			case 4:
				levels[i].pace = 100 * time.Microsecond
			}
		}
	}
	initial := len(levels) - 1
	if goos == "windows" {
		for i, p := range levels {
			if p.lanes >= 2 && p.chunkSize >= 128*1024 {
				initial = i
				break
			}
		}
	} else {
		for i, p := range levels {
			if p.lanes >= 3 {
				initial = i
				break
			}
		}
	}
	return &adaptiveTransferTuner{goos: goos, maxLanes: maxLanes, levels: levels, level: initial}
}

func (t *adaptiveTransferTuner) current() transferTuningProfile {
	if t.level < 0 {
		t.level = 0
	}
	if t.level >= len(t.levels) {
		t.level = len(t.levels) - 1
	}
	return t.levels[t.level]
}

func (t *adaptiveTransferTuner) resetWindow() {
	t.windowBytes = 0
	t.windowElapsed = 0
}

func (t *adaptiveTransferTuner) observe(bytes int64, elapsed time.Duration, err error) (transferTuningProfile, bool) {
	old := t.current()
	if err != nil {
		if t.level > 0 {
			t.level--
		}
		t.probing = false
		t.stable = 0
		t.cooldown = 3
		t.resetWindow()
		return t.current(), old != t.current()
	}
	if bytes > 0 {
		t.windowBytes += bytes
	}
	if elapsed > 0 {
		t.windowElapsed += elapsed
	}
	if t.windowElapsed < 800*time.Millisecond && t.windowBytes < 4*1024*1024 {
		return old, false
	}
	if t.windowElapsed <= 0 || t.windowBytes <= 0 {
		t.resetWindow()
		return old, false
	}
	rate := float64(t.windowBytes) / t.windowElapsed.Seconds()
	t.resetWindow()
	if rate > t.bestBps {
		t.bestBps = rate
	}
	if t.probing {
		if t.probeBase > 0 && rate < t.probeBase*0.90 {
			if t.level > 0 {
				t.level--
			}
			t.baselineBps = t.probeBase
			t.cooldown = 3
		} else {
			t.baselineBps = rate
		}
		t.probing = false
		t.stable = 0
		return t.current(), old != t.current()
	}
	if t.baselineBps == 0 {
		t.baselineBps = rate
	} else {
		t.baselineBps = t.baselineBps*0.70 + rate*0.30
	}
	if t.cooldown > 0 {
		t.cooldown--
		return old, false
	}
	t.stable++
	if t.stable >= 2 && t.level+1 < len(t.levels) {
		t.stable = 0
		t.probeBase = t.baselineBps
		t.level++
		t.probing = true
		return t.current(), true
	}
	return old, false
}

func currentTransferTuner(maxLanes int) *adaptiveTransferTuner {
	return newAdaptiveTransferTuner(runtime.GOOS, maxLanes)
}

func fastTransferProfile(maxLanes int) transferTuningProfile {
	if maxLanes < 1 {
		maxLanes = 1
	}
	if maxLanes > parallelLanes {
		maxLanes = parallelLanes
	}
	return transferTuningProfile{chunkSize: maxDataChunkSize, lanes: maxLanes}
}

// sustainedTransferProfile 用于真实长时间文件发送。
// Windows 的 Winsock UDP send queue 在多个 QUIC connection 同时持续写大块数据时
// 更容易出现 WSAENOBUFS。早期版本已经遇到过这个问题，因此这里恢复保守参数：
// 较小 application chunk、最多 2 条主动 lane，并在每次成功写后留一个很短 pacing。
// Linux/macOS 继续使用全 lane / 1 MiB，不牺牲它们的高吞吐路径。
func sustainedTransferProfile(goos string, maxLanes int) transferTuningProfile {
	if maxLanes < 1 {
		maxLanes = 1
	}
	if maxLanes > parallelLanes {
		maxLanes = parallelLanes
	}
	if goos == "windows" {
		lanes := maxLanes
		if lanes > 2 {
			lanes = 2
		}
		return transferTuningProfile{
			chunkSize: 128 * 1024,
			lanes:     lanes,
			pace:      200 * time.Microsecond,
		}
	}
	return fastTransferProfile(maxLanes)
}

// dataLaneProvider 把 QUIC connection 上预先建立的多条 data stream 暴露给会话。
type dataLaneProvider interface {
	DataLanes() []io.ReadWriteCloser
}

type sessionDataState struct {
	lanes    []io.ReadWriteCloser
	mu       []sync.Mutex
	disabled []atomic.Bool
	seq      atomic.Uint64
}

func (st *sessionDataState) healthyLaneIndices() []int {
	if st == nil {
		return nil
	}
	out := make([]int, 0, len(st.lanes))
	for i := range st.lanes {
		if i < len(st.disabled) && st.disabled[i].Load() {
			continue
		}
		out = append(out, i)
	}
	return out
}

func (st *sessionDataState) disableLane(idx int) bool {
	if st == nil || idx < 0 || idx >= len(st.lanes) || idx >= len(st.disabled) {
		return false
	}
	if !st.disabled[idx].CompareAndSwap(false, true) {
		return false
	}
	// 只关闭这一条 data stream。它可能属于主 QUIC connection，但关闭 stream
	// 不会关闭 control stream / session；独立 stripe QUIC 也由 rtcConn 最终回收。
	_ = st.lanes[idx].Close()
	return true
}

type preparedDataChunk struct {
	buf        []byte
	offset     int64
	payloadLen int
}

type inboundDataChunk struct {
	buf        []byte
	offset     int64
	payloadLen int
}

type inboundDataState struct {
	file *os.File
	size int64

	chunks chan inboundDataChunk
	budget chan struct{}
	stop   chan struct{}
	done   chan struct{}
	writerDone chan struct{}

	stopped   atomic.Bool
	stopOnce  sync.Once
	doneOnce  sync.Once

	resultMu sync.Mutex
	written  int64
	sum      []byte
	err      error
}

var sessionData sync.Map
var inboundData sync.Map
var outboundReady sync.Map

const pooledDataBufferSize = dataHeaderSize + maxDataChunkSize

var dataBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, pooledDataBufferSize)
	},
}

func acquireDataBuffer() []byte {
	b := dataBufferPool.Get().([]byte)
	if cap(b) < pooledDataBufferSize {
		return make([]byte, pooledDataBufferSize)
	}
	return b[:pooledDataBufferSize]
}

func releaseDataBuffer(b []byte) {
	if cap(b) < pooledDataBufferSize {
		return
	}
	dataBufferPool.Put(b[:pooledDataBufferSize])
}

func attachDataLanes(s *peerSession, conn io.ReadWriteCloser) {
	provider, ok := conn.(dataLaneProvider)
	if !ok {
		return
	}
	lanes := provider.DataLanes()
	st := &sessionDataState{
		lanes:    lanes,
		mu:       make([]sync.Mutex, len(lanes)),
		disabled: make([]atomic.Bool, len(lanes)),
	}
	sessionData.Store(s, st)
	for _, lane := range lanes {
		go s.dataLaneReadLoop(lane)
	}
}

func dataState(s *peerSession) *sessionDataState {
	v, _ := sessionData.Load(s)
	if v == nil {
		return nil
	}
	return v.(*sessionDataState)
}

func clearDataState(s *peerSession) { sessionData.Delete(s) }

func setOutboundReady(ot *outboundTransfer) chan string {
	ch := make(chan string, 1)
	outboundReady.Store(ot, ch)
	return ch
}

func getOutboundReady(ot *outboundTransfer) chan string {
	v, _ := outboundReady.Load(ot)
	if v == nil {
		return nil
	}
	return v.(chan string)
}

func clearOutboundReady(ot *outboundTransfer) { outboundReady.Delete(ot) }

func receiveWindowChunks(size int64) int {
	switch {
	case size >= 2*1024*1024*1024:
		return maxReceiveWindowChunks
	case size >= 512*1024*1024:
		return midReceiveWindowChunks
	default:
		return minReceiveWindowChunks
	}
}

func startInboundData(s *peerSession, id uint64, t *inboundTransfer, size int64, f *os.File) *inboundDataState {
	window := receiveWindowChunks(size)
	st := &inboundDataState{
		file:       f,
		size:       size,
		chunks:     make(chan inboundDataChunk, window),
		budget:     make(chan struct{}, window),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		writerDone: make(chan struct{}),
	}
	inboundData.Store(t, st)
	go s.inboundWriterLoop(id, t, st)
	return st
}

func getInboundData(t *inboundTransfer) *inboundDataState {
	v, _ := inboundData.Load(t)
	if v == nil {
		return nil
	}
	return v.(*inboundDataState)
}

func (st *inboundDataState) stopAccepting() {
	if st.stopped.CompareAndSwap(false, true) {
		st.stopOnce.Do(func() { close(st.stop) })
	}
}

func (st *inboundDataState) enqueue(chunk inboundDataChunk) bool {
	if st.stopped.Load() {
		return false
	}
	// credit 覆盖 channel + reorder map 的总 chunk 数。credit 用完时停止继续
	// 消费 QUIC stream，由 QUIC flow control 自然向发送端施加背压。
	select {
	case st.budget <- struct{}{}:
	case <-st.stop:
		return false
	}
	select {
	case st.chunks <- chunk:
		return true
	case <-st.stop:
		<-st.budget
		return false
	}
}

func (st *inboundDataState) releaseChunk(chunk inboundDataChunk) {
	releaseDataBuffer(chunk.buf)
	<-st.budget
}

func (st *inboundDataState) finish(written int64, sum []byte, err error) {
	st.resultMu.Lock()
	st.written = written
	st.sum = append([]byte(nil), sum...)
	st.err = err
	st.resultMu.Unlock()
	st.doneOnce.Do(func() { close(st.done) })
}

func (st *inboundDataState) result() (int64, []byte, error) {
	st.resultMu.Lock()
	defer st.resultMu.Unlock()
	return st.written, append([]byte(nil), st.sum...), st.err
}

func clearInboundData(t *inboundTransfer) {
	v, ok := inboundData.LoadAndDelete(t)
	if !ok {
		return
	}
	st := v.(*inboundDataState)
	st.stopAccepting()
	<-st.writerDone
}

func drainInboundBuffers(st *inboundDataState) {
	for {
		select {
		case chunk := <-st.chunks:
			st.releaseChunk(chunk)
		default:
			return
		}
	}
}

func (s *peerSession) inboundWriterLoop(id uint64, t *inboundTransfer, st *inboundDataState) {
	defer close(st.writerDone)
	h := sha256.New()
	pending := make(map[int64]inboundDataChunk)
	next := int64(0)

	releasePending := func() {
		for off, chunk := range pending {
			delete(pending, off)
			st.releaseChunk(chunk)
		}
		drainInboundBuffers(st)
	}
	fail := func(err error) {
		st.stopAccepting()
		releasePending()
		st.finish(next, nil, err)
		if err != nil {
			go s.cancelInbound(id, "write pipeline failed: "+err.Error(), true)
		}
	}

	if st.size == 0 {
		st.stopAccepting()
		st.finish(0, h.Sum(nil), nil)
		return
	}

	for next < st.size {
		select {
		case <-st.stop:
			releasePending()
			st.finish(next, nil, errors.New("receive pipeline stopped"))
			return
		case chunk := <-st.chunks:
			if chunk.offset < 0 || chunk.payloadLen < 0 ||
				chunk.payloadLen > maxDataChunkSize ||
				chunk.offset+int64(chunk.payloadLen) > st.size {
				st.releaseChunk(chunk)
				fail(errors.New("received data outside declared file range"))
				return
			}
			if chunk.offset < next {
				// QUIC 本身可靠，这里只把完全落在已写区域的重复块安全丢弃。
				st.releaseChunk(chunk)
				continue
			}
			if old, exists := pending[chunk.offset]; exists {
				st.releaseChunk(chunk)
				if old.payloadLen != chunk.payloadLen {
					fail(errors.New("duplicate chunk has different size"))
					return
				}
				continue
			}
			pending[chunk.offset] = chunk

			for {
				cur, ok := pending[next]
				if !ok {
					break
				}
				delete(pending, next)
				payload := cur.buf[dataHeaderSize : dataHeaderSize+cur.payloadLen]
				n, err := st.file.Write(payload)
				if n > 0 {
					_, _ = h.Write(payload[:n])
					next += int64(n)
					t.progress.addBytes(int64(n))
				}
				st.releaseChunk(cur)
				if err != nil {
					fail(err)
					return
				}
				if n != cur.payloadLen {
					fail(io.ErrShortWrite)
					return
				}
			}
		}
	}

	st.stopAccepting()
	releasePending()
	st.finish(next, h.Sum(nil), nil)
}

// writeDataChunk 是 control-stream fallback / 测试兼容路径。
func (s *peerSession) writeDataChunk(id uint64, offset int64, payload []byte) error {
	if offset < 0 {
		return errors.New("negative data offset")
	}
	st := dataState(s)
	if st == nil || len(st.lanes) == 0 {
		buf := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint64(buf[:8], uint64(offset))
		copy(buf[8:], payload)
		return s.writeFrame(frameData, id, buf)
	}
	idx := int((st.seq.Add(1) - 1) % uint64(len(st.lanes)))
	return s.writeDataChunkOnLane(idx, id, offset, payload)
}

func (s *peerSession) writePreparedDataChunkOnLane(idx int, id uint64, chunk preparedDataChunk) error {
	st := dataState(s)
	if st == nil || idx < 0 || idx >= len(st.lanes) {
		return fmt.Errorf("invalid data lane: %d", idx)
	}
	if chunk.offset < 0 || chunk.payloadLen < 0 || chunk.payloadLen > maxDataChunkSize {
		return errors.New("invalid prepared data chunk")
	}
	if len(chunk.buf) < dataHeaderSize+chunk.payloadLen {
		return errors.New("prepared data buffer too small")
	}
	binary.BigEndian.PutUint64(chunk.buf[0:8], id)
	binary.BigEndian.PutUint64(chunk.buf[8:16], uint64(chunk.offset))
	binary.BigEndian.PutUint32(chunk.buf[16:20], uint32(chunk.payloadLen))

	st.mu[idx].Lock()
	defer st.mu[idx].Unlock()
	frame := chunk.buf[:dataHeaderSize+chunk.payloadLen]
	n, err := st.lanes[idx].Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}


func (s *peerSession) writePreparedDataChunkOnControl(id uint64, chunk preparedDataChunk) error {
	if chunk.offset < 0 || chunk.payloadLen < 0 || chunk.payloadLen > maxDataChunkSize {
		return errors.New("invalid prepared data chunk")
	}
	if len(chunk.buf) < dataHeaderSize+chunk.payloadLen {
		return errors.New("prepared data buffer too small")
	}
	payload := make([]byte, 8+chunk.payloadLen)
	binary.BigEndian.PutUint64(payload[:8], uint64(chunk.offset))
	copy(payload[8:], chunk.buf[dataHeaderSize:dataHeaderSize+chunk.payloadLen])
	return s.writeFrame(frameData, id, payload)
}

// writePreparedDataChunkResilient 优先写指定 data lane；某条 lane 发生 I/O 错误后
// 立即永久移出当前 session 的 data 调度，并把同一 chunk 重试到其它健康 lane。
// 如果所有 data lane 都不可用，协议已有的 frameData control-stream 路径作为最后兜底。
// 这样独立 stripe 的瞬时/永久故障不会直接终止整个文件或整个会话。
func (s *peerSession) writePreparedDataChunkResilient(active []int, preferred int, id uint64, chunk preparedDataChunk) error {
	st := dataState(s)
	if st == nil || len(active) == 0 {
		return s.writePreparedDataChunkOnControl(id, chunk)
	}

	var firstErr error
	for step := 0; step < len(active); step++ {
		idx := active[(preferred+step)%len(active)]
		if idx < 0 || idx >= len(st.lanes) {
			continue
		}
		if idx < len(st.disabled) && st.disabled[idx].Load() {
			continue
		}
		if err := s.writePreparedDataChunkOnLane(idx, id, chunk); err == nil {
			return nil
		} else {
			if firstErr == nil {
				firstErr = err
			}
			if st.disableLane(idx) {
				consolePrintf("[数据流] lane %d 写入失败，已移除并自动降级: %v\n", idx+1, err)
			}
		}
	}

	if err := s.writePreparedDataChunkOnControl(id, chunk); err != nil {
		if firstErr != nil {
			return fmt.Errorf("data lane failed (%v); control fallback failed: %w", firstErr, err)
		}
		return err
	}
	return nil
}

func (s *peerSession) writeDataChunkOnLane(idx int, id uint64, offset int64, payload []byte) error {
	if len(payload) > maxDataChunkSize {
		return fmt.Errorf("data chunk too large: %d", len(payload))
	}
	buf := acquireDataBuffer()
	copy(buf[dataHeaderSize:], payload)
	err := s.writePreparedDataChunkOnLane(idx, id, preparedDataChunk{
		buf: buf, offset: offset, payloadLen: len(payload),
	})
	releaseDataBuffer(buf)
	return err
}

func (s *peerSession) handleTransferDataOwned(id uint64, offset int64, buf []byte, payloadLen int) error {
	t := s.getInbound(id)
	if t == nil {
		releaseDataBuffer(buf)
		return fmt.Errorf("data for unknown transfer %d", id)
	}

	t.mu.Lock()
	if t.cancelled || t.currentFile == nil {
		cancelled := t.cancelled
		t.mu.Unlock()
		releaseDataBuffer(buf)
		if cancelled {
			return nil
		}
		return errors.New("data arrived without active file")
	}
	size := t.currentRemaining
	st := getInboundData(t)
	t.mu.Unlock()

	if st == nil {
		releaseDataBuffer(buf)
		return errors.New("data state missing")
	}
	if offset < 0 || payloadLen < 0 || payloadLen > maxDataChunkSize ||
		offset+int64(payloadLen) > size {
		releaseDataBuffer(buf)
		s.cancelInbound(id, "received data outside declared file range", true)
		return nil
	}
	if !st.enqueue(inboundDataChunk{buf: buf, offset: offset, payloadLen: payloadLen}) {
		releaseDataBuffer(buf)
	}
	return nil
}

func (s *peerSession) dataLaneReadLoop(lane io.ReadWriteCloser) {
	header := make([]byte, dataHeaderSize)
	for {
		if _, err := io.ReadFull(lane, header); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				s.reportTransportError("数据流", err)
			}
			return
		}
		id := binary.BigEndian.Uint64(header[0:8])
		offset := int64(binary.BigEndian.Uint64(header[8:16]))
		want := int(binary.BigEndian.Uint32(header[16:20]))
		if want < 0 || want > maxDataChunkSize {
			consolePrintf("[数据流] 无效数据长度: %d\n", want)
			return
		}

		buf := acquireDataBuffer()
		copy(buf[:dataHeaderSize], header)
		if _, err := io.ReadFull(lane, buf[dataHeaderSize:dataHeaderSize+want]); err != nil {
			releaseDataBuffer(buf)
			s.reportTransportError("数据流", err)
			return
		}
		if err := s.handleTransferDataOwned(id, offset, buf, want); err != nil {
			consolePrintf("[数据流] 数据处理失败: %v\n", err)
		}
	}
}
