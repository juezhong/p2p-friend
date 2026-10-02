package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	frameEntryReady  = byte(11)
	dataHeaderSize   = 20
	maxDataChunkSize = 256 * 1024
	parallelLanes    = 4
)

type transferTuningProfile struct {
	chunkSize int
	lanes     int
	pace      time.Duration
}

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
		// 高档位仅保留极轻的 burst pacing，目标是避免 Winsock 短时队列峰值，
		// 而不是限速。真正的链路拥塞仍完全交给 QUIC congestion control。
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
	// Windows 从 2 lane / 128 KiB 起步，避免一次把 Winsock 队列压满；
	// Linux/macOS 从 3 lane 左右起步。之后都按实际吞吐探测到最高档。
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
	return &adaptiveTransferTuner{
		goos:     goos,
		maxLanes: maxLanes,
		levels:   levels,
		level:    initial,
	}
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
		// 真正的 socket / QUIC 写错误优先降档。正常网络拥塞由 QUIC 自己处理，
		// 不再用“某一批写了多久”这种绝对阈值误判慢链路。
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
	// 以吞吐窗口而不是单次 Write 延迟做判断。这样 1 MiB/s 和 100 MiB/s
	// 链路都能正常升档，不会因为 WAN RTT 或接收端背压被错误降到 1 lane。
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
		// 探测更高档后，只要吞吐没有明显恶化就保留；若下降超过约 10%，
		// 回到上一档并冷却几个窗口，避免在两个档位间频繁振荡。
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
		// 平滑基线，只用于下一次升档探测比较，不作为“网络拥塞”判断。
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

type dataLaneProvider interface {
	DataLanes() []io.ReadWriteCloser
}

type sessionDataState struct {
	lanes []io.ReadWriteCloser
	mu    []sync.Mutex
	seq   atomic.Uint64
}

type inboundDataState struct {
	chunks   map[int64]int
	received int64
	done     chan struct{}
	once     sync.Once
}

var sessionData sync.Map
var inboundData sync.Map
var outboundReady sync.Map

func attachDataLanes(s *peerSession, conn io.ReadWriteCloser) {
	provider, ok := conn.(dataLaneProvider)
	if !ok {
		return
	}
	lanes := provider.DataLanes()
	st := &sessionDataState{lanes: lanes, mu: make([]sync.Mutex, len(lanes))}
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

func resetInboundData(t *inboundTransfer, size int64) *inboundDataState {
	st := &inboundDataState{chunks: make(map[int64]int), done: make(chan struct{})}
	if size == 0 {
		st.once.Do(func() { close(st.done) })
	}
	inboundData.Store(t, st)
	return st
}

func getInboundData(t *inboundTransfer) *inboundDataState {
	v, _ := inboundData.Load(t)
	if v == nil {
		return nil
	}
	return v.(*inboundDataState)
}

func clearInboundData(t *inboundTransfer) {
	if st := getInboundData(t); st != nil {
		st.once.Do(func() { close(st.done) })
	}
	inboundData.Delete(t)
}

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

func (s *peerSession) writeDataChunkOnLane(idx int, id uint64, offset int64, payload []byte) error {
	st := dataState(s)
	if st == nil || idx < 0 || idx >= len(st.lanes) {
		return fmt.Errorf("invalid data lane: %d", idx)
	}
	if len(payload) > maxDataChunkSize {
		return fmt.Errorf("data chunk too large: %d", len(payload))
	}
	buf := make([]byte, dataHeaderSize+len(payload))
	binary.BigEndian.PutUint64(buf[0:8], id)
	binary.BigEndian.PutUint64(buf[8:16], uint64(offset))
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(payload)))
	copy(buf[dataHeaderSize:], payload)

	st.mu[idx].Lock()
	defer st.mu[idx].Unlock()
	n, err := st.lanes[idx].Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return err
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
		if want > maxDataChunkSize {
			consolePrintf("[数据流] 无效数据长度: %d\n", want)
			return
		}
		data := make([]byte, want)
		if _, err := io.ReadFull(lane, data); err != nil {
			s.reportTransportError("数据流", err)
			return
		}
		if err := s.handleTransferDataAt(id, offset, data); err != nil {
			consolePrintf("[数据流] 数据处理失败: %v\n", err)
		}
	}
}
