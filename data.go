package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

const (
	frameEntryReady = byte(11)
	dataHeaderSize  = 20
	dataChunkSize   = 256 * 1024
	parallelLanes   = 4
)

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

var sessionData sync.Map   // map[*peerSession]*sessionDataState
var inboundData sync.Map   // map[*inboundTransfer]*inboundDataState
var outboundReady sync.Map // map[*outboundTransfer]chan string

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
	if len(payload) > dataChunkSize {
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
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !isClosedErr(err) {
				consolePrintf("[数据流] 读取帧头失败: %v\n", err)
			}
			return
		}
		id := binary.BigEndian.Uint64(header[0:8])
		offset := int64(binary.BigEndian.Uint64(header[8:16]))
		want := int(binary.BigEndian.Uint32(header[16:20]))
		if want > dataChunkSize {
			consolePrintf("[数据流] 无效数据长度: %d\n", want)
			return
		}
		data := make([]byte, want)
		if _, err := io.ReadFull(lane, data); err != nil {
			if !isClosedErr(err) {
				consolePrintf("[数据流] 读取 payload 失败: %v\n", err)
			}
			return
		}
		if err := s.handleTransferDataAt(id, offset, data); err != nil {
			consolePrintf("[数据流] 数据处理失败: %v\n", err)
		}
	}
}
