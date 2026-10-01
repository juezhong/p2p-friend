package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const dataHeaderSize = 20

type dataLaneProvider interface {
	DataLanes() []io.ReadWriteCloser
}

func (s *peerSession) writeDataChunk(id uint64, offset int64, payload []byte) error {
	if offset < 0 {
		return errors.New("negative data offset")
	}
	if len(s.dataLanes) == 0 {
		buf := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint64(buf[:8], uint64(offset))
		copy(buf[8:], payload)
		return s.writeFrame(frameData, id, buf)
	}
	idx := int((s.dataLaneSeq.Add(1) - 1) % uint64(len(s.dataLanes)))
	return s.writeDataChunkOnLane(idx, id, offset, payload)
}

func (s *peerSession) writeDataChunkOnLane(idx int, id uint64, offset int64, payload []byte) error {
	if idx < 0 || idx >= len(s.dataLanes) {
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

	s.dataLaneMu[idx].Lock()
	defer s.dataLaneMu[idx].Unlock()
	n, err := s.dataLanes[idx].Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return err
}

func (s *peerSession) dataLaneReadLoop(lane io.ReadWriteCloser) {
	buf := make([]byte, dataHeaderSize+dataChunkSize)
	for {
		n, err := lane.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosedErr(err) {
				consolePrintf("[数据流] 读取失败: %v\n", err)
			}
			return
		}
		if n < dataHeaderSize {
			consolePrintf("[数据流] 无效数据帧长度: %d\n", n)
			continue
		}
		id := binary.BigEndian.Uint64(buf[0:8])
		offset := int64(binary.BigEndian.Uint64(buf[8:16]))
		want := int(binary.BigEndian.Uint32(buf[16:20]))
		if want != n-dataHeaderSize || want > dataChunkSize {
			consolePrintf("[数据流] 无效数据长度: frame=%d payload=%d\n", n, want)
			continue
		}
		data := make([]byte, want)
		copy(data, buf[dataHeaderSize:n])
		if err := s.handleTransferDataAt(id, offset, data); err != nil {
			consolePrintf("[数据流] 数据处理失败: %v\n", err)
		}
	}
}
