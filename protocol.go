package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func (s *peerSession) writeFrame(typ byte, id uint64, payload []byte) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("frame payload too large: %d", len(payload))
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	select {
	case <-s.closed:
		return errors.New("connection is closed")
	default:
	}

	var header [13]byte
	header[0] = typ
	binary.BigEndian.PutUint64(header[1:9], id)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(payload)))
	if _, err := s.bw.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.bw.Write(payload); err != nil {
			return err
		}
	}
	return s.bw.Flush()
}

func readFrame(r io.Reader) (wireFrame, error) {
	var f wireFrame
	var header [13]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return f, err
	}
	f.Type = header[0]
	f.ID = binary.BigEndian.Uint64(header[1:9])
	n := binary.BigEndian.Uint32(header[9:13])
	if n > maxFramePayload {
		return f, fmt.Errorf("frame payload too large: %d", n)
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return f, err
		}
	}
	return f, nil
}

func (s *peerSession) writeJSONFrame(typ byte, id uint64, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.writeFrame(typ, id, b)
}

func decodeJSON(payload []byte, v any) error {
	if len(payload) == 0 {
		return errors.New("empty JSON frame")
	}
	return json.Unmarshal(payload, v)
}

func (s *peerSession) nextRequestID() uint64 {
	return s.requestSeq.Add(1)
}

func (s *peerSession) nextTransferID() uint64 {
	return s.transferSeq.Add(1)
}
