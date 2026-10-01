package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	signalVersion      = 6
	signalPrefixOffer  = "P2P6-OFFER-"
	signalPrefixAnswer = "P2P6-ANSWER-"
	controlLabel       = "control"
)

type signalCode struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	Token   string `json:"token"`
	SDP     string `json:"sdp"`
}

type detachedChannel struct {
	label string
	rw    io.ReadWriteCloser
	err   error
}

type rtcPeer struct {
	pc        *webrtc.PeerConnection
	token     []byte
	detached  chan detachedChannel
	stateCh   chan webrtc.PeerConnectionState
	closeOnce sync.Once
}

type rtcConn struct {
	control *messageStream
	lanes   []io.ReadWriteCloser
	pc      *webrtc.PeerConnection
	closed  chan struct{}
	once    sync.Once
}

type messageStream struct {
	rw      io.ReadWriteCloser
	readMu  sync.Mutex
	writeMu sync.Mutex
	remain  []byte
}

type rtcAddr string

func (a rtcAddr) Network() string { return "webrtc/udp" }
func (a rtcAddr) String() string  { return string(a) }

func (s *messageStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(s.remain) == 0 {
		buf := make([]byte, 64*1024)
		n, err := s.rw.Read(buf)
		if err != nil {
			return 0, err
		}
		s.remain = buf[:n]
	}
	n := copy(p, s.remain)
	s.remain = s.remain[n:]
	return n, nil
}

func (s *messageStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	// Detached DataChannel preserves message boundaries. net.Conn semantics allow
	// short writes, but callers in this program expect a complete frame write.
	written := 0
	for len(p) > 0 {
		n := 16 * 1024
		if len(p) < n {
			n = len(p)
		}
		m, err := s.rw.Write(p[:n])
		written += m
		if err != nil {
			return written, err
		}
		if m != n {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	return written, nil
}

func (s *messageStream) Close() error { return s.rw.Close() }

func (c *rtcConn) Read(p []byte) (int, error)       { return c.control.Read(p) }
func (c *rtcConn) Write(p []byte) (int, error)      { return c.control.Write(p) }
func (c *rtcConn) LocalAddr() net.Addr              { return rtcAddr("ICE/UDP local") }
func (c *rtcConn) RemoteAddr() net.Addr             { return rtcAddr("ICE/UDP peer") }
func (c *rtcConn) SetDeadline(time.Time) error      { return nil }
func (c *rtcConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rtcConn) SetWriteDeadline(time.Time) error { return nil }
func (c *rtcConn) DataLanes() []io.ReadWriteCloser  { return c.lanes }

func (c *rtcConn) Close() error {
	var first error
	c.once.Do(func() {
		close(c.closed)
		if c.control != nil {
			if err := c.control.Close(); err != nil && first == nil {
				first = err
			}
		}
		for _, lane := range c.lanes {
			if err := lane.Close(); err != nil && first == nil {
				first = err
			}
		}
		if c.pc != nil {
			if err := c.pc.Close(); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

func newRTCPeer(createChannels bool) (*rtcPeer, error) {
	var se webrtc.SettingEngine
	se.DetachDataChannels()
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.cloudflare.com:3478"}},
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	})
	if err != nil {
		return nil, err
	}
	p := &rtcPeer{
		pc:       pc,
		detached: make(chan detachedChannel, parallelLanes+1),
		stateCh:  make(chan webrtc.PeerConnectionState, 16),
	}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		select {
		case p.stateCh <- state:
		default:
		}
	})
	register := func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			rw, err := dc.Detach()
			p.detached <- detachedChannel{label: dc.Label(), rw: rw, err: err}
		})
	}
	if createChannels {
		// The control channel stays ordered and reliable. Data lanes are reliable
		// but unordered: chunks carry absolute file offsets, so independent SCTP
		// streams don't need to wait for earlier chunks from the same file. Packet
		// loss is still retransmitted by SCTP; SHA-256 is the final end-to-end check.
		control, err := pc.CreateDataChannel(controlLabel, nil)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
		register(control)

		ordered := false
		for i := 0; i < parallelLanes; i++ {
			label := fmt.Sprintf("data-%d", i)
			dc, err := pc.CreateDataChannel(label, &webrtc.DataChannelInit{Ordered: &ordered})
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			register(dc)
		}
	} else {
		pc.OnDataChannel(register)
	}
	return p, nil
}

func newToken() ([]byte, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	return token, err
}

func createHostOffer() (*rtcPeer, string, error) {
	p, err := newRTCPeer(true)
	if err != nil {
		return nil, "", err
	}
	token, err := newToken()
	if err != nil {
		_ = p.pc.Close()
		return nil, "", err
	}
	p.token = token
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		_ = p.pc.Close()
		return nil, "", err
	}
	gatherDone := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(offer); err != nil {
		_ = p.pc.Close()
		return nil, "", err
	}
	if err := waitGather(gatherDone); err != nil {
		_ = p.pc.Close()
		return nil, "", err
	}
	local := p.pc.LocalDescription()
	if local == nil {
		_ = p.pc.Close()
		return nil, "", errors.New("missing local offer")
	}
	code, err := encodeSignal(signalCode{
		Version: signalVersion,
		Kind:    "offer",
		Token:   base64.RawURLEncoding.EncodeToString(token),
		SDP:     local.SDP,
	})
	if err != nil {
		_ = p.pc.Close()
		return nil, "", err
	}
	return p, code, nil
}

func (p *rtcPeer) acceptAnswer(raw string) (net.Conn, []byte, error) {
	code, err := decodeSignal(raw, "answer")
	if err != nil {
		return nil, nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(code.Token)
	if err != nil || !bytes.Equal(token, p.token) {
		return nil, nil, errors.New("ANSWER 与当前会话不匹配")
	}
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: code.SDP}); err != nil {
		return nil, nil, fmt.Errorf("set remote answer: %w", err)
	}
	conn, err := p.waitConn()
	return conn, p.token, err
}

func createJoinAnswer(rawOffer string) (*rtcPeer, string, []byte, error) {
	code, err := decodeSignal(rawOffer, "offer")
	if err != nil {
		return nil, "", nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(code.Token)
	if err != nil || len(token) != 32 {
		return nil, "", nil, errors.New("OFFER 中的会话 token 无效")
	}
	p, err := newRTCPeer(false)
	if err != nil {
		return nil, "", nil, err
	}
	p.token = token
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: code.SDP}); err != nil {
		_ = p.pc.Close()
		return nil, "", nil, fmt.Errorf("set remote offer: %w", err)
	}
	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		_ = p.pc.Close()
		return nil, "", nil, err
	}
	gatherDone := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(answer); err != nil {
		_ = p.pc.Close()
		return nil, "", nil, err
	}
	if err := waitGather(gatherDone); err != nil {
		_ = p.pc.Close()
		return nil, "", nil, err
	}
	local := p.pc.LocalDescription()
	if local == nil {
		_ = p.pc.Close()
		return nil, "", nil, errors.New("missing local answer")
	}
	answerCode, err := encodeSignal(signalCode{
		Version: signalVersion,
		Kind:    "answer",
		Token:   code.Token,
		SDP:     local.SDP,
	})
	if err != nil {
		_ = p.pc.Close()
		return nil, "", nil, err
	}
	return p, answerCode, token, nil
}

func (p *rtcPeer) waitConn() (net.Conn, error) {
	want := parallelLanes + 1
	channels := make(map[string]io.ReadWriteCloser, want)
	timer := time.NewTimer(75 * time.Second)
	defer timer.Stop()
	for len(channels) < want {
		select {
		case d := <-p.detached:
			if d.err != nil {
				return nil, d.err
			}
			channels[d.label] = d.rw
		case state := <-p.stateCh:
			if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
				return nil, fmt.Errorf("ICE/DTLS connection %s", state.String())
			}
		case <-timer.C:
			return nil, errors.New("ICE/UDP 连接超时：IPv4 NAT 打洞和 IPv6 直连候选均未建立")
		}
	}
	control := channels[controlLabel]
	if control == nil {
		return nil, errors.New("control data channel missing")
	}
	lanes := make([]io.ReadWriteCloser, 0, parallelLanes)
	for i := 0; i < parallelLanes; i++ {
		label := fmt.Sprintf("data-%d", i)
		lane := channels[label]
		if lane == nil {
			return nil, fmt.Errorf("data channel missing: %s", label)
		}
		lanes = append(lanes, lane)
	}
	return &rtcConn{
		control: &messageStream{rw: control},
		lanes:   lanes,
		pc:      p.pc,
		closed:  make(chan struct{}),
	}, nil
}

func waitGather(done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-time.After(15 * time.Second):
		return errors.New("ICE candidate gathering timeout")
	}
}

func encodeSignal(c signalCode) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	prefix := signalPrefixOffer
	if c.Kind == "answer" {
		prefix = signalPrefixAnswer
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeSignal(s, expectedKind string) (signalCode, error) {
	var c signalCode
	s = strings.TrimSpace(s)
	prefix := signalPrefixOffer
	if expectedKind == "answer" {
		prefix = signalPrefixAnswer
	}
	if !strings.HasPrefix(s, prefix) {
		return c, fmt.Errorf("连接码类型错误：需要 %s", strings.TrimSuffix(prefix, "-"))
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Version != signalVersion || c.Kind != expectedKind || c.SDP == "" {
		return c, errors.New("连接码协议版本或类型不匹配")
	}
	return c, nil
}

// readSignalLine avoids Scanner's token limit because SDP connection codes are large.
func readSignalLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
