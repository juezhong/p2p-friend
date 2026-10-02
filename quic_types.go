package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	signalVersion      = 12
	signalInvitePrefix = "P2PF-INVITE-"
	signalReplyPrefix  = "P2PF-REPLY-"
	quicALPN           = "p2p-friend/12"
	punchMagic         = "P2PF12PUNCH"

	maxDynamicCandidates = 16
	maxRemoteCandidates  = 32
)

// signalCandidate / signalCode 只是在进程内表示识别码内容；线上格式由
// encodeSignal/decodeSignal 的紧凑二进制编码定义。
type signalCandidate struct {
	Addr string
	Type string
}

type signalCode struct {
	Version     int
	Kind        string
	Token       string
	Candidates  []signalCandidate
	Fingerprint string
}

type udpEndpoint struct {
	conn      *net.UDPConn
	transport *quic.Transport
	listener  *quic.Listener
	family    int
}

// rtcPeer 是历史类型名，当前实现不是 WebRTC peer。
// server 只表示“创建方 / 传输仲裁方”，v12 起双方都会同时尝试 QUIC Listen + Dial。
type rtcPeer struct {
	token []byte

	cert             tls.Certificate
	localFingerprint []byte
	remoteFingerprint []byte

	// fingerprint 保留给旧的包内测试辅助路径：创建方保存本机指纹，
	// 加入方在解析邀请码后保存远端创建方指纹。正式 v12 建链使用上面的
	// localFingerprint / remoteFingerprint。
	fingerprint []byte

	punchNonce [12]byte
	punchSeenMu sync.Mutex
	punchSeen   map[[8]byte]time.Time
	endpoints  []*udpEndpoint

	localMu sync.RWMutex
	local   []signalCandidate

	remoteMu sync.RWMutex
	remote   []signalCandidate

	networkInfoMu    sync.RWMutex
	mappingBehavior  string
	stunObservations []string
	portMappings     []string

	cleanupMu sync.Mutex
	cleanups  []func()

	server    bool
	closeOnce sync.Once
}

type quicStreamConn struct{ *quic.Stream }

func (s *quicStreamConn) Close() error { return s.Stream.Close() }

type rtcConn struct {
	control  *quic.Stream
	lanes    []io.ReadWriteCloser
	qc       *quic.Conn
	peer     *rtcPeer
	outbound bool
	once     sync.Once
}

type quicAddr struct{ net.Addr }

func (a quicAddr) Network() string {
	if a.Addr == nil {
		return "quic/udp"
	}
	return "quic/" + a.Addr.Network()
}

func (c *rtcConn) Read(p []byte) (int, error)         { return c.control.Read(p) }
func (c *rtcConn) Write(p []byte) (int, error)        { return c.control.Write(p) }
func (c *rtcConn) LocalAddr() net.Addr                { return quicAddr{c.qc.LocalAddr()} }
func (c *rtcConn) RemoteAddr() net.Addr               { return quicAddr{c.qc.RemoteAddr()} }
func (c *rtcConn) SetReadDeadline(t time.Time) error  { return c.control.SetReadDeadline(t) }
func (c *rtcConn) SetWriteDeadline(t time.Time) error { return c.control.SetWriteDeadline(t) }
func (c *rtcConn) SetDeadline(t time.Time) error      { return c.control.SetDeadline(t) }
func (c *rtcConn) DataLanes() []io.ReadWriteCloser    { return c.lanes }
func (c *rtcConn) TransferCoordinator() bool          { return c.peer.server }
func (c *rtcConn) QUICOutbound() bool                 { return c.outbound }

func (c *rtcConn) LinkMode() string {
	return classifyQUICLink(c.qc, c.peer.remoteCandidates())
}

func (c *rtcConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.qc.CloseWithError(0, "normal shutdown")
		_ = c.peer.Close()
	})
	return err
}

func (p *rtcPeer) setLocalCandidates(cands []signalCandidate) {
	p.localMu.Lock()
	p.local = append([]signalCandidate(nil), cands...)
	p.localMu.Unlock()
}

func (p *rtcPeer) localCandidates() []signalCandidate {
	p.localMu.RLock()
	defer p.localMu.RUnlock()
	return append([]signalCandidate(nil), p.local...)
}

func (p *rtcPeer) setRemoteCandidates(cands []signalCandidate) {
	p.remoteMu.Lock()
	p.remote = append([]signalCandidate(nil), cands...)
	p.remoteMu.Unlock()
}

// addRemoteCandidate 只给运行时发现的真实 peer endpoint 使用。
// 数量有硬上限，即使会话 token 泄漏后有人持续发送合法格式 probe，也不能无限增长。
func (p *rtcPeer) addRemoteCandidate(c signalCandidate) bool {
	addr, _, err := parseCandidate(c)
	if err != nil || addr == nil || addr.Port <= 0 {
		return false
	}
	if c.Type != "prflx" {
		return false
	}

	p.remoteMu.Lock()
	defer p.remoteMu.Unlock()

	for i := range p.remote {
		if !sameUDPAddress(p.remote[i].Addr, c.Addr) {
			continue
		}
		// 已有显式/信令 candidate 比运行时 prflx 信息更强，不覆盖它。
		if p.remote[i].Type == "prflx" {
			p.remote[i] = c
		}
		return false
	}

	dynamic := 0
	for _, old := range p.remote {
		if old.Type == "prflx" {
			dynamic++
		}
	}
	if dynamic >= maxDynamicCandidates || len(p.remote) >= maxRemoteCandidates {
		return false
	}
	p.remote = append(p.remote, c)
	return true
}

func (p *rtcPeer) remoteCandidates() []signalCandidate {
	p.remoteMu.RLock()
	defer p.remoteMu.RUnlock()
	return append([]signalCandidate(nil), p.remote...)
}

func (p *rtcPeer) setNetworkInfo(behavior string, stun, mappings []string) {
	p.networkInfoMu.Lock()
	p.mappingBehavior = behavior
	p.stunObservations = append([]string(nil), stun...)
	p.portMappings = append([]string(nil), mappings...)
	p.networkInfoMu.Unlock()
}

func (p *rtcPeer) networkInfo() (string, []string, []string) {
	p.networkInfoMu.RLock()
	defer p.networkInfoMu.RUnlock()
	return p.mappingBehavior,
		append([]string(nil), p.stunObservations...),
		append([]string(nil), p.portMappings...)
}

func (p *rtcPeer) addCleanup(fn func()) {
	if fn == nil {
		return
	}
	p.cleanupMu.Lock()
	p.cleanups = append(p.cleanups, fn)
	p.cleanupMu.Unlock()
}

func classifyQUICLink(qc *quic.Conn, candidates []signalCandidate) string {
	addr, ok := qc.RemoteAddr().(*net.UDPAddr)
	if !ok || addr == nil || addr.IP == nil {
		return "QUIC"
	}
	ip := addr.IP
	if ip.To4() == nil {
		if ip.IsPrivate() {
			return "IPv6-LAN"
		}
		return "IPv6-DIRECT"
	}
	if ip.IsPrivate() {
		return "IPv4-LAN"
	}

	remote := addr.String()
	bestType := ""
	for _, c := range candidates {
		if !sameUDPAddress(c.Addr, remote) {
			continue
		}
		switch strings.ToLower(c.Type) {
		case "host":
			bestType = "host"
		case "portmap":
			if bestType != "host" {
				bestType = "portmap"
			}
		case "prflx":
			if bestType == "" || bestType == "srflx" {
				bestType = "prflx"
			}
		case "srflx":
			if bestType == "" {
				bestType = "srflx"
			}
		}
	}
	switch bestType {
	case "portmap":
		return "IPv4-PORTMAP"
	case "prflx", "srflx":
		return "IPv4-NAT-PUNCH"
	default:
		return "IPv4-DIRECT"
	}
}

func sameUDPAddress(a, b string) bool {
	aa, errA := net.ResolveUDPAddr("udp", a)
	bb, errB := net.ResolveUDPAddr("udp", b)
	if errA != nil || errB != nil || aa == nil || bb == nil {
		return a == b
	}
	return aa.Port == bb.Port && aa.IP.Equal(bb.IP)
}

func newToken() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func generateQUICCertificate() (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "p2p-friend ephemeral"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, der, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           12 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         64 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow:     256 * 1024 * 1024,
		MaxIncomingStreams:             int64(parallelLanes + 8),
	}
}

func (p *rtcPeer) serverTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
	}
}

func (p *rtcPeer) clientTLSConfig() *tls.Config {
	expected := append([]byte(nil), p.remoteFingerprint...)
	if len(expected) == 0 {
		expected = append([]byte(nil), p.fingerprint...)
	}
	return &tls.Config{
		// 双方证书都是本次会话临时生成，不走公网 CA；信任根是识别码交换的
		// SHA-256 指纹。InsecureSkipVerify 只关闭默认 PKI，下面仍严格做 pinning。
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{quicALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(expected) != sha256.Size {
				return errors.New("missing remote QUIC certificate fingerprint")
			}
			if len(rawCerts) != 1 {
				return errors.New("unexpected QUIC certificate chain")
			}
			actual := sha256.Sum256(rawCerts[0])
			if !equalBytes(actual[:], expected) {
				return errors.New("QUIC certificate fingerprint mismatch")
			}
			return nil
		},
	}
}
