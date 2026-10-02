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
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	signalVersion      = 7
	signalPrefixOffer  = "P2P7-OFFER-"
	signalPrefixAnswer = "P2P7-ANSWER-"
	quicALPN           = "p2p-friend/7"
	punchMagic         = "P2P7PUNCH"
)

type signalCode struct {
	Version     int      `json:"v"`
	Kind        string   `json:"kind"`
	Token       string   `json:"token"`
	Candidates  []string `json:"candidates"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type udpEndpoint struct {
	conn      *net.UDPConn
	transport *quic.Transport
	listener  *quic.Listener
	family    int
}

type rtcPeer struct {
	token       []byte
	fingerprint []byte
	cert        tls.Certificate
	endpoints   []*udpEndpoint
	remote      []string
	server      bool
	closeOnce   sync.Once
}

type quicStreamConn struct{ *quic.Stream }

func (s *quicStreamConn) Close() error { return s.Stream.Close() }

type rtcConn struct {
	control *quic.Stream
	lanes   []io.ReadWriteCloser
	qc      *quic.Conn
	peer    *rtcPeer
	once    sync.Once
}

type quicAddr struct{ net.Addr }

func (a quicAddr) Network() string {
	if a.Addr == nil {
		return "quic/udp"
	}
	return "quic/" + a.Addr.Network()
}

func (c *rtcConn) Read(p []byte) (int, error)       { return c.control.Read(p) }
func (c *rtcConn) Write(p []byte) (int, error)      { return c.control.Write(p) }
func (c *rtcConn) LocalAddr() net.Addr              { return quicAddr{c.qc.LocalAddr()} }
func (c *rtcConn) RemoteAddr() net.Addr             { return quicAddr{c.qc.RemoteAddr()} }
func (c *rtcConn) SetReadDeadline(t time.Time) error  { return c.control.SetReadDeadline(t) }
func (c *rtcConn) SetWriteDeadline(t time.Time) error { return c.control.SetWriteDeadline(t) }
func (c *rtcConn) SetDeadline(t time.Time) error      { return c.control.SetDeadline(t) }
func (c *rtcConn) DataLanes() []io.ReadWriteCloser    { return c.lanes }

func (c *rtcConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = c.control.Close()
		for _, lane := range c.lanes {
			_ = lane.Close()
		}
		err = c.qc.CloseWithError(0, "session closed")
		_ = c.peer.Close()
	})
	return err
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
		Subject: pkix.Name{CommonName: "p2p-friend ephemeral"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, der, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 12 * time.Second,
		MaxIdleTimeout: 60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		InitialStreamReceiveWindow: 16 * 1024 * 1024,
		MaxStreamReceiveWindow: 64 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxConnectionReceiveWindow: 256 * 1024 * 1024,
		MaxIncomingStreams: int64(parallelLanes + 8),
	}
}

func (p *rtcPeer) serverTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.cert},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{quicALPN},
	}
}

func (p *rtcPeer) clientTLSConfig() *tls.Config {
	expected := append([]byte(nil), p.fingerprint...)
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{quicALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
