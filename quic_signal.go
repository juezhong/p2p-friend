package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/pion/stun/v3"
	quic "github.com/quic-go/quic-go"
)

func newPeer(server bool) (*rtcPeer, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	p := &rtcPeer{token: token, server: server}
	if server {
		cert, der, err := generateQUICCertificate()
		if err != nil {
			return nil, err
		}
		p.cert = cert
		sum := sha256.Sum256(der)
		p.fingerprint = append([]byte(nil), sum[:]...)
	}
	for _, network := range []string{"udp6", "udp4"} {
		conn, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
		if err != nil {
			continue
		}
		_ = conn.SetReadBuffer(16 * 1024 * 1024)
		_ = conn.SetWriteBuffer(16 * 1024 * 1024)
		family := 4
		if network == "udp6" {
			family = 6
		}
		p.endpoints = append(p.endpoints, &udpEndpoint{
			conn: conn, transport: &quic.Transport{Conn: conn}, family: family,
		})
	}
	if len(p.endpoints) == 0 {
		return nil, errors.New("unable to open UDP4/UDP6 socket")
	}
	return p, nil
}

func (p *rtcPeer) Close() error {
	var first error
	p.closeOnce.Do(func() {
		for _, ep := range p.endpoints {
			if ep.listener != nil {
				_ = ep.listener.Close()
			}
			if ep.transport != nil {
				if err := ep.transport.Close(); err != nil && first == nil {
					first = err
				}
			} else if ep.conn != nil {
				if err := ep.conn.Close(); err != nil && first == nil {
					first = err
				}
			}
		}
	})
	return first
}

func createHostOffer() (*rtcPeer, string, error) {
	p, err := newPeer(true)
	if err != nil {
		return nil, "", err
	}
	cands := gatherCandidates(p.endpoints)
	if len(cands) == 0 {
		_ = p.Close()
		return nil, "", errors.New("没有可用 UDP candidate")
	}
	code, err := encodeSignal(signalCode{
		Version: signalVersion,
		Kind: "offer",
		Token: base64.RawURLEncoding.EncodeToString(p.token),
		Candidates: cands,
		Fingerprint: hex.EncodeToString(p.fingerprint),
	})
	if err != nil {
		_ = p.Close()
		return nil, "", err
	}
	return p, code, nil
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
	fp, err := hex.DecodeString(code.Fingerprint)
	if err != nil || len(fp) != 32 {
		return nil, "", nil, errors.New("OFFER 中的 QUIC 证书指纹无效")
	}
	p, err := newPeer(false)
	if err != nil {
		return nil, "", nil, err
	}
	p.token = token
	p.fingerprint = fp
	p.remote = append([]string(nil), code.Candidates...)
	cands := gatherCandidates(p.endpoints)
	if len(cands) == 0 {
		_ = p.Close()
		return nil, "", nil, errors.New("没有可用 UDP candidate")
	}
	answer, err := encodeSignal(signalCode{
		Version: signalVersion,
		Kind: "answer",
		Token: code.Token,
		Candidates: cands,
	})
	if err != nil {
		_ = p.Close()
		return nil, "", nil, err
	}
	return p, answer, token, nil
}

func (p *rtcPeer) acceptAnswer(raw string) (net.Conn, []byte, error) {
	code, err := decodeSignal(raw, "answer")
	if err != nil {
		return nil, nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(code.Token)
	if err != nil || !equalBytes(token, p.token) {
		return nil, nil, errors.New("ANSWER 与当前会话不匹配")
	}
	p.remote = append([]string(nil), code.Candidates...)
	conn, err := p.acceptQUIC()
	return conn, p.token, err
}

func (p *rtcPeer) waitConn() (net.Conn, error) { return p.dialQUIC() }

func gatherCandidates(endpoints []*udpEndpoint) []string {
	set := map[string]struct{}{}
	ifaces, _ := net.Interfaces()
	for _, ep := range endpoints {
		port := ep.conn.LocalAddr().(*net.UDPAddr).Port
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, raw := range addrs {
				var ip net.IP
				switch v := raw.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
					continue
				}
				if ep.family == 4 && ip.To4() == nil {
					continue
				}
				if ep.family == 6 && ip.To4() != nil {
					continue
				}
				set[net.JoinHostPort(ip.String(), fmt.Sprint(port))] = struct{}{}
			}
		}
		if ep.family == 4 {
			if addr, err := stunMappedAddress(ep.conn); err == nil {
				set[addr.String()] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return candidateRank(out[i]) < candidateRank(out[j]) })
	return out
}

func candidateRank(s string) int {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return 9
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return 9
	}
	if ip.To4() == nil && !ip.IsPrivate() {
		return 0
	}
	if ip.To4() != nil && !ip.IsPrivate() {
		return 1
	}
	if ip.To4() == nil {
		return 2
	}
	return 3
}

func stunMappedAddress(conn *net.UDPConn) (*net.UDPAddr, error) {
	for _, server := range []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"} {
		addr, err := net.ResolveUDPAddr("udp4", server)
		if err != nil {
			continue
		}
		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		if _, err := conn.WriteToUDP(req.Raw, addr); err != nil {
			continue
		}
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			res := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if err := res.Decode(); err != nil || res.TransactionID != req.TransactionID {
				continue
			}
			var xor stun.XORMappedAddress
			if err := xor.GetFrom(res); err == nil {
				_ = conn.SetDeadline(time.Time{})
				return &net.UDPAddr{IP: xor.IP, Port: xor.Port}, nil
			}
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return nil, errors.New("STUN failed")
}

func parseCandidate(raw string) (*net.UDPAddr, int, error) {
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		return nil, 0, err
	}
	family := 6
	if addr.IP.To4() != nil {
		family = 4
	}
	return addr, family, nil
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
	if c.Version != signalVersion || c.Kind != expectedKind || len(c.Candidates) == 0 {
		return c, errors.New("连接码协议版本或类型不匹配")
	}
	return c, nil
}

func readSignalLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
