package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
				if err := ep.transport.Close(); err != nil && !errors.Is(err, net.ErrClosed) && first == nil {
					first = err
				}
			}
			// Transport and listener lifetime are independent from the UDPConn.
			// Explicitly close the socket we opened so the OS port is released
			// immediately on normal process/session exit.
			if ep.conn != nil {
				if err := ep.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && first == nil {
					first = err
				}
			}
		}
	})
	return first
}

func createConnectionCode() (*rtcPeer, string, error) {
	p, err := newPeer(true)
	if err != nil {
		return nil, "", err
	}
	cands := gatherCandidates(p.endpoints)
	p.setLocalCandidates(cands)
	if len(cands) == 0 {
		_ = p.Close()
		return nil, "", errors.New("没有可用 UDP candidate")
	}
	code, err := encodeSignal(signalCode{
		Version:     signalVersion,
		Kind:        "connect",
		Token:       base64.RawURLEncoding.EncodeToString(p.token),
		Candidates:  cands,
		Fingerprint: hex.EncodeToString(p.fingerprint),
	})
	if err != nil {
		_ = p.Close()
		return nil, "", err
	}
	return p, code, nil
}

func createJoinConfirmation(rawCode string) (*rtcPeer, string, []byte, error) {
	code, err := decodeSignal(rawCode, "connect")
	if err != nil {
		return nil, "", nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(code.Token)
	if err != nil || len(token) != 32 {
		return nil, "", nil, errors.New("连接码中的会话 token 无效")
	}
	fp, err := hex.DecodeString(code.Fingerprint)
	if err != nil || len(fp) != 32 {
		return nil, "", nil, errors.New("连接码中的 QUIC 证书指纹无效")
	}
	p, err := newPeer(false)
	if err != nil {
		return nil, "", nil, err
	}
	p.token = token
	p.fingerprint = fp
	p.setRemoteCandidates(code.Candidates)
	cands := gatherCandidates(p.endpoints)
	p.setLocalCandidates(cands)
	if len(cands) == 0 {
		_ = p.Close()
		return nil, "", nil, errors.New("没有可用 UDP candidate")
	}
	confirm, err := encodeSignal(signalCode{
		Version:    signalVersion,
		Kind:       "confirm",
		Token:      code.Token,
		Candidates: cands,
	})
	if err != nil {
		_ = p.Close()
		return nil, "", nil, err
	}
	return p, confirm, token, nil
}

func (p *rtcPeer) applyConfirmation(raw string) error {
	code, err := decodeSignal(raw, "confirm")
	if err != nil {
		return err
	}
	token, err := base64.RawURLEncoding.DecodeString(code.Token)
	if err != nil || !equalBytes(token, p.token) {
		return errors.New("确认码与当前连接不匹配")
	}
	p.setRemoteCandidates(code.Candidates)
	return nil
}

func (p *rtcPeer) waitConn() (net.Conn, error) { return p.dialQUIC() }

func gatherCandidates(endpoints []*udpEndpoint) []signalCandidate {
	set := map[string]signalCandidate{}
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
				addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
				set["host|"+addr] = signalCandidate{Addr: addr, Type: "host"}
			}
		}
		if ep.family == 4 {
			if addr, err := stunMappedAddress(ep.conn); err == nil {
				key := "srflx|" + addr.String()
				set[key] = signalCandidate{Addr: addr.String(), Type: "srflx"}
			}
		}
	}
	out := make([]signalCandidate, 0, len(set))
	for _, c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		ri := candidateRank(out[i])
		rj := candidateRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

func candidateRank(c signalCandidate) int {
	host, _, err := net.SplitHostPort(c.Addr)
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
	if c.Type == "srflx" {
		return 1
	}
	if ip.To4() != nil && !ip.IsPrivate() {
		return 2
	}
	if ip.To4() == nil {
		return 3
	}
	return 4
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

func parseCandidate(raw signalCandidate) (*net.UDPAddr, int, error) {
	addr, err := net.ResolveUDPAddr("udp", raw.Addr)
	if err != nil {
		return nil, 0, err
	}
	family := 6
	if addr.IP.To4() != nil {
		family = 4
	}
	return addr, family, nil
}

const (
	maxSignalCandidates = 16
	maxSignalPayload     = 1024
)

func signalPrefixForKind(kind string) (string, error) {
	switch kind {
	case "connect":
		return signalInvitePrefix, nil
	case "confirm":
		return signalReplyPrefix, nil
	default:
		return "", fmt.Errorf("unknown signal kind: %s", kind)
	}
}

func normalizeSignalCandidates(in []signalCandidate) ([]signalCandidate, error) {
	byAddr := make(map[string]signalCandidate)
	for _, cand := range in {
		addr, err := net.ResolveUDPAddr("udp", cand.Addr)
		if err != nil || addr == nil || addr.IP == nil || addr.Port <= 0 || addr.Port > 65535 {
			return nil, fmt.Errorf("invalid candidate %q", cand.Addr)
		}
		if addr.IP.IsUnspecified() || addr.IP.IsLoopback() || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(cand.Type))
		if typ != "host" && typ != "srflx" {
			return nil, fmt.Errorf("unsupported candidate type %q", cand.Type)
		}
		ip := addr.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		} else {
			ip = ip.To16()
		}
		if ip == nil {
			continue
		}
		key := net.JoinHostPort(ip.String(), fmt.Sprint(addr.Port))
		normalized := signalCandidate{Addr: key, Type: typ}
		if prev, ok := byAddr[key]; ok {
			// 同一公网地址同时作为 host / srflx 出现时，host 更能准确表示
			// “无需 NAT 映射即可直接到达”，同时也减少识别码长度。
			if prev.Type == "host" || typ != "host" {
				continue
			}
		}
		byAddr[key] = normalized
	}
	out := make([]signalCandidate, 0, len(byAddr))
	for _, cand := range byAddr {
		out = append(out, cand)
	}
	sort.Slice(out, func(i, j int) bool {
		ri := candidateRank(out[i])
		rj := candidateRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].Addr < out[j].Addr
	})
	if len(out) > maxSignalCandidates {
		out = out[:maxSignalCandidates]
	}
	if len(out) == 0 {
		return nil, errors.New("没有可编码的 UDP candidate")
	}
	return out, nil
}

func encodeSignal(c signalCode) (string, error) {
	prefix, err := signalPrefixForKind(c.Kind)
	if err != nil {
		return "", err
	}
	if c.Version != signalVersion {
		return "", fmt.Errorf("unsupported signal version %d", c.Version)
	}

	token, err := base64.RawURLEncoding.DecodeString(c.Token)
	if err != nil || len(token) != 32 {
		return "", errors.New("识别码 token 必须是 256-bit")
	}
	var fingerprint []byte
	if c.Kind == "connect" {
		fingerprint, err = hex.DecodeString(c.Fingerprint)
		if err != nil || len(fingerprint) != 32 {
			return "", errors.New("INVITE 证书指纹必须是 SHA-256")
		}
	}

	cands, err := normalizeSignalCandidates(c.Candidates)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	buf.Grow(2 + len(token) + len(fingerprint) + len(cands)*20)
	buf.WriteByte(byte(signalVersion))
	buf.WriteByte(byte(len(cands)))
	buf.Write(token)
	if c.Kind == "connect" {
		buf.Write(fingerprint)
	}
	for _, cand := range cands {
		addr, err := net.ResolveUDPAddr("udp", cand.Addr)
		if err != nil {
			return "", err
		}
		flags := byte(0)
		ip := addr.IP.To4()
		if ip == nil {
			flags |= 0x01
			ip = addr.IP.To16()
		}
		if strings.EqualFold(cand.Type, "srflx") {
			flags |= 0x02
		}
		buf.WriteByte(flags)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(addr.Port))
		buf.Write(port[:])
		buf.Write(ip)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func decodeSignal(s, expectedKind string) (signalCode, error) {
	var c signalCode
	s = strings.TrimSpace(s)
	expectedPrefix, err := signalPrefixForKind(expectedKind)
	if err != nil {
		return c, err
	}
	if !strings.HasPrefix(s, expectedPrefix) {
		switch {
		case strings.HasPrefix(s, signalInvitePrefix) && expectedKind == "confirm":
			return c, errors.New("这是 P2PF-INVITE 邀请码；它应发给准备加入连接的一方。当前创建方需要 P2PF-REPLY 回传码")
		case strings.HasPrefix(s, signalReplyPrefix) && expectedKind == "connect":
			return c, errors.New("这是 P2PF-REPLY 回传码；它应交回创建方。加入连接需要 P2PF-INVITE 邀请码")
		default:
			return c, fmt.Errorf("识别码格式错误：当前需要 %s...", expectedPrefix)
		}
	}

	rawText := strings.TrimPrefix(s, expectedPrefix)
	if len(rawText) > base64.RawURLEncoding.EncodedLen(maxSignalPayload) {
		return c, errors.New("识别码过长")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rawText)
	if err != nil {
		return c, errors.New("识别码 Base64 数据无效")
	}
	if len(raw) < 2+32 {
		return c, errors.New("识别码数据过短")
	}
	if int(raw[0]) != signalVersion {
		return c, fmt.Errorf("识别码协议版本不匹配：收到 v%d，需要 v%d", raw[0], signalVersion)
	}
	count := int(raw[1])
	if count <= 0 || count > maxSignalCandidates {
		return c, errors.New("识别码 candidate 数量无效")
	}
	pos := 2
	if len(raw) < pos+32 {
		return c, errors.New("识别码缺少会话 token")
	}
	token := append([]byte(nil), raw[pos:pos+32]...)
	pos += 32

	var fingerprint []byte
	if expectedKind == "connect" {
		if len(raw) < pos+32 {
			return c, errors.New("INVITE 邀请码缺少证书指纹")
		}
		fingerprint = append([]byte(nil), raw[pos:pos+32]...)
		pos += 32
	}

	cands := make([]signalCandidate, 0, count)
	for i := 0; i < count; i++ {
		if len(raw) < pos+3 {
			return c, errors.New("识别码 candidate 数据不完整")
		}
		flags := raw[pos]
		pos++
		if flags&^byte(0x03) != 0 {
			return c, errors.New("识别码 candidate flags 无效")
		}
		port := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		pos += 2
		if port == 0 {
			return c, errors.New("识别码 candidate 端口无效")
		}
		ipLen := 4
		if flags&0x01 != 0 {
			ipLen = 16
		}
		if len(raw) < pos+ipLen {
			return c, errors.New("识别码 candidate IP 数据不完整")
		}
		ip := net.IP(append([]byte(nil), raw[pos:pos+ipLen]...))
		pos += ipLen
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return c, errors.New("识别码包含不可用 candidate")
		}
		typ := "host"
		if flags&0x02 != 0 {
			typ = "srflx"
		}
		cands = append(cands, signalCandidate{
			Addr: net.JoinHostPort(ip.String(), fmt.Sprint(port)),
			Type: typ,
		})
	}
	if pos != len(raw) {
		return c, errors.New("识别码包含多余数据")
	}

	c = signalCode{
		Version:    signalVersion,
		Kind:       expectedKind,
		Token:      base64.RawURLEncoding.EncodeToString(token),
		Candidates: cands,
	}
	if expectedKind == "connect" {
		c.Fingerprint = hex.EncodeToString(fingerprint)
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
