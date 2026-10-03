package main

import (
	"bufio"
	"context"
	"bytes"
	"crypto/rand"
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

// newPeer 为 IPv4/IPv6 各打开一个 UDP socket。STUN、端口映射、punch、QUIC
// 握手和文件传输尽量复用同一个本地 UDP 端口，避免 NAT 映射在建链过程中变化。
func newPeer(server bool) (*rtcPeer, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	cert, der, err := generateQUICCertificate()
	if err != nil {
		return nil, err
	}
	p := &rtcPeer{token: token, server: server, cert: cert}
	sum := sha256.Sum256(der)
	p.localFingerprint = append([]byte(nil), sum[:]...)
	if server {
		// 保留旧测试辅助路径的语义。
		p.fingerprint = append([]byte(nil), sum[:]...)
	}
	if _, err := rand.Read(p.punchNonce[:]); err != nil {
		return nil, err
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
		p.cleanupMu.Lock()
		cleanups := append([]func(){}, p.cleanups...)
		p.cleanups = nil
		p.cleanupMu.Unlock()
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
		for _, ep := range p.endpoints {
			if ep.listener != nil {
				_ = ep.listener.Close()
			}
			if ep.transport != nil {
				if err := ep.transport.Close(); err != nil && !errors.Is(err, net.ErrClosed) && first == nil {
					first = err
				}
			}
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
	cands := gatherCandidates(p)
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
		Fingerprint: hex.EncodeToString(p.localFingerprint),
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
	p.token = append([]byte(nil), token...)
	p.remoteFingerprint = append([]byte(nil), fp...)
	p.fingerprint = append([]byte(nil), fp...)
	p.setRemoteCandidates(code.Candidates)

	cands := gatherCandidates(p)
	p.setLocalCandidates(cands)
	if len(cands) == 0 {
		_ = p.Close()
		return nil, "", nil, errors.New("没有可用 UDP candidate")
	}
	confirm, err := encodeSignal(signalCode{
		Version:     signalVersion,
		Kind:        "confirm",
		Token:       code.Token,
		Candidates:  cands,
		Fingerprint: hex.EncodeToString(p.localFingerprint),
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
	fp, err := hex.DecodeString(code.Fingerprint)
	if err != nil || len(fp) != 32 {
		return errors.New("回传码中的 QUIC 证书指纹无效")
	}
	p.remoteFingerprint = append([]byte(nil), fp...)
	p.setRemoteCandidates(code.Candidates)
	return nil
}

func (p *rtcPeer) waitConn() (net.Conn, error) { return p.connectQUIC() }

const candidateGatherBudget = 1500 * time.Millisecond

type candidateGatherResult struct {
	mapped  []*net.UDPAddr
	cand    signalCandidate
	cleanup func()
	method  string
}

// gatherCandidates 先立即收集本机 host candidate，再把 Multi-STUN 与端口映射并行执行。
// 所有“增强候选”共享统一时间预算，避免某个不支持 PCP/NAT-PMP/UPnP 的路由器
// 或不可达 STUN server 串行拖慢邀请码 / 回传码生成。
func gatherCandidates(p *rtcPeer) []signalCandidate {
	set := map[string]signalCandidate{}
	ifaces, _ := net.Interfaces()
	var ipv4Endpoint *udpEndpoint

	for _, ep := range p.endpoints {
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
			ipv4Endpoint = ep
		}
	}

	behavior := "unknown"
	var observations, mappings []string
	if ipv4Endpoint != nil {
		ctx, cancel := context.WithTimeout(context.Background(), candidateGatherBudget)
		defer cancel()

		results := make(chan candidateGatherResult, 2)
		go func() {
			results <- candidateGatherResult{mapped: stunMappedAddressesContext(ctx, ipv4Endpoint.conn)}
		}()
		go func() {
			cand, cleanup, method, err := discoverPortMappingContext(ctx, ipv4Endpoint)
			if err != nil {
				results <- candidateGatherResult{}
				return
			}
			select {
			case results <- candidateGatherResult{cand: cand, cleanup: cleanup, method: method}:
			case <-ctx.Done():
				if cleanup != nil {
					cleanup()
				}
			}
		}()

		for received := 0; received < 2; {
			select {
			case result := <-results:
				received++
				if len(result.mapped) > 0 {
					unique := map[string]struct{}{}
					for _, a := range result.mapped {
						s := a.String()
						unique[s] = struct{}{}
						observations = append(observations, s)
						set["srflx|"+s] = signalCandidate{Addr: s, Type: "srflx"}
					}
					if len(unique) == 1 {
						behavior = "stable"
					} else {
						behavior = "endpoint-dependent"
					}
				}
				if result.cand.Addr != "" {
					set["portmap|"+result.cand.Addr] = result.cand
					mappings = append(mappings, result.method+" "+result.cand.Addr)
					p.addCleanup(result.cleanup)
				}
			case <-ctx.Done():
				received = 2
			}
		}
	}

	out := make([]signalCandidate, 0, len(set))
	for _, c := range set {
		out = append(out, c)
	}
	sortCandidates(out)
	p.setNetworkInfo(behavior, observations, mappings)
	return out
}

func sortCandidates(out []signalCandidate) {
	sort.Slice(out, func(i, j int) bool {
		ri := candidateRank(out[i])
		rj := candidateRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].Addr < out[j].Addr
	})
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
	if strings.EqualFold(c.Type, "portmap") {
		return 1
	}
	// 同一个公网 endpoint 同时以 host/srflx 出现时，host 代表无需 NAT 映射的
	// 直接可达地址，应优先于反射/运行时发现候选。
	if ip.To4() != nil && !ip.IsPrivate() && strings.EqualFold(c.Type, "host") {
		return 2
	}
	switch strings.ToLower(c.Type) {
	case "prflx":
		return 3
	case "srflx":
		return 4
	}
	if ip.To4() == nil {
		return 5
	}
	return 6
}

// stunMappedAddressesContext 会先并行发出多个 STUN Binding Request，再在同一 UDP
// socket 上用 transaction ID 分流响应。总耗时由 ctx 控制，不再按 server 串行叠加超时。
func stunMappedAddressesContext(ctx context.Context, conn *net.UDPConn) []*net.UDPAddr {
	servers := []string{
		"stun.cloudflare.com:3478",
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
	}
	type transactionID [stun.TransactionIDSize]byte
	pending := make(map[transactionID]struct{})

	for _, server := range servers {
		addr, err := resolveUDP4Context(ctx, server)
		if err != nil {
			continue
		}
		req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		var id transactionID
		copy(id[:], req.TransactionID[:])
		if _, err := conn.WriteToUDP(req.Raw, addr); err != nil {
			continue
		}
		pending[id] = struct{}{}
	}
	if len(pending) == 0 {
		return nil
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(candidateGatherBudget)
	}
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})

	var out []*net.UDPAddr
	seen := map[string]struct{}{}
	buf := make([]byte, 2048)
	for len(pending) > 0 {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		res := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := res.Decode(); err != nil {
			continue
		}
		var id transactionID
		copy(id[:], res.TransactionID[:])
		if _, ok := pending[id]; !ok {
			continue
		}
		delete(pending, id)

		var xor stun.XORMappedAddress
		if err := xor.GetFrom(res); err != nil {
			continue
		}
		mapped := &net.UDPAddr{IP: xor.IP, Port: xor.Port}
		if _, ok := seen[mapped.String()]; !ok {
			seen[mapped.String()] = struct{}{}
			out = append(out, mapped)
		}
	}
	return out
}

func resolveUDP4Context(ctx context.Context, server string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("STUN DNS lookup failed")
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

func stunMappedAddresses(conn *net.UDPConn) []*net.UDPAddr {
	ctx, cancel := context.WithTimeout(context.Background(), candidateGatherBudget)
	defer cancel()
	return stunMappedAddressesContext(ctx, conn)
}

func stunMappedAddress(conn *net.UDPConn) (*net.UDPAddr, error) {
	addrs := stunMappedAddresses(conn)
	if len(addrs) == 0 {
		return nil, errors.New("STUN failed")
	}
	return addrs[0], nil
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
		if typ != "host" && typ != "srflx" && typ != "portmap" {
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
		if prev, ok := byAddr[key]; ok && candidateRank(prev) <= candidateRank(normalized) {
			continue
		}
		byAddr[key] = normalized
	}
	out := make([]signalCandidate, 0, len(byAddr))
	for _, cand := range byAddr {
		out = append(out, cand)
	}
	sortCandidates(out)
	if len(out) > maxSignalCandidates {
		out = out[:maxSignalCandidates]
	}
	if len(out) == 0 {
		return nil, errors.New("没有可编码的 UDP candidate")
	}
	return out, nil
}

// v12 的 INVITE 和 REPLY 都携带本端临时证书指纹，使双方都能安全地充当 QUIC server。
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
	fingerprint, err := hex.DecodeString(c.Fingerprint)
	if err != nil || len(fingerprint) != 32 {
		return "", errors.New("证书指纹必须是 SHA-256")
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
	buf.Write(fingerprint)
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
		switch strings.ToLower(cand.Type) {
		case "srflx":
			flags |= 0x02
		case "portmap":
			flags |= 0x04
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
			return c, errors.New("这是 P2PF-INVITE 邀请码；当前创建方需要 P2PF-REPLY 回传码")
		case strings.HasPrefix(s, signalReplyPrefix) && expectedKind == "connect":
			return c, errors.New("这是 P2PF-REPLY 回传码；加入连接需要 P2PF-INVITE 邀请码")
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
	if len(raw) < 2+32+32 {
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
	token := append([]byte(nil), raw[pos:pos+32]...)
	pos += 32
	fingerprint := append([]byte(nil), raw[pos:pos+32]...)
	pos += 32

	cands := make([]signalCandidate, 0, count)
	for i := 0; i < count; i++ {
		if len(raw) < pos+3 {
			return c, errors.New("识别码 candidate 数据不完整")
		}
		flags := raw[pos]
		pos++
		if flags&^byte(0x07) != 0 || flags&0x06 == 0x06 {
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
		switch flags & 0x06 {
		case 0x02:
			typ = "srflx"
		case 0x04:
			typ = "portmap"
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
		Version:     signalVersion,
		Kind:        expectedKind,
		Token:       base64.RawURLEncoding.EncodeToString(token),
		Candidates:  cands,
		Fingerprint: hex.EncodeToString(fingerprint),
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
