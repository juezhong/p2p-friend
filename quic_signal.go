package main

import (
	"bufio"
	"context"
	"bytes"
	"crypto/hmac"
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
	p := &rtcPeer{
		token:        token,
		server:       server,
		cert:         cert,
		peerActivity: make(chan struct{}, 1),
		closed:       make(chan struct{}),
	}
	p.setLocalCapabilities(signalCapabilitiesCurrent)
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
		if p.closed != nil {
			close(p.closed)
		}
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
		Version:     signalEnvelopeVersion,
		Kind:        "connect",
		Token:       base64.RawURLEncoding.EncodeToString(p.token),
		Candidates:  cands,
		Capabilities: signalCapabilitiesCurrent,
		Fingerprint:  hex.EncodeToString(p.localFingerprint),
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
	p.setRemoteCapabilities(code.Capabilities)

	cands := gatherCandidates(p)
	p.setLocalCandidates(cands)
	if len(cands) == 0 {
		_ = p.Close()
		return nil, "", nil, errors.New("没有可用 UDP candidate")
	}
	binding := makeSignalBinding(token)
	confirm, err := encodeSignal(signalCode{
		Version:        signalEnvelopeVersion,
		Capabilities:   signalCapabilitiesCurrent,
		Kind:           "confirm",
		SessionBinding: base64.RawURLEncoding.EncodeToString(binding),
		Candidates:     cands,
		Fingerprint:    hex.EncodeToString(p.localFingerprint),
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
	binding, err := base64.RawURLEncoding.DecodeString(code.SessionBinding)
	if err != nil || !equalBytes(binding, makeSignalBinding(p.token)) {
		return errors.New("确认码与当前连接不匹配")
	}
	fp, err := hex.DecodeString(code.Fingerprint)
	if err != nil || len(fp) != 32 {
		return errors.New("回传码中的 QUIC 证书指纹无效")
	}
	p.remoteFingerprint = append([]byte(nil), fp...)
	p.setRemoteCandidates(code.Candidates)
	p.setRemoteCapabilities(code.Capabilities)
	return nil
}

func (p *rtcPeer) waitConn() (net.Conn, error) { return p.waitForPeerThenConnect() }

const (
	candidateGatherBudget = 1200 * time.Millisecond
	candidateGatherGrace  = 180 * time.Millisecond
	stunSecondProbeGrace  = 220 * time.Millisecond
)

type candidateGatherResult struct {
	mapped        []*net.UDPAddr
	stunResponses int
	cand          signalCandidate
	cleanup       func()
	method        string
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
				var prefixBits uint8
				var prefixKnown bool
				switch v := raw.(type) {
				case *net.IPNet:
					ip = v.IP
					if ones, bits := v.Mask.Size(); ones >= 0 && (bits == 32 || bits == 128) {
						prefixBits = uint8(ones)
						prefixKnown = true
					}
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
				set["host|"+addr] = signalCandidate{Addr: addr, Type: "host", PrefixBits: prefixBits, PrefixKnown: prefixKnown}
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
			obs := stunMappingObservationsContext(ctx, ipv4Endpoint.conn)
			results <- candidateGatherResult{mapped: obs.mapped, stunResponses: obs.responses}
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

		var softTimer *time.Timer
		var softC <-chan time.Time
		resetSoft := func(d time.Duration) {
			if softTimer == nil {
				softTimer = time.NewTimer(d)
			} else {
				if !softTimer.Stop() {
					select {
					case <-softTimer.C:
					default:
					}
				}
				softTimer.Reset(d)
			}
			softC = softTimer.C
		}
		defer func() {
			if softTimer != nil {
				softTimer.Stop()
			}
		}()

		for received := 0; received < 2; {
			select {
			case result := <-results:
				received++
				useful := false
				if len(result.mapped) > 0 {
					useful = true
					unique := map[string]struct{}{}
					for _, a := range result.mapped {
						s := a.String()
						unique[s] = struct{}{}
						observations = append(observations, s)
						set["srflx|"+s] = signalCandidate{Addr: s, Type: "srflx"}
					}
					switch {
					case result.stunResponses >= 2 && len(unique) == 1:
						behavior = "stable"
					case result.stunResponses >= 2 && len(unique) > 1:
						behavior = "endpoint-dependent"
					default:
						behavior = "single-observation"
					}
				}
				if result.cand.Addr != "" {
					useful = true
					set["portmap|"+result.cand.Addr] = result.cand
					mappings = append(mappings, result.method+" "+result.cand.Addr)
					p.addCleanup(result.cleanup)
				}
				if received >= 2 {
					break
				}
				if useful {
					grace := candidateGatherGrace
					if behavior == "endpoint-dependent" && result.cand.Addr == "" {
						// STUN 已表明映射依赖目标时，显式 port mapping 的价值更高，
						// 多给一点机会，但仍受 1.2s hard deadline 限制。
						grace = 420 * time.Millisecond
					}
					resetSoft(grace)
				}
			case <-softC:
				received = 2
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

type stunMappingObservation struct {
	mapped    []*net.UDPAddr
	responses int
}

// stunMappingObservationsContext 会先并行发出多个 STUN Binding Request，再在同一 UDP
// socket 上用 transaction ID 分流响应。两个有效响应已经足够比较 mapping behavior；
// 若只有一个响应，则只再等一个很短的 grace，不为了第三个 STUN 把邀请码拖到 hard deadline。
func stunMappingObservationsContext(ctx context.Context, conn *net.UDPConn) stunMappingObservation {
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
		return stunMappingObservation{}
	}

	hardDeadline, ok := ctx.Deadline()
	if !ok {
		hardDeadline = time.Now().Add(candidateGatherBudget)
	}
	readDeadline := hardDeadline
	_ = conn.SetReadDeadline(readDeadline)
	defer conn.SetReadDeadline(time.Time{})

	var out []*net.UDPAddr
	responses := 0
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
		responses++
		mapped := &net.UDPAddr{IP: xor.IP, Port: xor.Port}
		if _, ok := seen[mapped.String()]; !ok {
			seen[mapped.String()] = struct{}{}
			out = append(out, mapped)
		}
		if responses >= 2 {
			break
		}
		// 第一个有效结果已经提供可用 srflx；只短等第二个结果用于 behavior 对比。
		shortDeadline := time.Now().Add(stunSecondProbeGrace)
		if shortDeadline.Before(hardDeadline) {
			readDeadline = shortDeadline
			_ = conn.SetReadDeadline(readDeadline)
		}
	}
	return stunMappingObservation{mapped: out, responses: responses}
}

func stunMappedAddressesContext(ctx context.Context, conn *net.UDPConn) []*net.UDPAddr {
	return stunMappingObservationsContext(ctx, conn).mapped
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
		if typ == "host" && cand.PrefixKnown {
			maxBits := uint8(128)
			if ip.To4() != nil {
				maxBits = 32
			}
			if cand.PrefixBits <= maxBits {
				normalized.PrefixKnown = true
				normalized.PrefixBits = cand.PrefixBits
			}
		}
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

// v0.15 起识别码使用稳定 binary envelope。产品版本号不再进入识别码。
// envelope version 只描述这个长期格式本身；兼容功能通过 capability bitmap 协商。
//
// Layout:
//   version(1) | kind(1) | capabilities(uvarint) | candidate-count(1)
//   INVITE: token(32)
//   REPLY:  session-binding(16)
//   fingerprint(32)
//   candidates...
//
// candidate:
//   flags(1) | port(2) | [prefix-bits(1)] | raw-ip(4/16)
//
// 这比 protobuf 对当前固定小字段更紧凑，同时保留 capability 扩展点。
func encodeSignal(c signalCode) (string, error) {
	prefix, err := signalPrefixForKind(c.Kind)
	if err != nil {
		return "", err
	}
	if c.Version != signalEnvelopeVersion {
		return "", fmt.Errorf("unsupported signal envelope %d", c.Version)
	}
	fingerprint, err := hex.DecodeString(c.Fingerprint)
	if err != nil || len(fingerprint) != 32 {
		return "", errors.New("证书指纹必须是 SHA-256")
	}
	cands, err := normalizeSignalCandidates(c.Candidates)
	if err != nil {
		return "", err
	}

	kind := byte(0)
	switch c.Kind {
	case "connect":
		kind = 1
	case "confirm":
		kind = 2
	}
	var identity []byte
	if kind == 1 {
		identity, err = base64.RawURLEncoding.DecodeString(c.Token)
		if err != nil || len(identity) != 32 {
			return "", errors.New("邀请码 token 必须是 256-bit")
		}
	} else {
		identity, err = base64.RawURLEncoding.DecodeString(c.SessionBinding)
		if err != nil || len(identity) != 16 {
			return "", errors.New("回传码 session binding 无效")
		}
	}

	var buf bytes.Buffer
	buf.Grow(4 + len(identity) + len(fingerprint) + len(cands)*20)
	buf.WriteByte(byte(signalEnvelopeVersion))
	buf.WriteByte(kind)
	var varint [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varint[:], c.Capabilities)
	buf.Write(varint[:n])
	buf.WriteByte(byte(len(cands)))
	buf.Write(identity)
	buf.Write(fingerprint)

	for _, cand := range cands {
		addr, err := net.ResolveUDPAddr("udp", cand.Addr)
		if err != nil {
			return "", err
		}
		var rec bytes.Buffer
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
		if cand.Type == "host" && cand.PrefixKnown {
			flags |= 0x08
		}
		rec.WriteByte(flags)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(addr.Port))
		rec.Write(port[:])
		if flags&0x08 != 0 {
			rec.WriteByte(cand.PrefixBits)
		}
		rec.Write(ip)

		n := binary.PutUvarint(varint[:], uint64(rec.Len()))
		buf.Write(varint[:n])
		buf.Write(rec.Bytes())
	}
	// 顶层 extension area：未来新增可选字段时旧程序可以整体跳过，不必更换邀请码格式。
	n = binary.PutUvarint(varint[:], 0)
	buf.Write(varint[:n])
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
	if len(raw) < 4 {
		return c, errors.New("识别码数据过短")
	}
	if int(raw[0]) != signalEnvelopeVersion {
		return c, fmt.Errorf("识别码 envelope 不兼容：收到 %d，需要 %d", raw[0], signalEnvelopeVersion)
	}
	wantKind := byte(1)
	if expectedKind == "confirm" {
		wantKind = 2
	}
	if raw[1] != wantKind {
		return c, errors.New("识别码 kind 与前缀不一致")
	}
	pos := 2
	caps, n := binary.Uvarint(raw[pos:])
	if n <= 0 {
		return c, errors.New("识别码 capability 数据无效")
	}
	pos += n
	if len(raw) <= pos {
		return c, errors.New("识别码 candidate 数量缺失")
	}
	count := int(raw[pos])
	pos++
	if count <= 0 || count > maxSignalCandidates {
		return c, errors.New("识别码 candidate 数量无效")
	}

	identityLen := 32
	if expectedKind == "confirm" {
		identityLen = 16
	}
	if len(raw) < pos+identityLen+32 {
		return c, errors.New("识别码身份数据不完整")
	}
	identity := append([]byte(nil), raw[pos:pos+identityLen]...)
	pos += identityLen
	fingerprint := append([]byte(nil), raw[pos:pos+32]...)
	pos += 32

	cands := make([]signalCandidate, 0, count)
	for i := 0; i < count; i++ {
		recLen, n := binary.Uvarint(raw[pos:])
		if n <= 0 {
			return c, errors.New("识别码 candidate 长度无效")
		}
		pos += n
		if recLen == 0 || recLen > uint64(len(raw)-pos) {
			return c, errors.New("识别码 candidate 数据不完整")
		}
		recEnd := pos + int(recLen)
		if recEnd-pos < 3 {
			return c, errors.New("识别码 candidate 数据过短")
		}
		flags := raw[pos]
		pos++
		if flags&^byte(0x0f) != 0 || flags&0x06 == 0x06 {
			return c, errors.New("识别码 candidate flags 无效")
		}
		port := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		pos += 2
		if port == 0 {
			return c, errors.New("识别码 candidate 端口无效")
		}
		prefixKnown := flags&0x08 != 0
		var prefixBits uint8
		if prefixKnown {
			if recEnd <= pos {
				return c, errors.New("识别码 candidate prefix 不完整")
			}
			prefixBits = raw[pos]
			pos++
		}
		ipLen := 4
		maxPrefix := uint8(32)
		if flags&0x01 != 0 {
			ipLen = 16
			maxPrefix = 128
		}
		if prefixKnown && prefixBits > maxPrefix {
			return c, errors.New("识别码 candidate prefix 无效")
		}
		if recEnd < pos+ipLen {
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
		if typ != "host" && prefixKnown {
			return c, errors.New("只有 HOST candidate 可以携带 prefix")
		}
		cands = append(cands, signalCandidate{
			Addr:        net.JoinHostPort(ip.String(), fmt.Sprint(port)),
			Type:        typ,
			PrefixBits:  prefixBits,
			PrefixKnown: prefixKnown,
		})
		// recEnd 之后的 candidate 扩展字段由旧实现直接跳过。
		pos = recEnd
	}
	extLen, n := binary.Uvarint(raw[pos:])
	if n <= 0 {
		return c, errors.New("识别码 extension 长度无效")
	}
	pos += n
	if extLen > uint64(len(raw)-pos) {
		return c, errors.New("识别码 extension 数据不完整")
	}
	pos += int(extLen)
	if pos != len(raw) {
		return c, errors.New("识别码包含多余数据")
	}

	c = signalCode{
		Version:      signalEnvelopeVersion,
		Capabilities: caps,
		Kind:         expectedKind,
		Candidates:   cands,
		Fingerprint:  hex.EncodeToString(fingerprint),
	}
	if expectedKind == "connect" {
		c.Token = base64.RawURLEncoding.EncodeToString(identity)
	} else {
		c.SessionBinding = base64.RawURLEncoding.EncodeToString(identity)
	}
	return c, nil
}

func makeSignalBinding(token []byte) []byte {
	mac := hmac.New(sha256.New, token)
	_, _ = mac.Write([]byte("p2p-friend/reply-binding"))
	sum := mac.Sum(nil)
	return append([]byte(nil), sum[:16]...)
}

func readSignalLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
