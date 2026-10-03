package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	connectionWaitTimeout = 5 * time.Minute
	punchClockSkew        = 2 * time.Minute
	punchRetryInterval    = 250 * time.Millisecond
	passivePunchInterval  = 1 * time.Second
	pathPreferenceWindow  = 600 * time.Millisecond
	lanCandidateHeadStart = 150 * time.Millisecond
	lanConnectTimeout     = 3 * time.Second
)

type quicConnectResult struct {
	conn     net.Conn
	err      error
	outbound bool
}

// connectQUIC 是 v14 的默认建链入口。双方都先启动 QUIC listener，再同时对远端
// candidates 拨号。创建方优先保留 inbound，加入方优先保留 outbound，从而在两条
// 方向同时成功时稳定选中同一条 connection；首选方向不可达时短暂等待后使用反向路径。
func (p *rtcPeer) connectQUIC() (net.Conn, error) {
	// HOST prefix 相同只能说明“可能在同一 LAN”，不能证明双方真的共享二层网络。
	// 两个不同 NAT 后面的家庭网络经常同时使用 192.168.1.0/24。
	// 因此所有 candidate 始终保留在竞速中；疑似 LAN HOST 只获得很短的 head start，
	// 真正不可达时公网 IPv6 / portmap / srflx / prflx 会自动接管。
	ctx, cancel := context.WithTimeout(context.Background(), connectionWaitTimeout)
	defer cancel()

	results := make(chan quicConnectResult, 16)
	startedListeners := p.startAcceptWorkers(ctx, results)
	if startedListeners == 0 {
		return nil, errors.New("无法启动 QUIC UDP listener")
	}

	for _, ep := range p.endpoints {
		go punchLoop(ctx, p, ep.transport, ep.family)
		go punchReadLoop(ctx, p, ep.transport, ep.family)
	}
	go func() {
		conn, err := p.dialQUICContext(ctx)
		select {
		case results <- quicConnectResult{conn: conn, err: err, outbound: true}:
		case <-ctx.Done():
			if loser, ok := conn.(*rtcConn); ok {
				_ = loser.closeQUICOnly("connection race canceled")
			} else if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	preferOutbound := !p.server
	var fallback net.Conn
	var fallbackTimer <-chan time.Time
	var lastErr error

	for {
		select {
		case res := <-results:
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if res.conn == nil {
				continue
			}
			preferred := res.outbound == preferOutbound
			if preferred {
				closeRaceLoser(fallback, "preferred path won")
				cancel()
				return res.conn, nil
			}
			if fallback == nil {
				fallback = res.conn
				fallbackTimer = time.After(pathPreferenceWindow)
			} else {
				closeRaceLoser(res.conn, "another path won")
			}
		case <-fallbackTimer:
			if fallback != nil {
				cancel()
				return fallback, nil
			}
		case <-ctx.Done():
			if fallback != nil {
				return fallback, nil
			}
			if lastErr != nil {
				return nil, fmt.Errorf("%w；最后一次候选错误: %v", connectionTimeoutError(), lastErr)
			}
			return nil, connectionTimeoutError()
		}
	}
}

// waitForPeerThenConnect 是加入方打印 REPLY 后的“等待对方准备”状态。
//
// 关键语义：这里没有连接超时。生成/打印 REPLY 不代表创建方已经收到它，
// 所以不能从这个时刻开始计算 LAN/QUIC 失败。加入方只保持 listener 与必要的
// NAT 探测状态；只有真正观察到对端网络活动后，才启动主动 QUIC Dial。
func (p *rtcPeer) waitForPeerThenConnect() (net.Conn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make(chan quicConnectResult, 16)
	if p.startAcceptWorkers(ctx, results) == 0 {
		return nil, errors.New("无法启动 QUIC UDP listener")
	}

	// Prefix overlap 不是 LAN 的可靠证明，因此等待阶段始终保留全部 candidate。
	// 低频 authenticated punch 既能维持 NAT mapping，也能在真实 LAN 上直接触达对端。
	for _, ep := range p.endpoints {
		go punchLoopWithInterval(ctx, p, ep.transport, ep.family, passivePunchInterval)
		go punchReadLoop(ctx, p, ep.transport, ep.family)
	}

	dialStarted := false
	var fastPunchOnce sync.Once
	startDial := func() {
		if dialStarted {
			return
		}
		dialStarted = true
		// 对端已经真实出现后只启动一组高频 punch，避免 Dial 重试时累积 goroutine。
		fastPunchOnce.Do(func() {
			for _, ep := range p.endpoints {
				go punchLoop(ctx, p, ep.transport, ep.family)
			}
		})
		go func() {
			conn, err := p.dialQUICContext(ctx)
			select {
			case results <- quicConnectResult{conn: conn, err: err, outbound: true}:
			case <-ctx.Done():
				closeRaceLoser(conn, "join readiness wait canceled")
			}
		}()
	}

	// 与 connectQUIC 使用同一套方向仲裁。JOIN 偏好 outbound，HOST 偏好 inbound，
	// 因此双方最终会选中同一条 QUIC connection，而不是各自拿到不同 race winner。
	preferOutbound := !p.server
	var fallback net.Conn
	var fallbackTimer <-chan time.Time

	for {
		select {
		case res := <-results:
			if res.err != nil {
				// 只有主动 Dial 自己结束时才能允许后续重新启动。
				if res.outbound {
					dialStarted = false
				}
				continue
			}
			if res.conn == nil {
				continue
			}

			preferred := res.outbound == preferOutbound
			if preferred {
				closeRaceLoser(fallback, "preferred path won")
				cancel()
				return res.conn, nil
			}
			if fallback == nil {
				fallback = res.conn
				fallbackTimer = time.After(pathPreferenceWindow)
			} else {
				closeRaceLoser(res.conn, "another path won")
			}

		case <-fallbackTimer:
			if fallback != nil {
				cancel()
				return fallback, nil
			}

		case <-p.peerActivity:
			// 只有经过 HMAC / nonce / role 校验的 punch 才能触发这里。
			// 这表示创建方已经拿到 REPLY 并真正开始网络建连。
			startDial()

		case <-p.closed:
			closeRaceLoser(fallback, "peer closed")
			return nil, net.ErrClosed
		}
	}
}

// acceptQUIC 保留给测试/兼容调用：只监听，不发起 QUIC Dial，但仍执行安全 punch。
func (p *rtcPeer) acceptQUIC() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionWaitTimeout)
	defer cancel()
	results := make(chan quicConnectResult, 16)
	if p.startAcceptWorkers(ctx, results) == 0 {
		return nil, errors.New("无法启动 QUIC UDP listener")
	}
	for _, ep := range p.endpoints {
		go punchLoop(ctx, p, ep.transport, ep.family)
		go punchReadLoop(ctx, p, ep.transport, ep.family)
	}
	var lastErr error
	for {
		select {
		case res := <-results:
			if res.err == nil && res.conn != nil {
				return res.conn, nil
			}
			if res.err != nil {
				lastErr = res.err
			}
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("%w；最后一次候选错误: %v", connectionTimeoutError(), lastErr)
			}
			return nil, connectionTimeoutError()
		}
	}
}

func (p *rtcPeer) startAcceptWorkers(ctx context.Context, results chan<- quicConnectResult) int {
	started := 0
	for _, ep := range p.endpoints {
		ln, err := ep.transport.Listen(p.serverTLSConfig(), quicConfig())
		if err != nil {
			continue
		}
		ep.listener = ln
		started++
		p.primaryAcceptWG.Add(1)
		go func(ln *quic.Listener) {
			defer p.primaryAcceptWG.Done()
			for {
				qc, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				go func(qc *quic.Conn) {
					conn, err := establishStreams(qc, p, false)
					if err != nil {
						_ = qc.CloseWithError(0, "candidate rejected")
					}
					select {
					case results <- quicConnectResult{conn: conn, err: err, outbound: false}:
					case <-ctx.Done():
						if loser, ok := conn.(*rtcConn); ok {
							_ = loser.closeQUICOnly("connection race canceled")
						} else if conn != nil {
							_ = conn.Close()
						}
					}
				}(qc)
			}
		}(ln)
	}
	return started
}

// dialQUIC 保留为主动连接入口；v14 默认使用 connectQUIC。
func (p *rtcPeer) dialQUIC() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionWaitTimeout)
	defer cancel()
	for _, ep := range p.endpoints {
		go punchLoop(ctx, p, ep.transport, ep.family)
		go punchReadLoop(ctx, p, ep.transport, ep.family)
	}
	return p.dialQUICContext(ctx)
}

// dialQUICContext 每一轮都重新读取 remoteCandidates，因此运行时从安全 punch
// 学到的 prflx endpoint 会立即进入下一轮，而不是像旧实现一样固定初始 targets。
func (p *rtcPeer) dialQUICContext(ctx context.Context) (net.Conn, error) {
	type target struct {
		ep   *udpEndpoint
		addr *net.UDPAddr
		raw  signalCandidate
		key  string
	}

	for {
		if ctx.Err() != nil {
			return nil, connectionTimeoutError()
		}
		var targets []target
		seen := map[string]struct{}{}
		for _, ep := range p.endpoints {
			for _, raw := range p.remoteCandidates() {
				addr, family, err := parseCandidate(raw)
				if err != nil || family != ep.family {
					continue
				}
				key := fmt.Sprintf("%d|%s", family, addr.String())
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				targets = append(targets, target{ep: ep, addr: addr, raw: raw, key: key})
			}
		}
		if len(targets) == 0 {
			select {
			case <-ctx.Done():
				return nil, connectionTimeoutError()
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		result := make(chan *quic.Conn, 1)
		roundCtx, stopRound := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var winOnce sync.Once
		for _, t := range targets {
			wg.Add(1)
			go func(t target) {
				defer wg.Done()
				if delay := candidateDialDelay(t.raw, t.addr); delay > 0 {
					select {
					case <-roundCtx.Done():
						return
					case <-time.After(delay):
					}
				}
				dialCtx, stop := context.WithTimeout(roundCtx, 2*time.Second)
				defer stop()
				qc, err := t.ep.transport.Dial(dialCtx, t.addr, p.clientTLSConfig(), quicConfig())
				if err != nil {
					return
				}
				won := false
				winOnce.Do(func() {
					won = true
					result <- qc
					stopRound()
				})
				if !won {
					_ = qc.CloseWithError(0, "another path won")
				}
			}(t)
		}

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case qc := <-result:
			stopRound()
			conn, err := establishStreams(qc, p, true)
			if err != nil {
				_ = qc.CloseWithError(0, "stream setup failed")
				select {
				case <-ctx.Done():
					return nil, connectionTimeoutError()
				case <-time.After(120 * time.Millisecond):
					continue
				}
			}
			return conn, nil
		case <-ctx.Done():
			stopRound()
			return nil, connectionTimeoutError()
		case <-done:
			stopRound()
			select {
			case <-ctx.Done():
				return nil, connectionTimeoutError()
			case <-time.After(180 * time.Millisecond):
			}
		}
	}
}

func (p *rtcPeer) connectStrictLAN(lan []signalCandidate) (net.Conn, error) {
	full := p.remoteCandidates()
	p.setRemoteCandidates(lan)
	defer p.setRemoteCandidates(full)

	ctx, cancel := context.WithTimeout(context.Background(), lanConnectTimeout)
	defer cancel()
	results := make(chan quicConnectResult, 16)
	if p.startAcceptWorkers(ctx, results) == 0 {
		return nil, errors.New("无法启动 LAN QUIC listener")
	}
	go func() {
		conn, err := p.dialQUICContext(ctx)
		select {
		case results <- quicConnectResult{conn: conn, err: err, outbound: true}:
		case <-ctx.Done():
			closeRaceLoser(conn, "LAN connection canceled")
		}
	}()

	preferOutbound := !p.server
	var fallback net.Conn
	var timer <-chan time.Time
	var lastErr error
	for {
		select {
		case res := <-results:
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if res.conn == nil || !connUsesMutualLAN(res.conn, lan) {
				closeRaceLoser(res.conn, "non-LAN connection rejected")
				continue
			}
			if res.outbound == preferOutbound {
				closeRaceLoser(fallback, "preferred LAN direction won")
				cancel()
				return res.conn, nil
			}
			if fallback == nil {
				fallback = res.conn
				timer = time.After(pathPreferenceWindow)
			} else {
				closeRaceLoser(res.conn, "another LAN direction won")
			}
		case <-timer:
			if fallback != nil {
				cancel()
				return fallback, nil
			}
		case <-ctx.Done():
			if fallback != nil {
				return fallback, nil
			}
			if lastErr != nil {
				return nil, fmt.Errorf("检测到同一局域网，但 LAN QUIC 建连失败: %v", lastErr)
			}
			return nil, errors.New("检测到同一局域网，但 LAN QUIC 建连失败；请检查 AP/VLAN 隔离和本机防火墙")
		}
	}
}

func candidateIPNet(c signalCandidate) (*net.UDPAddr, *net.IPNet, bool) {
	if !strings.EqualFold(c.Type, "host") || !c.PrefixKnown {
		return nil, nil, false
	}
	addr, _, err := parseCandidate(c)
	if err != nil || addr == nil || addr.IP == nil {
		return nil, nil, false
	}
	ip := addr.IP
	bits := 128
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		bits = 32
	}
	if int(c.PrefixBits) > bits {
		return nil, nil, false
	}
	mask := net.CIDRMask(int(c.PrefixBits), bits)
	return addr, &net.IPNet{IP: ip.Mask(mask), Mask: mask}, true
}

func candidatesShareLAN(local, remote signalCandidate) bool {
	la, ln, ok := candidateIPNet(local)
	if !ok {
		return false
	}
	ra, rn, ok := candidateIPNet(remote)
	if !ok || (la.IP.To4() == nil) != (ra.IP.To4() == nil) {
		return false
	}
	return ln.Contains(ra.IP) && rn.Contains(la.IP)
}

func (p *rtcPeer) mutualLANRemoteCandidates() []signalCandidate {
	local := p.localCandidates()
	remote := p.remoteCandidates()
	var out []signalCandidate
	seen := map[string]struct{}{}
	for _, rc := range remote {
		for _, lc := range local {
			if !candidatesShareLAN(lc, rc) {
				continue
			}
			if _, ok := seen[rc.Addr]; !ok {
				seen[rc.Addr] = struct{}{}
				out = append(out, rc)
			}
			break
		}
	}
	sortCandidates(out)
	return out
}

func connUsesMutualLAN(conn net.Conn, lan []signalCandidate) bool {
	rc, ok := conn.(*rtcConn)
	if !ok || rc == nil || rc.qc == nil {
		return false
	}
	remote := rc.qc.RemoteAddr().String()
	for _, cand := range lan {
		if sameUDPAddress(cand.Addr, remote) {
			return true
		}
	}
	return false
}

func isSameSubnetHostCandidate(c signalCandidate, addr *net.UDPAddr) bool {
	return addr != nil && addr.IP != nil &&
		strings.EqualFold(c.Type, "host") && isSameSubnetIP(addr.IP)
}

func (p *rtcPeer) hasSameSubnetHostCandidate() bool {
	return len(p.mutualLANRemoteCandidates()) > 0
}

func connUsesSameSubnet(conn net.Conn) bool {
	rc, ok := conn.(*rtcConn)
	if !ok || rc == nil || rc.qc == nil {
		return false
	}
	addr, ok := rc.qc.RemoteAddr().(*net.UDPAddr)
	return ok && addr != nil && addr.IP != nil && isSameSubnetIP(addr.IP)
}

func closeRaceLoser(conn net.Conn, reason string) {
	if conn == nil {
		return
	}
	if loser, ok := conn.(*rtcConn); ok {
		_ = loser.closeQUICOnly(reason)
		return
	}
	_ = conn.Close()
}

func connectionTimeoutError() error {
	return errors.New("P2P UDP/QUIC 连接超时；当前网络的 NAT/防火墙没有形成可用直连路径")
}

// candidateDialDelay 给“疑似同网段 HOST”一个很短的 head start，但绝不把它
// 当作已确认 LAN。RFC1918 网段会在不同 NAT 后重复，所以公网/NAT candidate
// 仍会在短延迟后并发启动，避免 192.168.1.0/24 之类的重叠私网误判卡死连接。
func candidateDialDelay(c signalCandidate, addr *net.UDPAddr) time.Duration {
	if isSameSubnetHostCandidate(c, addr) {
		return 0
	}
	return lanCandidateHeadStart
}

func isSameSubnetIP(remote net.IP) bool {
	if remote == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	var localNets []*net.IPNet
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			ipNet, ok := raw.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.Mask == nil {
				continue
			}
			localNets = append(localNets, ipNet)
		}
	}
	return ipInSameSubnet(remote, localNets)
}

func ipInSameSubnet(remote net.IP, localNets []*net.IPNet) bool {
	if remote == nil {
		return false
	}
	for _, ipNet := range localNets {
		if ipNet == nil || ipNet.IP == nil || ipNet.Mask == nil {
			continue
		}
		if (remote.To4() == nil) != (ipNet.IP.To4() == nil) {
			continue
		}
		if ipNet.Contains(remote) {
			return true
		}
	}
	return false
}

// punch packet:
// 0x00 | magic | role(1) | unixSeconds(8) | nonce(8) | HMAC-SHA256[:16]
// HMAC key 是本次 INVITE/REPLY 的 256-bit session token。
func buildPunchPacket(p *rtcPeer) ([]byte, error) {
	if len(p.token) != 32 {
		return nil, errors.New("invalid punch token")
	}
	role := roleJoin
	if p.server {
		role = roleHost
	}
	prefixLen := 1 + len(punchMagic) + 1 + 8 + 8
	buf := make([]byte, prefixLen+16)
	buf[0] = 0
	copy(buf[1:], punchMagic)
	pos := 1 + len(punchMagic)
	buf[pos] = role
	pos++
	binary.BigEndian.PutUint64(buf[pos:pos+8], uint64(time.Now().Unix()))
	pos += 8
	if _, err := rand.Read(buf[pos : pos+8]); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, p.token)
	_, _ = mac.Write(buf[:prefixLen])
	copy(buf[prefixLen:], mac.Sum(nil)[:16])
	return buf, nil
}

func (p *rtcPeer) verifyPunchPacket(buf []byte) bool {
	prefixLen := 1 + len(punchMagic) + 1 + 8 + 8
	if len(buf) != prefixLen+16 || buf[0] != 0 || string(buf[1:1+len(punchMagic)]) != punchMagic {
		return false
	}
	if len(p.token) != 32 {
		return false
	}
	pos := 1 + len(punchMagic)
	remoteRole := buf[pos]
	localRole := roleJoin
	if p.server {
		localRole = roleHost
	}
	if (remoteRole != roleHost && remoteRole != roleJoin) || remoteRole == localRole {
		return false
	}
	pos++
	ts := int64(binary.BigEndian.Uint64(buf[pos : pos+8]))
	now := time.Now()
	when := time.Unix(ts, 0)
	if when.Before(now.Add(-punchClockSkew)) || when.After(now.Add(punchClockSkew)) {
		return false
	}
	pos += 8
	var nonce [8]byte
	copy(nonce[:], buf[pos:pos+8])

	mac := hmac.New(sha256.New, p.token)
	_, _ = mac.Write(buf[:prefixLen])
	if !hmac.Equal(buf[prefixLen:], mac.Sum(nil)[:16]) {
		return false
	}

	p.punchSeenMu.Lock()
	defer p.punchSeenMu.Unlock()
	if p.punchSeen == nil {
		p.punchSeen = make(map[[8]byte]time.Time)
	}
	for n, expiry := range p.punchSeen {
		if now.After(expiry) {
			delete(p.punchSeen, n)
		}
	}
	if _, replay := p.punchSeen[nonce]; replay {
		return false
	}
	p.punchSeen[nonce] = now.Add(punchClockSkew)
	return true
}

// punchLoop 负责持续建立/刷新 NAT 和 stateful firewall 状态，不承载文件数据。
func punchLoop(ctx context.Context, p *rtcPeer, tr *quic.Transport, family int) {
	punchLoopWithInterval(ctx, p, tr, family, punchRetryInterval)
}

func punchLoopWithInterval(ctx context.Context, p *rtcPeer, tr *quic.Transport, family int, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		payload, err := buildPunchPacket(p)
		if err == nil {
			for _, raw := range p.remoteCandidates() {
				addr, fam, err := parseCandidate(raw)
				if err != nil || fam != family {
					continue
				}
				_, _ = tr.WriteTo(payload, addr)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// punchReadLoop 读取 quic-go 从同一 UDP socket 分流出的非 QUIC 包。
// 只有通过 token/HMAC、角色、时间窗、nonce 重放检查的 probe 才能生成 prflx candidate。
func punchReadLoop(ctx context.Context, p *rtcPeer, tr *quic.Transport, family int) {
	buf := make([]byte, 512)
	for {
		n, addr, err := tr.ReadNonQUICPacket(ctx, buf)
		if err != nil {
			return
		}
		if !p.verifyPunchPacket(buf[:n]) {
			continue
		}
		p.signalPeerActivity()
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || udpAddr == nil || udpAddr.IP == nil || udpAddr.IP.IsUnspecified() || udpAddr.IP.IsLoopback() {
			continue
		}
		if family == 4 && udpAddr.IP.To4() == nil {
			continue
		}
		if family == 6 && udpAddr.IP.To4() != nil {
			continue
		}
		cand := signalCandidate{Addr: udpAddr.String(), Type: "prflx"}
		if p.addRemoteCandidate(cand) {
			// 立即向观察到的真实 endpoint 回探测，加快双方建立对称状态。
			if reply, err := buildPunchPacket(p); err == nil {
				_, _ = tr.WriteTo(reply, udpAddr)
			}
		}
	}
}

func establishStreams(qc *quic.Conn, p *rtcPeer, opener bool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var control *quic.Stream
	lanes := make([]io.ReadWriteCloser, 0, primaryDataStreams)
	if opener {
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := st.Write([]byte{0}); err != nil {
			return nil, err
		}
		control = st
		for i := 0; i < primaryDataStreams; i++ {
			lane, err := qc.OpenStreamSync(ctx)
			if err != nil {
				return nil, err
			}
			if _, err := lane.Write([]byte{byte(i + 1)}); err != nil {
				return nil, err
			}
			lanes = append(lanes, &quicStreamConn{lane})
		}
	} else {
		got := make(map[byte]*quic.Stream, primaryDataStreams+1)
		for len(got) < primaryDataStreams+1 {
			st, err := qc.AcceptStream(ctx)
			if err != nil {
				return nil, err
			}
			var tag [1]byte
			if _, err := io.ReadFull(st, tag[:]); err != nil {
				return nil, err
			}
			if tag[0] > byte(primaryDataStreams) {
				_ = st.Close()
				continue
			}
			if old := got[tag[0]]; old != nil {
				_ = st.Close()
				continue
			}
			got[tag[0]] = st
		}
		control = got[0]
		if control == nil {
			return nil, errors.New("QUIC control stream missing")
		}
		for i := 0; i < primaryDataStreams; i++ {
			st := got[byte(i+1)]
			if st == nil {
				return nil, fmt.Errorf("QUIC data stream %d missing", i)
			}
			lanes = append(lanes, &quicStreamConn{st})
		}
	}
	return &rtcConn{control: control, lanes: lanes, qc: qc, peer: p, outbound: opener}, nil
}
