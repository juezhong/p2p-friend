package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const connectionWaitTimeout = 5 * time.Minute

// acceptQUIC 由创建方执行。创建方在每个可用 UDP family 上监听 QUIC，同时仍会
// 主动发送 UDP 探测包，因此“QUIC 监听端”并不等于网络层完全被动。
func (p *rtcPeer) acceptQUIC() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionWaitTimeout)
	defer cancel()

	acceptCh := make(chan *quic.Conn, 8)
	var wg sync.WaitGroup
	started := 0
	for _, ep := range p.endpoints {
		ln, err := ep.transport.Listen(p.serverTLSConfig(), quicConfig())
		if err != nil {
			continue
		}
		ep.listener = ln
		started++
		wg.Add(1)
		go func(ln *quic.Listener) {
			defer wg.Done()
			for {
				qc, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				select {
				case acceptCh <- qc:
				case <-ctx.Done():
					_ = qc.CloseWithError(0, "cancelled")
					return
				}
			}
		}(ln)
		// IPv4 用于 NAT 打洞；IPv6 用同样的双向 UDP 探测打开有状态防火墙。
		go punchLoop(ctx, p, ep.transport, ep.family)
	}
	if started == 0 {
		return nil, errors.New("无法启动 QUIC UDP listener")
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var lastErr error
	for {
		select {
		case qc := <-acceptCh:
			conn, err := establishStreams(qc, p, true)
			if err == nil {
				cancel()
				return conn, nil
			}
			lastErr = err
			_ = qc.CloseWithError(0, "candidate rejected")
			// 多个 candidate 会并行竞争。监听端可能先 Accept 到一条随后被拨号端
			// 放弃的连接（另一条路径已经获胜），因此必须继续 Accept，直到应用
			// control/data stream 也完整建立。
			continue
		case <-done:
			if lastErr != nil {
				return nil, fmt.Errorf("QUIC listener 已停止，候选连接均未完成: %w", lastErr)
			}
			return nil, errors.New("QUIC listener 已停止，未建立连接")
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("%w；最后一次候选错误: %v", connectionTimeoutError(), lastErr)
			}
			return nil, connectionTimeoutError()
		}
	}
}

// dialQUIC 由加入方执行。它会对双方交换得到的所有匹配 candidate 发起并行尝试，
// 但给公网 IPv6 一个短暂优先窗口；IPv6 不通时 IPv4 会自动继续竞争。
func (p *rtcPeer) dialQUIC() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), connectionWaitTimeout)
	defer cancel()

	type target struct {
		ep   *udpEndpoint
		addr *net.UDPAddr
		rank int
	}
	var targets []target
	for _, ep := range p.endpoints {
		// IPv4 用于 NAT 打洞；IPv6 用同样的双向 UDP 探测打开有状态防火墙。
		go punchLoop(ctx, p, ep.transport, ep.family)
		for _, raw := range p.remoteCandidates() {
			addr, family, err := parseCandidate(raw)
			if err != nil || family != ep.family {
				continue
			}
			targets = append(targets, target{ep: ep, addr: addr, rank: candidateRank(raw)})
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("连接码中没有与本机 UDP socket 匹配的候选地址")
	}

	// 长生命周期连接管理器：等待远端真正出现，而不是把一次 candidate
	// 握手失败当成最终结果。远端开始监听后，下一次握手会立即成功返回。
	for {
		if ctx.Err() != nil {
			return nil, connectionTimeoutError()
		}

		result := make(chan *quic.Conn, 1)
		roundCtx, stopRound := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var winOnce sync.Once
		preferGlobalIPv6 := false
		for _, t := range targets {
			if t.rank == 0 {
				preferGlobalIPv6 = true
				break
			}
		}
		for _, t := range targets {
			wg.Add(1)
			go func(t target) {
				defer wg.Done()
				// 此时双方已经完整交换 candidate。公网 IPv6 获得 250ms 优先窗口，
				// 让双栈环境尽量选择 IPv6；IPv6 被过滤或不可达时，IPv4 仍会自动
				// 进入竞争，不需要再次交换识别码。
				if preferGlobalIPv6 && t.rank != 0 {
					select {
					case <-roundCtx.Done():
						return
					case <-time.After(250 * time.Millisecond):
					}
				}
				dialCtx, stop := context.WithTimeout(roundCtx, 6*time.Second)
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
			return establishStreams(qc, p, false)
		case <-ctx.Done():
			stopRound()
			return nil, connectionTimeoutError()
		case <-done:
			stopRound()
			select {
			case <-ctx.Done():
				return nil, connectionTimeoutError()
			case <-time.After(350 * time.Millisecond):
			}
		}
	}
}

func connectionTimeoutError() error {
	return errors.New("P2P UDP/QUIC 连接超时；如果持续失败，可以交换“创建连接 / 加入连接”角色后重试")
}

// punchLoop 只负责 UDP 可达性探测，不承载文件数据，也不替代 QUIC 握手。
// IPv4 侧用于建立/刷新 NAT 映射与过滤状态；IPv6 侧没有 NAT 映射，主要用于
 // 尽量打开 stateful firewall 的返回流量状态。
func punchLoop(ctx context.Context, p *rtcPeer, tr *quic.Transport, family int) {
	payload := append([]byte{0x00}, []byte(punchMagic)...)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		for _, raw := range p.remoteCandidates() {
			addr, fam, err := parseCandidate(raw)
			if err != nil || fam != family {
				continue
			}
			_, _ = tr.WriteTo(payload, addr)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func establishStreams(qc *quic.Conn, p *rtcPeer, opener bool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var control *quic.Stream
	lanes := make([]io.ReadWriteCloser, 0, parallelLanes)
	if opener {
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := st.Write([]byte{0}); err != nil {
			return nil, err
		}
		control = st
		for i := 0; i < parallelLanes; i++ {
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
		got := make(map[byte]*quic.Stream, parallelLanes+1)
		for len(got) < parallelLanes+1 {
			st, err := qc.AcceptStream(ctx)
			if err != nil {
				return nil, err
			}
			var tag [1]byte
			if _, err := io.ReadFull(st, tag[:]); err != nil {
				return nil, err
			}
			if tag[0] > byte(parallelLanes) {
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
		for i := 0; i < parallelLanes; i++ {
			st := got[byte(i+1)]
			if st == nil {
				return nil, fmt.Errorf("QUIC data stream %d missing", i)
			}
			lanes = append(lanes, &quicStreamConn{st})
		}
	}
	return &rtcConn{control: control, lanes: lanes, qc: qc, peer: p}, nil
}
