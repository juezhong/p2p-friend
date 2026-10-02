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
		if ep.family == 4 {
			go punchLoop(ctx, p, ep.transport, ep.family)
		}
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
			// Candidate racing can make us accept a connection that the dialer
			// immediately closes because another path won. Keep accepting until
			// a connection actually completes stream establishment.
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
		if ep.family == 4 {
			go punchLoop(ctx, p, ep.transport, ep.family)
		}
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
				// Both sides have already exchanged their full candidate sets.
				// Give globally routable IPv6 a small head start so dual-stack
				// peers normally select IPv6-DIRECT, while IPv4 remains an
				// automatic fallback if IPv6 is filtered or unreachable.
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
