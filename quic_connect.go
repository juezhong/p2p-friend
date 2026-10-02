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

func (p *rtcPeer) acceptQUIC() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	acceptCh := make(chan *quic.Conn, 1)
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
			qc, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			select {
			case acceptCh <- qc:
			case <-ctx.Done():
				_ = qc.CloseWithError(0, "cancelled")
			}
		}(ln)
		go punchLoop(ctx, ep.transport, p.remote, ep.family)
	}
	if started == 0 {
		return nil, errors.New("无法启动 QUIC UDP listener")
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case qc := <-acceptCh:
		cancel()
		return establishStreams(qc, p, true)
	case <-done:
		return nil, errors.New("所有 QUIC listener 均已停止，未建立连接")
	case <-ctx.Done():
		return nil, errors.New("QUIC/UDP 连接超时：IPv6 直连和 IPv4 UDP 打洞均未建立")
	}
}

func (p *rtcPeer) dialQUIC() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	result := make(chan *quic.Conn, 1)
	var wg sync.WaitGroup
	attempts := 0
	for _, ep := range p.endpoints {
		go punchLoop(ctx, ep.transport, p.remote, ep.family)
		for _, raw := range p.remote {
			addr, family, err := parseCandidate(raw)
			if err != nil || family != ep.family {
				continue
			}
			attempts++
			wg.Add(1)
			go func(ep *udpEndpoint, addr *net.UDPAddr) {
				defer wg.Done()
				dialCtx, stop := context.WithTimeout(ctx, 12*time.Second)
				defer stop()
				qc, err := ep.transport.Dial(dialCtx, addr, p.clientTLSConfig(), quicConfig())
				if err != nil {
					return
				}
				select {
				case result <- qc:
				case <-ctx.Done():
					_ = qc.CloseWithError(0, "another path won")
				}
			}(ep, addr)
		}
	}
	if attempts == 0 {
		return nil, errors.New("连接码中没有与本机 UDP socket 匹配的 candidate")
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case qc := <-result:
		cancel()
		return establishStreams(qc, p, false)
	case <-done:
		return nil, errors.New("所有 QUIC candidate 均连接失败")
	case <-ctx.Done():
		return nil, errors.New("QUIC/UDP 连接超时：IPv6 直连和 IPv4 UDP 打洞均未建立")
	}
}

func punchLoop(ctx context.Context, tr *quic.Transport, candidates []string, family int) {
	payload := append([]byte{0x00}, []byte(punchMagic)...)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for i := 0; i < 16; i++ {
		for _, raw := range candidates {
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
