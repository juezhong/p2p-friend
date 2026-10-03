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

const (
	dataStripeTag       = byte(0xF0)
	dataStripeSetupWait = 3 * time.Second
)

// setupDataStripes 在主 QUIC 完成 TLS + 应用 token 认证后扩展额外 data-only
// QUIC connections。v0.14.1 的主动端优先给每条 stripe 分配独立 UDP source port，
// 形成真正不同的 UDP 5-tuple；目标 endpoint 仍复用主连接已经验证可达的地址。
// 额外 stripe 不需要重新做 STUN / punch，失败时只退化为更少的 data connection。
//
// 主连接的 dialer 负责创建额外连接，主连接的 listener 负责接受。这样双方
// 对“谁拨号”有完全一致的判断，不需要再做一次角色协商。
func setupDataStripes(conn net.Conn, token []byte) int {
	rc, ok := conn.(*rtcConn)
	if !ok || len(token) != 32 {
		return 0
	}
	want := maxDataConnections - primaryDataStreams
	if want <= 0 {
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), dataStripeSetupWait)
	defer cancel()

	rc.peer.primaryAcceptWG.Wait()
	if rc.outbound {
		return rc.dialDataStripes(ctx, token, want)
	}
	return rc.acceptDataStripes(ctx, token, want)
}

func (c *rtcConn) selectedEndpoint() *udpEndpoint {
	local, ok := c.qc.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil
	}
	family := 6
	if local.IP.To4() != nil {
		family = 4
	}
	for _, ep := range c.peer.endpoints {
		addr, ok := ep.conn.LocalAddr().(*net.UDPAddr)
		if !ok || addr == nil {
			continue
		}
		if ep.family == family && addr.Port == local.Port {
			return ep
		}
	}
	return nil
}

func (c *rtcConn) dialDataStripes(ctx context.Context, token []byte, want int) int {
	ep := c.selectedEndpoint()
	remote, ok := c.qc.RemoteAddr().(*net.UDPAddr)
	if ep == nil || !ok || remote == nil {
		return 0
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	added := 0
	for i := 0; i < want; i++ {
		wg.Add(1)
		go func(index byte) {
			defer wg.Done()

			qc, st, owner, err := c.dialOneDataStripe(ctx, ep, remote, token, index, true)
			if err != nil {
				// 兼容 v0.14.0 / 严格 NAT：独立 source port 不通时退回原共享 UDP socket。
				qc, st, owner, err = c.dialOneDataStripe(ctx, ep, remote, token, index, false)
			}
			if err != nil {
				return
			}
			c.addStripe(qc, &quicStreamConn{st}, owner)
			mu.Lock()
			added++
			mu.Unlock()
		}(byte(i + 1))
	}
	wg.Wait()
	return added
}

func (c *rtcConn) dialOneDataStripe(
	ctx context.Context,
	ep *udpEndpoint,
	remote *net.UDPAddr,
	token []byte,
	index byte,
	dedicated bool,
) (*quic.Conn, *quic.Stream, io.Closer, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dataStripeSetupWait)
	defer cancel()

	tr := ep.transport
	var owner io.Closer
	var udpConn *net.UDPConn
	if dedicated {
		network := "udp6"
		bind := &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}
		if remote.IP.To4() != nil {
			network = "udp4"
			bind = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}
		var err error
		udpConn, err = net.ListenUDP(network, bind)
		if err != nil {
			return nil, nil, nil, err
		}
		_ = udpConn.SetReadBuffer(16 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(16 * 1024 * 1024)
		ownedTransport := &quic.Transport{Conn: udpConn}
		tr = ownedTransport
		owner = ownedTransport
	}

	cleanup := func() {
		if owner != nil {
			_ = owner.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
	}

	qc, err := tr.Dial(dialCtx, remote, c.peer.clientTLSConfig(), quicConfig())
	if err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	st, err := qc.OpenStreamSync(dialCtx)
	if err != nil {
		_ = qc.CloseWithError(0, "data stripe stream failed")
		cleanup()
		return nil, nil, nil, err
	}

	header := make([]byte, 2+len(token))
	header[0] = dataStripeTag
	header[1] = index
	copy(header[2:], token)
	if _, err := st.Write(header); err != nil {
		_ = qc.CloseWithError(0, "data stripe auth failed")
		cleanup()
		return nil, nil, nil, err
	}
	var ack [2]byte
	if _, err := io.ReadFull(st, ack[:]); err != nil || string(ack[:]) != "OK" {
		_ = qc.CloseWithError(0, "data stripe rejected")
		cleanup()
		if err == nil {
			err = errors.New("data stripe rejected")
		}
		return nil, nil, nil, err
	}
	return qc, st, owner, nil
}

func (c *rtcConn) acceptDataStripes(ctx context.Context, token []byte, want int) int {
	ep := c.selectedEndpoint()
	if ep == nil || ep.listener == nil {
		return 0
	}
	primaryRemote, _ := c.qc.RemoteAddr().(*net.UDPAddr)
	added := 0

	for added < want {
		qc, err := ep.listener.Accept(ctx)
		if err != nil {
			break
		}
		// v0.14.1 data stripe 会使用不同的远端 source port，所以这里只要求
		// 来源 IP 与主 QUIC 相同。真正的会话归属继续由 TLS fingerprint +
		// 下方 256-bit session token 双重校验。
		stripeRemote, _ := qc.RemoteAddr().(*net.UDPAddr)
		if primaryRemote == nil || stripeRemote == nil || !stripeRemote.IP.Equal(primaryRemote.IP) {
			_ = qc.CloseWithError(0, "unexpected stripe endpoint")
			continue
		}
		if err := c.acceptOneDataStripe(ctx, qc, token); err != nil {
			_ = qc.CloseWithError(0, "invalid data stripe")
			continue
		}
		added++
	}
	return added
}

func (c *rtcConn) acceptOneDataStripe(ctx context.Context, qc *quic.Conn, token []byte) error {
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		return err
	}
	header := make([]byte, 2+len(token))
	if _, err := io.ReadFull(st, header); err != nil {
		return err
	}
	if header[0] != dataStripeTag {
		return errors.New("not a data stripe")
	}
	if header[1] == 0 || int(header[1]) >= maxDataConnections {
		return fmt.Errorf("invalid data stripe index %d", header[1])
	}
	if !equalBytes(header[2:], token) {
		return errors.New("data stripe token mismatch")
	}
	if _, err := st.Write([]byte("OK")); err != nil {
		return err
	}
	c.addStripe(qc, &quicStreamConn{st}, nil)
	return nil
}
