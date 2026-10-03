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
	dataStripeSetupWait = 2 * time.Second
)

// setupDataStripes 在主 QUIC 完成 TLS + 应用 token 认证后扩展额外 data-only
// QUIC connections。它们复用主连接已经验证可达的 UDP 5-tuple 和同一个
// quic.Transport，因此不会重新做 STUN / punch，也不会新开 NAT 端口。
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

			dialCtx, cancel := context.WithTimeout(ctx, dataStripeSetupWait)
			defer cancel()
			qc, err := ep.transport.Dial(dialCtx, remote, c.peer.clientTLSConfig(), quicConfig())
			if err != nil {
				return
			}
			st, err := qc.OpenStreamSync(dialCtx)
			if err != nil {
				_ = qc.CloseWithError(0, "data stripe stream failed")
				return
			}

			header := make([]byte, 2+len(token))
			header[0] = dataStripeTag
			header[1] = index
			copy(header[2:], token)
			if _, err := st.Write(header); err != nil {
				_ = qc.CloseWithError(0, "data stripe auth failed")
				return
			}
			var ack [2]byte
			if _, err := io.ReadFull(st, ack[:]); err != nil || string(ack[:]) != "OK" {
				_ = qc.CloseWithError(0, "data stripe rejected")
				return
			}

			c.addStripe(qc, &quicStreamConn{st})
			mu.Lock()
			added++
			mu.Unlock()
		}(byte(i + 1))
	}
	wg.Wait()
	return added
}

func (c *rtcConn) acceptDataStripes(ctx context.Context, token []byte, want int) int {
	ep := c.selectedEndpoint()
	if ep == nil || ep.listener == nil {
		return 0
	}
	primaryRemote := c.qc.RemoteAddr().String()
	added := 0

	for added < want {
		qc, err := ep.listener.Accept(ctx)
		if err != nil {
			break
		}
		if !sameUDPAddress(qc.RemoteAddr().String(), primaryRemote) {
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
	c.addStripe(qc, &quicStreamConn{st})
	return nil
}
