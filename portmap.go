package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

const (
	portMapLifetimeSeconds = 3600
	pcpPort                = 5351
)

type portMapResult struct {
	addr    *net.UDPAddr
	cleanup func()
	method  string
	err     error
}

// discoverPortMappingContext 并行尝试 PCP / NAT-PMP / UPnP，返回最先成功的一条。
// 未获胜的探测在 ctx 取消后会尽量停止；若已经创建映射，会立即清理。
func discoverPortMappingContext(ctx context.Context, ep *udpEndpoint) (signalCandidate, func(), string, error) {
	if ep == nil || ep.family != 4 || ep.conn == nil {
		return signalCandidate{}, nil, "", errors.New("IPv4 UDP endpoint required")
	}
	localPort := ep.conn.LocalAddr().(*net.UDPAddr).Port
	gw, gwErr := gateway.DiscoverGateway()
	localIP, ipErr := gateway.DiscoverInterface()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan portMapResult, 3)
	workers := 0

	start := func(method string, fn func(context.Context) (*net.UDPAddr, func(), error)) {
		workers++
		go func() {
			addr, cleanup, err := fn(ctx)
			result := portMapResult{addr: addr, cleanup: cleanup, method: method, err: err}
			select {
			case results <- result:
			case <-ctx.Done():
				if cleanup != nil {
					cleanup()
				}
			}
		}()
	}

	if gwErr == nil && ipErr == nil && localIP.To4() != nil {
		start("PCP", func(ctx context.Context) (*net.UDPAddr, func(), error) {
			return tryPCPContext(ctx, gw, localIP, localPort)
		})
		start("NAT-PMP", func(ctx context.Context) (*net.UDPAddr, func(), error) {
			return tryNATPMPContext(ctx, gw, localIP, localPort)
		})
	}
	start("UPnP", func(ctx context.Context) (*net.UDPAddr, func(), error) {
		return tryUPnPContext(ctx, localPort)
	})

	var lastErr error
	for completed := 0; completed < workers; {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return signalCandidate{}, nil, "", lastErr
			}
			return signalCandidate{}, nil, "", ctx.Err()
		case result := <-results:
			completed++
			if result.err != nil || result.addr == nil {
				if result.err != nil {
					lastErr = result.err
				}
				continue
			}
			cancel()
			return signalCandidate{Addr: result.addr.String(), Type: "portmap"}, result.cleanup, result.method, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no explicit UDP port mapping available")
	}
	return signalCandidate{}, nil, "", lastErr
}

func discoverPortMapping(ep *udpEndpoint) (signalCandidate, func(), string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), candidateGatherBudget)
	defer cancel()
	return discoverPortMappingContext(ctx, ep)
}

func tryNATPMPContext(ctx context.Context, gw, _ net.IP, localPort int) (*net.UDPAddr, func(), error) {
	timeout := 600 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, nil, context.DeadlineExceeded
	}
	client := natpmp.NewClientWithTimeout(gw, timeout)
	ext, err := client.GetExternalAddress()
	if err != nil {
		return nil, nil, err
	}
	mapping, err := client.AddPortMapping("udp", localPort, localPort, portMapLifetimeSeconds)
	if err != nil || mapping.MappedExternalPort == 0 {
		return nil, nil, errors.New("NAT-PMP mapping failed")
	}
	ip := net.IPv4(
		ext.ExternalIPAddress[0],
		ext.ExternalIPAddress[1],
		ext.ExternalIPAddress[2],
		ext.ExternalIPAddress[3],
	)
	if ip.IsUnspecified() {
		return nil, nil, errors.New("NAT-PMP returned unspecified external IP")
	}
	mappedPort := int(mapping.MappedExternalPort)
	cleanup := func() {
		_, _ = client.AddPortMapping("udp", localPort, 0, 0)
	}
	return &net.UDPAddr{IP: ip, Port: mappedPort}, cleanup, nil
}

func tryNATPMP(gw, localIP net.IP, localPort int) (*net.UDPAddr, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), candidateGatherBudget)
	defer cancel()
	return tryNATPMPContext(ctx, gw, localIP, localPort)
}

func tryUPnPContext(ctx context.Context, localPort int) (*net.UDPAddr, func(), error) {

	// IGD v2 支持 AddAnyPortMapping，可接受路由器重新选择外部端口。
	if clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil {
		for _, c := range clients {
			extIP, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil {
				continue
			}
			ip := net.ParseIP(extIP)
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			reserved, err := c.AddAnyPortMappingCtx(
				ctx, "", uint16(localPort), "UDP", uint16(localPort),
				localIPv4String(), true, "p2p-friend", portMapLifetimeSeconds,
			)
			if err != nil {
				err = c.AddPortMappingCtx(
					ctx, "", uint16(localPort), "UDP", uint16(localPort),
					localIPv4String(), true, "p2p-friend", portMapLifetimeSeconds,
				)
				if err != nil {
					continue
				}
				reserved = uint16(localPort)
			}
			cleanup := func() {
				dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
				defer dcancel()
				_ = c.DeletePortMappingCtx(dctx, "", reserved, "UDP")
			}
			return &net.UDPAddr{IP: ip, Port: int(reserved)}, cleanup, nil
		}
	}

	// 老路由器常只提供 IGD v1 WANIPConnection。
	if clients, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range clients {
			extIP, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil {
				continue
			}
			ip := net.ParseIP(extIP)
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			err = c.AddPortMappingCtx(
				ctx, "", uint16(localPort), "UDP", uint16(localPort),
				localIPv4String(), true, "p2p-friend", portMapLifetimeSeconds,
			)
			if err != nil {
				continue
			}
			cleanup := func() {
				dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
				defer dcancel()
				_ = c.DeletePortMappingCtx(dctx, "", uint16(localPort), "UDP")
			}
			return &net.UDPAddr{IP: ip, Port: localPort}, cleanup, nil
		}
	}

	// PPP 型网关也属于常见 IGD v1 实现。
	if clients, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range clients {
			extIP, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil {
				continue
			}
			ip := net.ParseIP(extIP)
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			err = c.AddPortMappingCtx(
				ctx, "", uint16(localPort), "UDP", uint16(localPort),
				localIPv4String(), true, "p2p-friend", portMapLifetimeSeconds,
			)
			if err != nil {
				continue
			}
			cleanup := func() {
				dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
				defer dcancel()
				_ = c.DeletePortMappingCtx(dctx, "", uint16(localPort), "UDP")
			}
			return &net.UDPAddr{IP: ip, Port: localPort}, cleanup, nil
		}
	}
	return nil, nil, errors.New("UPnP mapping unavailable")
}

func tryUPnP(localPort int) (*net.UDPAddr, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), candidateGatherBudget)
	defer cancel()
	return tryUPnPContext(ctx, localPort)
}

func localIPv4String() string {
	if ip, err := gateway.DiscoverInterface(); err == nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// PCP MAP 按 RFC 6887 使用独立控制 socket 与默认网关通信；真正映射的内部端口
// 仍是 p2p-friend 的 QUIC UDP 端口。
func tryPCPContext(ctx context.Context, gw, localIP net.IP, localPort int) (*net.UDPAddr, func(), error) {
	gw4 := gw.To4()
	local4 := localIP.To4()
	if gw4 == nil || local4 == nil {
		return nil, nil, errors.New("PCP requires IPv4 gateway")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local4, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	req := buildPCPMapRequest(local4, uint16(localPort), uint16(localPort), portMapLifetimeSeconds, nonce)
	gwAddr := &net.UDPAddr{IP: gw4, Port: pcpPort}
	buf := make([]byte, 1100)
	for attempt := 0; attempt < 2; attempt++ {
		deadline := time.Now().Add(500 * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetDeadline(deadline)
		if _, err := conn.WriteToUDP(req, gwAddr); err != nil {
			continue
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		addr, err := parsePCPMapResponse(buf[:n], nonce)
		if err != nil {
			continue
		}
		cleanup := func() {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local4, Port: 0})
			if err != nil {
				return
			}
			defer c.Close()
			del := buildPCPMapRequest(local4, uint16(localPort), 0, 0, nonce)
			_, _ = c.WriteToUDP(del, gwAddr)
		}
		return addr, cleanup, nil
	}
	return nil, nil, errors.New("PCP mapping unavailable")
}

func tryPCP(gw, localIP net.IP, localPort int) (*net.UDPAddr, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), candidateGatherBudget)
	defer cancel()
	return tryPCPContext(ctx, gw, localIP, localPort)
}

func buildPCPMapRequest(localIP net.IP, internalPort, suggestedExternalPort uint16, lifetime uint32, nonce [12]byte) []byte {
	pkt := make([]byte, 60)
	pkt[0] = 2
	pkt[1] = 1 // MAP
	binary.BigEndian.PutUint32(pkt[4:8], lifetime)
	ip16 := localIP.To16()
	copy(pkt[8:24], ip16)
	copy(pkt[24:36], nonce[:])
	pkt[36] = 17 // UDP
	binary.BigEndian.PutUint16(pkt[40:42], internalPort)
	binary.BigEndian.PutUint16(pkt[42:44], suggestedExternalPort)
	// suggested external IP remains all-zero.
	return pkt
}

func parsePCPMapResponse(pkt []byte, nonce [12]byte) (*net.UDPAddr, error) {
	if len(pkt) < 60 || pkt[0] != 2 || pkt[1] != 0x81 {
		return nil, errors.New("invalid PCP MAP response")
	}
	if pkt[3] != 0 {
		return nil, fmt.Errorf("PCP result code %d", pkt[3])
	}
	if !equalBytes(pkt[24:36], nonce[:]) {
		return nil, errors.New("PCP nonce mismatch")
	}
	port := binary.BigEndian.Uint16(pkt[42:44])
	ip := net.IP(append([]byte(nil), pkt[44:60]...))
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if port == 0 || ip == nil || ip.IsUnspecified() {
		return nil, errors.New("PCP returned invalid external endpoint")
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}
