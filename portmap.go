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

// discoverPortMapping 尝试 PCP -> NAT-PMP -> UPnP IGD。
// 这些映射都只是创建公网到当前 QUIC UDP 端口的直接路径，不转发任何业务流量。
func discoverPortMapping(ep *udpEndpoint) (signalCandidate, func(), string, error) {
	if ep == nil || ep.family != 4 || ep.conn == nil {
		return signalCandidate{}, nil, "", errors.New("IPv4 UDP endpoint required")
	}
	localPort := ep.conn.LocalAddr().(*net.UDPAddr).Port
	gw, err := gateway.DiscoverGateway()
	if err == nil {
		localIP, localErr := gateway.DiscoverInterface()
		if localErr == nil && localIP.To4() != nil {
			if addr, cleanup, err := tryPCP(gw, localIP, localPort); err == nil {
				return signalCandidate{Addr: addr.String(), Type: "portmap"}, cleanup, "PCP", nil
			}
			if addr, cleanup, err := tryNATPMP(gw, localIP, localPort); err == nil {
				return signalCandidate{Addr: addr.String(), Type: "portmap"}, cleanup, "NAT-PMP", nil
			}
		}
	}
	if addr, cleanup, err := tryUPnP(localPort); err == nil {
		return signalCandidate{Addr: addr.String(), Type: "portmap"}, cleanup, "UPnP", nil
	}
	return signalCandidate{}, nil, "", errors.New("no explicit UDP port mapping available")
}

func tryNATPMP(gw, localIP net.IP, localPort int) (*net.UDPAddr, func(), error) {
	client := natpmp.NewClientWithLocalAndTimeout(gw, localIP, 1100*time.Millisecond)
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

func tryUPnP(localPort int) (*net.UDPAddr, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
	defer cancel()

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
func tryPCP(gw, localIP net.IP, localPort int) (*net.UDPAddr, func(), error) {
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
		_ = conn.SetDeadline(time.Now().Add(650 * time.Millisecond))
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
