package main

import (
	"fmt"
	"net"
	"strings"
)

type udpSocketInfo struct {
	Family   string
	Address  string
	Mode     string
	Selected bool
}

type quicConnectionInfo struct {
	LinkMode            string
	QUICRole            string
	LocalUDP            string
	RemoteUDP           string
	RemoteCandidateType string
	Streams             int
	Sockets             []udpSocketInfo
	STUNMappings        []string
}

func (c *rtcConn) ConnectionInfo() quicConnectionInfo {
	info := quicConnectionInfo{
		LinkMode:  c.LinkMode(),
		LocalUDP:  c.qc.LocalAddr().String(),
		RemoteUDP: c.qc.RemoteAddr().String(),
		Streams:   len(c.lanes),
	}
	if c.peer.server {
		info.QUICRole = "监听端"
	} else {
		info.QUICRole = "主动连接端"
	}

	remote := c.qc.RemoteAddr().String()
	for _, cand := range c.peer.remoteCandidates() {
		if !sameUDPAddress(cand.Addr, remote) {
			continue
		}
		switch strings.ToLower(cand.Type) {
		case "srflx":
			info.RemoteCandidateType = "STUN 映射 / NAT-PUNCH"
		case "host":
			info.RemoteCandidateType = "HOST"
		default:
			info.RemoteCandidateType = strings.ToUpper(cand.Type)
		}
	}
	if info.RemoteCandidateType == "" {
		info.RemoteCandidateType = "未知"
	}

	selected, _ := c.qc.LocalAddr().(*net.UDPAddr)
	for _, ep := range c.peer.endpoints {
		addr := ep.conn.LocalAddr().String()
		family := "IPv4"
		if ep.family == 6 {
			family = "IPv6"
		}
		mode := "主动连接"
		if ep.listener != nil {
			mode = "监听"
		}
		if ep.family == 4 {
			mode += " + NAT 打洞"
		}
		isSelected := false
		if selected != nil {
			if udpAddr, ok := ep.conn.LocalAddr().(*net.UDPAddr); ok {
				isSelected = udpAddr.Port == selected.Port && ((ep.family == 4 && selected.IP.To4() != nil) || (ep.family == 6 && selected.IP.To4() == nil))
			}
		}
		info.Sockets = append(info.Sockets, udpSocketInfo{
			Family: family, Address: addr, Mode: mode, Selected: isSelected,
		})
	}

	for _, cand := range c.peer.localCandidates() {
		if strings.EqualFold(cand.Type, "srflx") {
			info.STUNMappings = append(info.STUNMappings, cand.Addr)
		}
	}
	return info
}

func formatSocketStatus(s udpSocketInfo) string {
	selected := ""
	if s.Selected {
		selected = " [当前 QUIC/传输]"
	}
	return fmt.Sprintf("%s %s  %s%s", s.Family, s.Address, s.Mode, selected)
}
