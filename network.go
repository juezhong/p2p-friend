package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

// 这层认证发生在 QUIC/TLS 1.3 连接建立之后，不涉及 WebRTC、ICE、DTLS 或 DataChannel。
// 会话 token 来自人工交换的 P2PF-INVITE / P2PF-REPLY，用来把已经建立的 QUIC
// 连接绑定到本次会话，并校验双方角色没有选反。QUIC 传输加密和创建方证书指纹校验
// 由 quic-go/TLS 层完成，这里只做应用层的会话确认。
func authenticateDialer(conn net.Conn, token []byte, localRole byte) error {
	if len(token) != 32 {
		return errors.New("invalid authentication token length")
	}
	buf := make([]byte, 0, len(protocolMagic)+len(token)+1)
	buf = append(buf, protocolMagic...)
	buf = append(buf, token...)
	buf = append(buf, localRole)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("send authentication: %w", err)
	}
	ack := make([]byte, 2)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return fmt.Errorf("read authentication response: %w", err)
	}
	if string(ack) != "OK" {
		return errors.New("peer rejected authentication or session role")
	}
	return nil
}

func authenticateListener(conn net.Conn, token []byte, localRole byte) error {
	magic := make([]byte, len(protocolMagic))
	if _, err := io.ReadFull(conn, magic); err != nil {
		return fmt.Errorf("read authentication magic: %w", err)
	}
	if string(magic) != protocolMagic {
		_, _ = conn.Write([]byte("ER"))
		return errors.New("invalid protocol magic")
	}
	gotToken := make([]byte, len(token))
	if _, err := io.ReadFull(conn, gotToken); err != nil {
		return fmt.Errorf("read authentication token: %w", err)
	}
	var role [1]byte
	if _, err := io.ReadFull(conn, role[:]); err != nil {
		return fmt.Errorf("read peer role: %w", err)
	}
	if !bytes.Equal(gotToken, token) {
		_, _ = conn.Write([]byte("ER"))
		return errors.New("authentication token mismatch")
	}
	if role[0] != roleHost && role[0] != roleJoin {
		_, _ = conn.Write([]byte("ER"))
		return fmt.Errorf("invalid peer role: %d", role[0])
	}
	if role[0] == localRole {
		_, _ = conn.Write([]byte("ER"))
		return errors.New("both peers selected the same session role")
	}
	if _, err := conn.Write([]byte("OK")); err != nil {
		return fmt.Errorf("send authentication response: %w", err)
	}
	return nil
}


func authenticatePeerConn(conn net.Conn, token []byte, localRole byte) error {
	if q, ok := conn.(interface{ QUICOutbound() bool }); ok && q.QUICOutbound() {
		return authenticateDialer(conn, token, localRole)
	}
	return authenticateListener(conn, token, localRole)
}
