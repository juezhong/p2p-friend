package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

// authenticateDialer and authenticateListener run after ICE/DTLS/DataChannel
// establishment. The random token comes from the manually exchanged signal
// code and binds the established channel to that session.
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
