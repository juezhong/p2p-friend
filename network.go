package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"
)

func openTLSListener(listenAddr string) (net.Listener, []byte, string, error) {
	cert, certDER, err := generateCertificate()
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate TLS certificate: %w", err)
	}
	fingerprint := sha256.Sum256(certDER)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, nil, "", fmt.Errorf("generate token: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return nil, nil, "", fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	return ln, token, fingerprintHex, nil
}

func printConnectionCodes(ln net.Listener, token []byte, fingerprintHex string) error {
	port, err := listenerPort(ln.Addr())
	if err != nil {
		return err
	}
	addresses, err := localCandidateAddresses(port)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errors.New("没有找到可用的非回环网络地址")
	}

	consolePrintln("连接码（优先使用 [global IPv6]）：")
	consolePrintln("")
	tokenB64 := base64.RawURLEncoding.EncodeToString(token)
	for _, addr := range addresses {
		code, err := encodeCode(connectCode{
			Version:     protocolVersion,
			Address:     addr,
			Token:       tokenB64,
			Fingerprint: fingerprintHex,
		})
		if err != nil {
			return err
		}
		consolePrintf("  %s %s
", addr, addressScope(addr))
		consolePrintf("  %s

", code)
	}
	return nil
}

func addressScope(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		if ip.IsPrivate() {
			return "[private IPv4: 仅同一局域网/VPN]"
		}
		return "[public IPv4]"
	}
	if ip.IsPrivate() {
		return "[private IPv6/ULA]"
	}
	return "[global IPv6]"
}

func dialPeer(rawCode string) (net.Conn, []byte, error) {
	code, err := decodeCode(rawCode)
	if err != nil {
		return nil, nil, fmt.Errorf("无效连接码: %w", err)
	}
	if code.Version != protocolVersion {
		return nil, nil, fmt.Errorf("协议版本不匹配: 对方=%d，本程序=%d；双方都请使用 v%s", code.Version, protocolVersion, appVersion)
	}
	if _, _, err := net.SplitHostPort(code.Address); err != nil {
		return nil, nil, fmt.Errorf("invalid peer address %q: %w", code.Address, err)
	}

	token, err := base64.RawURLEncoding.DecodeString(code.Token)
	if err != nil || len(token) != 32 {
		return nil, nil, errors.New("连接码中的认证 token 无效")
	}
	expectedFP, err := hex.DecodeString(code.Fingerprint)
	if err != nil || len(expectedFP) != sha256.Size {
		return nil, nil, errors.New("连接码中的证书指纹无效")
	}

	consolePrintf("正在连接 %s ...
", code.Address)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 使用连接码中的 SHA-256 证书指纹校验临时证书。
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("unexpected TLS certificate chain")
			}
			actual := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(actual[:], expectedFP) {
				return errors.New("TLS certificate fingerprint mismatch")
			}
			return nil
		},
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", code.Address, tlsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("连接失败: %w%s", err, connectionHint(code.Address))
	}
	return conn, token, nil
}

func connectionHint(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return ""
	}
	if ip.To4() != nil && ip.IsPrivate() {
		return "
提示：这是私有 IPv4，只能用于同一局域网/VPN。公网请优先使用 global IPv6 连接码。"
	}
	if ip.To4() == nil {
		return "
提示：IPv6 TCP 在文件传输前就失败了，通常是创建会话一方的主机/路由器 IPv6 入站防火墙阻断。让另一方创建会话再试。"
	}
	return ""
}

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

func generateCertificate() (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "p2p-file ephemeral"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, der, nil
}

func listenerPort(addr net.Addr) (string, error) {
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", fmt.Errorf("parse listener address: %w", err)
	}
	return port, nil
}

func localCandidateAddresses(port string) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	seen := map[string]bool{}
	var globalV6, otherV6, publicV4, privateV4 []string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			addr := net.JoinHostPort(ip.String(), port)
			if seen[addr] {
				continue
			}
			seen[addr] = true
			if ip.To4() == nil {
				if ip.IsPrivate() {
					otherV6 = append(otherV6, addr)
				} else {
					globalV6 = append(globalV6, addr)
				}
			} else if ip.IsPrivate() {
				privateV4 = append(privateV4, addr)
			} else {
				publicV4 = append(publicV4, addr)
			}
		}
	}
	sort.Strings(globalV6)
	sort.Strings(otherV6)
	sort.Strings(publicV4)
	sort.Strings(privateV4)
	out := append([]string{}, globalV6...)
	out = append(out, publicV4...)
	out = append(out, otherV6...)
	out = append(out, privateV4...)
	return out, nil
}

func encodeCode(c connectCode) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return "P2P3-" + base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeCode(s string) (connectCode, error) {
	var c connectCode
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "P2P3-") {
		return c, errors.New("缺少 P2P3- 前缀；v0.3 与旧版 P2P1/P2P2 不兼容")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "P2P3-"))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}
