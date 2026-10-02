package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

var consoleOut io.Writer = os.Stdout

func (p *progress) print(force bool) {
	if p == nil || p.Silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if !force && now.Sub(p.LastPrint) < 500*time.Millisecond {
		return
	}
	p.LastPrint = now
	elapsed := now.Sub(p.Start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}
	speed := float64(p.Done) / elapsed
	var line string
	if p.Total > 0 {
		percent := float64(p.Done) * 100 / float64(p.Total)
		line = fmt.Sprintf("\r%s %-30s %6.2f%%  %s / %s  %s/s", p.Prefix, truncate(p.Current, 30), percent, humanBytes(p.Done), humanBytes(p.Total), humanBytes(int64(speed)))
	} else {
		line = fmt.Sprintf("\r%s %-30s %s  %s/s", p.Prefix, truncate(p.Current, 30), humanBytes(p.Done), humanBytes(int64(speed)))
	}
	if force {
		line += "\n"
		p.lineOpen = false
	} else {
		p.lineOpen = true
	}
	consoleMu.Lock()
	defer consoleMu.Unlock()
	_, _ = io.WriteString(consoleOut, line)
}

func (p *progress) closeLine() {
	if p == nil || p.Silent {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.lineOpen {
		return
	}
	consoleMu.Lock()
	_, _ = io.WriteString(consoleOut, "\r\n")
	consoleMu.Unlock()
	p.lineOpen = false
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return "…" + string(r[len(r)-(n-1):])
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	for _, u := range units {
		v /= 1024
		if v < 1024 || u == units[len(units)-1] {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%d B", n)
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0 {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "session closed") ||
		strings.Contains(s, "normal shutdown")
}

func (s *peerSession) reportTransportError(scope string, err error) {
	if err == nil || s.closing.Load() || s.remoteBye.Load() || isClosedErr(err) {
		return
	}
	s.transportErrOnce.Do(func() {
		msg := err.Error()
		if strings.Contains(strings.ToLower(msg), "buffer space") || strings.Contains(strings.ToLower(msg), "queue was full") {
			consolePrintf("[%s] Windows UDP 发送队列已满，连接异常: %v\n", scope, err)
			return
		}
		consolePrintf("[%s] 传输连接异常: %v\n", scope, err)
	})
}

func setConsoleWriter(w io.Writer) func() {
	if w == nil {
		w = os.Stdout
	}
	consoleMu.Lock()
	prev := consoleOut
	consoleOut = w
	consoleMu.Unlock()
	return func() {
		consoleMu.Lock()
		consoleOut = prev
		consoleMu.Unlock()
	}
}

func consolePrintf(format string, args ...any) {
	consoleMu.Lock()
	defer consoleMu.Unlock()
	fmt.Fprintf(consoleOut, format, args...)
}

func consolePrintln(args ...any) {
	consoleMu.Lock()
	defer consoleMu.Unlock()
	fmt.Fprintln(consoleOut, args...)
}
