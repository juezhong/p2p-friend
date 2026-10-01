package main

import (
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
)

func writeText(w io.Writer, s string) error {
	b := []byte(s)
	if len(b) > maxTextBytes {
		return fmt.Errorf("text too long: %d bytes", len(b))
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readText(r io.Reader) (string, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	if n > maxTextBytes {
		return "", fmt.Errorf("text too long: %d bytes", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func copyExactWithProgress(dst io.Writer, src io.Reader, h hash.Hash, size int64, buf []byte, p *progress) error {
	remaining := size
	for remaining > 0 {
		want := int64(len(buf))
		if remaining < want {
			want = remaining
		}
		n, err := io.ReadFull(src, buf[:want])
		if err != nil {
			return err
		}
		chunk := buf[:n]
		if _, err := dst.Write(chunk); err != nil {
			return err
		}
		if _, err := h.Write(chunk); err != nil {
			return err
		}
		remaining -= int64(n)
		p.Done += int64(n)
		p.CurrentDone += int64(n)
		p.print(false)
	}
	return nil
}

func (p *progress) print(force bool) {
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
	consoleMu.Lock()
	defer consoleMu.Unlock()
	if p.Total > 0 {
		percent := float64(p.Done) * 100 / float64(p.Total)
		fmt.Printf("\r%s %-28s %6.2f%%  %s / %s  %s/s", p.Prefix, truncate(p.Current, 28), percent, humanBytes(p.Done), humanBytes(p.Total), humanBytes(int64(speed)))
	} else {
		fmt.Printf("\r%s %-28s %s  %s/s", p.Prefix, truncate(p.Current, 28), humanBytes(p.Done), humanBytes(int64(speed)))
	}
	if force {
		fmt.Println()
	}
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
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "connection reset")
}

func consolePrintf(format string, args ...any) {
	consoleMu.Lock()
	defer consoleMu.Unlock()
	fmt.Printf(format, args...)
}

func consolePrintln(args ...any) {
	consoleMu.Lock()
	defer consoleMu.Unlock()
	fmt.Println(args...)
}
