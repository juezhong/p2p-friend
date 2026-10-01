package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConnectionCodeRoundTrip(t *testing.T) {
	in := connectCode{Version: protocolVersion, Address: "[2001:db8::1]:5000", Token: "abc", Fingerprint: "def"}
	s, err := encodeCode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeCode(s)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %#v != %#v", out, in)
	}
}

func TestSplitCommandKeepsWindowsAndUnicodePath(t *testing.T) {
	cmd, arg := splitCommand(`put "D:\\BaiduNetdiskDownload\\【正点原子】\\手册 2024.pdf"`)
	if cmd != "put" {
		t.Fatalf("cmd=%q", cmd)
	}
	want := `D:\\BaiduNetdiskDownload\\【正点原子】\\手册 2024.pdf`
	if arg != want {
		t.Fatalf("arg=%q want=%q", arg, want)
	}
}

func TestSafeDestinationRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	bad := []string{"../escape", "a/../../escape", "/absolute"}
	for _, p := range bad {
		if _, err := safeDestination(base, p); err == nil {
			t.Fatalf("expected %q to be rejected", p)
		}
	}
}

func TestSafeRequestedPathRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := safeRequestedPath(base, "ok.txt"); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	bad := []string{"../escape", "a/../../escape", "/absolute", "."}
	for _, p := range bad {
		if _, err := safeRequestedPath(base, p); err == nil {
			t.Fatalf("expected %q to be rejected", p)
		}
	}
}

func TestRecursiveUnicodeTransfer(t *testing.T) {
	srcParent := t.TempDir()
	src := filepath.Join(srcParent, "资料目录")
	if err := os.MkdirAll(filepath.Join(src, "子目录", "空目录"), 0o755); err != nil {
		t.Fatal(err)
	}
	wantA := []byte("中文文件名内容\n")
	wantB := bytes.Repeat([]byte{0x00, 0x11, 0x22, 0x33}, 4096)
	if err := os.WriteFile(filepath.Join(src, "正点原子产品选型手册_20240826.pdf"), wantA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "子目录", "data.bin"), wantB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "子目录", "zero"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	entries, total, err := buildEntries(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	sendErr := make(chan error, 1)
	go func() {
		bw := bufio.NewWriter(left)
		sendErr <- sendSessionWriter(bw, entries, total, "[TEST]")
	}()
	br := bufio.NewReader(right)
	if err := receiveSessionReader(br, dst, false, total, "[TEST]"); err != nil {
		t.Fatal(err)
	}
	if err := <-sendErr; err != nil {
		t.Fatal(err)
	}

	gotA, err := os.ReadFile(filepath.Join(dst, "资料目录", "正点原子产品选型手册_20240826.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, wantA) {
		t.Fatal("unicode file content mismatch")
	}
	gotB, err := os.ReadFile(filepath.Join(dst, "资料目录", "子目录", "data.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, wantB) {
		t.Fatal("binary file mismatch")
	}
	if st, err := os.Stat(filepath.Join(dst, "资料目录", "子目录", "空目录")); err != nil || !st.IsDir() {
		t.Fatalf("empty directory missing: %v", err)
	}
}

func TestTwoTransfersRemainFramedOnOneConnection(t *testing.T) {
	srcParent := t.TempDir()
	f1 := filepath.Join(srcParent, "one.txt")
	f2 := filepath.Join(srcParent, "二号.txt")
	if err := os.WriteFile(f1, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	e1, n1, err := buildEntries(f1)
	if err != nil {
		t.Fatal(err)
	}
	e2, n2, err := buildEntries(f2)
	if err != nil {
		t.Fatal(err)
	}

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	dst := t.TempDir()

	sendErr := make(chan error, 1)
	go func() {
		bw := bufio.NewWriter(left)
		for _, x := range []struct {
			label string
			e     []sendEntry
			n     int64
		}{{"one.txt", e1, n1}, {"二号.txt", e2, n2}} {
			if err := bw.WriteByte(msgTransfer); err != nil {
				sendErr <- err
				return
			}
			if err := writeText(bw, x.label); err != nil {
				sendErr <- err
				return
			}
			if err := binary.Write(bw, binary.BigEndian, uint64(x.n)); err != nil {
				sendErr <- err
				return
			}
			if err := sendSessionWriter(bw, x.e, x.n, "[TEST]"); err != nil {
				sendErr <- err
				return
			}
		}
		sendErr <- nil
	}()

	br := bufio.NewReader(right)
	for i := 0; i < 2; i++ {
		typ, err := br.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		if typ != msgTransfer {
			t.Fatalf("message %d type=%d", i, typ)
		}
		if _, err := readText(br); err != nil {
			t.Fatal(err)
		}
		var total uint64
		if err := binary.Read(br, binary.BigEndian, &total); err != nil {
			t.Fatal(err)
		}
		if err := receiveSessionReader(br, dst, false, int64(total), "[TEST]"); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"one.txt": "one", "二号.txt": "two"} {
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Fatalf("%s=%q", name, string(b))
		}
	}
}

func TestAuthenticationRoles(t *testing.T) {
	token := bytes.Repeat([]byte{0x42}, 32)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- authenticateListener(left, token, roleHost)
	}()
	if err := authenticateDialer(right, token, roleJoin); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestRejectSymlinkInSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require Windows privileges")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "tree")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildEntries(dir); err == nil {
		t.Fatal("expected symlink source to be rejected")
	}
}
