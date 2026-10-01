package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestConnectionCodeRoundTrip(t *testing.T) {
	in := connectCode{Version: protocolVersion, Address: "[2001:db8::1]:5000", Token: "abc", Fingerprint: "def"}
	s, err := encodeCode(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "P2P4-") {
		t.Fatalf("unexpected code prefix: %s", s)
	}
	out, err := decodeCode(s)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %#v != %#v", out, in)
	}
}

func TestParseCommandLinePreservesWindowsUnicodePath(t *testing.T) {
	args, err := parseCommandLine(`get "D:\BaiduNetdiskDownload\【正点原子】\手册 2024.pdf" "./本地 手册.pdf"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"get", `D:\BaiduNetdiskDownload\【正点原子】\手册 2024.pdf`, "./本地 手册.pdf"}
	if len(args) != len(want) {
		t.Fatalf("args=%#v", args)
	}
	for i := range args {
		if args[i] != want[i] {
			t.Fatalf("arg[%d]=%q want=%q", i, args[i], want[i])
		}
	}
}

func TestChangeDirDash(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}
	next, prev, err := changeDir(a, "", b)
	if err != nil {
		t.Fatal(err)
	}
	if next != b || prev != a {
		t.Fatalf("next=%q prev=%q", next, prev)
	}
	next, prev, err = changeDir(next, prev, "-")
	if err != nil {
		t.Fatal(err)
	}
	if next != a || prev != b {
		t.Fatalf("dash next=%q prev=%q", next, prev)
	}
}

func TestAbsolutePathAllowed(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "x.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := cleanExistingPath(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("got=%q want=%q", got, p)
	}
}

func TestBidirectionalRemoteFilesystemAndTransfer(t *testing.T) {
	aLocal := t.TempDir()
	bLocal := t.TempDir()
	bOther := t.TempDir()

	if err := os.MkdirAll(filepath.Join(aLocal, "资料", "子目录"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aLocal, "资料", "中文.txt"), []byte("hello from A"), 0o644); err != nil {
		t.Fatal(err)
	}
	absRemoteFile := filepath.Join(bOther, "远端绝对路径.bin")
	wantRemote := bytes.Repeat([]byte{0x11, 0x22, 0x33}, 4096)
	if err := os.WriteFile(absRemoteFile, wantRemote, 0o644); err != nil {
		t.Fatal(err)
	}

	a, b := newSessionPair(t, aLocal, bLocal, 0)
	defer a.close(false)
	defer b.close(false)

	pwd, err := a.remotePwd()
	if err != nil {
		t.Fatal(err)
	}
	if pwd != bLocal {
		t.Fatalf("remote pwd=%q want=%q", pwd, bLocal)
	}

	resp, err := a.callRPC("ls", bOther, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].Name != filepath.Base(absRemoteFile) {
		t.Fatalf("unexpected remote entries: %#v", resp.Entries)
	}

	remoteDest := filepath.Join(bLocal, "incoming", "renamed-data")
	if err := a.put("资料", remoteDest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(remoteDest, "中文.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello from A" {
		t.Fatalf("put content=%q", string(got))
	}

	localDest := filepath.Join(aLocal, "downloaded.bin")
	if err := a.get(absRemoteFile, localDest); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(localDest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantRemote) {
		t.Fatal("absolute get content mismatch")
	}

	if err := a.remoteCd(bOther); err != nil {
		t.Fatal(err)
	}
	if a.getRemoteCwd() != bOther {
		t.Fatalf("cached remote cwd=%q", a.getRemoteCwd())
	}
	if err := a.remoteCd("-"); err != nil {
		t.Fatal(err)
	}
	if a.getRemoteCwd() != bLocal {
		t.Fatalf("remote cd - =%q want=%q", a.getRemoteCwd(), bLocal)
	}
}

type slowConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Write(p)
}

func TestCancelGetKeepsSessionAndRemovesPartialFile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration cancellation test")
	}
	aLocal := t.TempDir()
	bLocal := t.TempDir()
	large := filepath.Join(bLocal, "large.bin")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{0x5a}, 1024*1024)
	for i := 0; i < 32; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	a, b := newSessionPair(t, aLocal, bLocal, 2*time.Millisecond)
	defer a.close(false)
	defer b.close(false)

	done := make(chan error, 1)
	go func() { done <- a.get("large.bin", "cancelled.bin") }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.transferMu.Lock()
		n := len(a.inbound)
		a.transferMu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !a.cancelActive("test cancel") {
		t.Fatal("no active transfer to cancel")
	}

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("get error=%v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled get did not return")
	}

	if _, err := os.Stat(filepath.Join(aLocal, "cancelled.bin")); !os.IsNotExist(err) {
		t.Fatalf("partial destination still exists: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(aLocal, ".p2p-friend-*.part"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left after cancel: %#v", matches)
	}

	// 取消传输后同一条连接仍应能继续处理远端命令。
	pwd, err := a.remotePwd()
	if err != nil {
		t.Fatalf("session unusable after cancel: %v", err)
	}
	if pwd != bLocal {
		t.Fatalf("pwd after cancel=%q want=%q", pwd, bLocal)
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
	if _, _, _, err := buildEntries(dir); err == nil {
		t.Fatal("expected symlink source to be rejected")
	}
}

func newSessionPair(t *testing.T, aCwd, bCwd string, bWriteDelay time.Duration) (*peerSession, *peerSession) {
	t.Helper()
	left, right := net.Pipe()
	var bConn net.Conn = right
	if bWriteDelay > 0 {
		bConn = &slowConn{Conn: right, delay: bWriteDelay}
	}
	a := initPeerSession(left, "A", aCwd)
	b := initPeerSession(bConn, "B", bCwd)
	go a.readLoop()
	go b.readLoop()
	return a, b
}
