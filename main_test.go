package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestSignalCodeRoundTrip(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	in := signalCode{
		Version: signalEnvelopeVersion,
		Kind:    "connect",
		Token:   token,
		Candidates: []signalCandidate{
			{Addr: "[2001:db8::1]:5000", Type: "host"},
			{Addr: "203.0.113.1:40000", Type: "srflx"},
		},
		Fingerprint: strings.Repeat("ab", 32),
	}
	s, err := encodeSignal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, signalInvitePrefix) {
		t.Fatalf("unexpected INVITE code prefix: %s", s)
	}
	if len(s) >= 200 {
		t.Fatalf("compact INVITE unexpectedly long: %d chars: %s", len(s), s)
	}
	out, err := decodeSignal(s, "connect")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
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

func TestParseCommandLineAutoEscapedSpaces(t *testing.T) {
	args, err := parseCommandLine(`get D:\Program\ Files\中文.txt`)
	if err != nil {
		t.Fatal(err)
	}
	want := `D:\Program Files\中文.txt`
	if len(args) != 2 || args[1] != want {
		t.Fatalf("args=%#v want path=%q", args, want)
	}
}

func TestLocalCompletionQuotesUnicodeSpaceDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "中文 目录"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &peerSession{localCwd: root}
	line := []rune("lcd 中")
	res := buildCompletion(s, line, len(line))
	if len(res.candidates) != 1 {
		t.Fatalf("candidates=%#v", res.candidates)
	}
	got := string(res.replace)
	want := `"中文 目录/"`
	if runtime.GOOS == "windows" {
		want = `"中文 目录\"`
	}
	if got != want {
		t.Fatalf("replace=%q want=%q", got, want)
	}
	if res.cursor != len([]rune(got))-1 {
		t.Fatalf("directory cursor=%d replacement runes=%d", res.cursor, len([]rune(got)))
	}
	cmd := string(line[:res.start]) + got
	args, err := parseCommandLine(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || !strings.Contains(args[1], "中文 目录") {
		t.Fatalf("completed command parsed as %#v", args)
	}
}

func TestRemoteCompletionUsesPeerDirectory(t *testing.T) {
	aLocal := t.TempDir()
	bLocal := t.TempDir()
	if err := os.Mkdir(filepath.Join(bLocal, "远程 空格"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bLocal, "远程文件.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, b := newSessionPair(t, aLocal, bLocal, 0)
	defer a.close(false)
	defer b.close(false)
	if _, err := a.remotePwd(); err != nil {
		t.Fatal(err)
	}

	line := []rune("cd 远")
	res := buildCompletion(a, line, len(line))
	if len(res.candidates) != 1 || !res.candidates[0].dir {
		t.Fatalf("cd candidates=%#v", res.candidates)
	}
	if got := string(res.replace); got != `"远程 空格/"` {
		t.Fatalf("cd completion=%q", got)
	}

	line = []rune("get 远程文")
	res = buildCompletion(a, line, len(line))
	if len(res.candidates) != 1 || res.candidates[0].dir {
		t.Fatalf("get candidates=%#v", res.candidates)
	}
	if got := string(res.replace); got != "远程文件.txt" {
		t.Fatalf("get completion=%q", got)
	}

	// 光标位于自动生成的闭合引号前时继续补全，不应产生两个闭合引号。
	if err := os.WriteFile(filepath.Join(bLocal, "远程 文件.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	line = []rune(`get "远程 文"`)
	res = buildCompletion(a, line, len(line)-1)
	if got := string(res.replace); got != `"远程 文件.txt"` {
		t.Fatalf("quoted continuation completion=%q", got)
	}
	if res.end != len(line) {
		t.Fatalf("completion should replace old closing quote: end=%d len=%d", res.end, len(line))
	}
}

func TestWindowsRemoteCompletionSplit(t *testing.T) {
	dir, base, sep := splitRemoteCompletionPath(`D:\BaiduNetdiskDownload\正点`, `D:\Downdata`)
	if dir != `D:\BaiduNetdiskDownload\` || base != "正点" || sep != `\` {
		t.Fatalf("dir=%q base=%q sep=%q", dir, base, sep)
	}
	dir, base, sep = splitRemoteCompletionPath(`D:\`, `D:\Downdata`)
	if dir != `D:\` || base != "" || sep != `\` {
		t.Fatalf("root dir=%q base=%q sep=%q", dir, base, sep)
	}
}

func TestDisplayWidthChinese(t *testing.T) {
	if got := displayWidthRunes([]rune("A中B")); got != 4 {
		t.Fatalf("display width=%d want=4", got)
	}
}

func TestLineEditorAsyncOutputKeepsPromptAndInput(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{out: &out, active: true, prompt: "p2p> ", line: []rune("get 中文"), cursor: len([]rune("get 中文"))}

	if _, err := e.Write([]byte("\r[GET] file.bin 50.00%  512 MiB / 1 GiB  8 MiB/s")); err != nil {
		t.Fatal(err)
	}
	if e.status == "" {
		t.Fatal("progress status was not stored")
	}
	if got := out.String(); !strings.Contains(got, "p2p> get 中文") || !strings.Contains(got, "[GET] file.bin 50.00%") {
		t.Fatalf("progress redraw missing prompt or status: %q", got)
	}

	out.Reset()
	if _, err := e.Write([]byte("[REMOTE GET] 对方请求下载: D:\\资料\\手册.pdf\n")); err != nil {
		t.Fatal(err)
	}
	if e.status != "" {
		t.Fatalf("ordinary async message should clear status, got %q", e.status)
	}
	got := out.String()
	if !strings.Contains(got, "[REMOTE GET] 对方请求下载") || !strings.Contains(got, "p2p> get 中文") {
		t.Fatalf("async message did not preserve prompt/input: %q", got)
	}
}

type multiLaneTestConn struct {
	net.Conn
	lanes []io.ReadWriteCloser
}

func (c *multiLaneTestConn) DataLanes() []io.ReadWriteCloser { return c.lanes }

func newMultiLaneSessionPair(t *testing.T, aCwd, bCwd string) (*peerSession, *peerSession) {
	t.Helper()
	ca, cb := net.Pipe()
	aLanes := make([]io.ReadWriteCloser, 0, parallelLanes)
	bLanes := make([]io.ReadWriteCloser, 0, parallelLanes)
	for i := 0; i < parallelLanes; i++ {
		la, lb := net.Pipe()
		aLanes = append(aLanes, la)
		bLanes = append(bLanes, lb)
	}
	a := initPeerSession(&multiLaneTestConn{Conn: ca, lanes: aLanes}, "A", aCwd)
	b := initPeerSession(&multiLaneTestConn{Conn: cb, lanes: bLanes}, "B", bCwd)
	go a.readLoop()
	go b.readLoop()
	return a, b
}

func TestParallelDataLanesTransferAndHash(t *testing.T) {
	aLocal := t.TempDir()
	bLocal := t.TempDir()
	payload := bytes.Repeat([]byte("0123456789abcdef"), 180000)
	if err := os.WriteFile(filepath.Join(aLocal, "large.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	a, b := newMultiLaneSessionPair(t, aLocal, bLocal)
	defer a.close(false)
	defer b.close(false)
	if st := dataState(a); st == nil || len(st.lanes) != parallelLanes {
		t.Fatalf("sender data lanes = %#v", st)
	}
	if st := dataState(b); st == nil || len(st.lanes) != parallelLanes {
		t.Fatalf("receiver data lanes = %#v", st)
	}
	if err := a.put("large.bin", "received.bin"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(bLocal, "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("parallel lane payload mismatch")
	}
	wantHash, err := fileSHA256(filepath.Join(aLocal, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	gotHash, err := fileSHA256(filepath.Join(bLocal, "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHash, wantHash) {
		t.Fatalf("hash mismatch sender=%x receiver=%x", wantHash, gotHash)
	}
}

func TestSessionAuthenticationTokenAndRoles(t *testing.T) {
	token := bytes.Repeat([]byte{0x5a}, 32)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	serverErr := make(chan error, 1)
	go func() { serverErr <- authenticateListener(left, token, roleHost) }()
	if err := authenticateDialer(right, token, roleJoin); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestAdaptiveTransferTuner(t *testing.T) {
	tuner := newAdaptiveTransferTuner("windows", 4)
	if got := tuner.current(); got.lanes != 2 || got.chunkSize != 128*1024 || got.pace != 0 {
		t.Fatalf("unexpected initial tuning: %#v", got)
	}

	// Even a slow but healthy 1 MiB/s path must be allowed to probe upward.
	for i := 0; i < 6; i++ {
		tuner.observe(512*1024, 500*time.Millisecond, nil)
	}
	if got := tuner.current(); got.lanes < 3 {
		t.Fatalf("throughput-based tuner failed to ramp on a slow healthy path: %#v", got)
	}

	// A higher profile that materially reduces throughput should be reverted.
	tuner = newAdaptiveTransferTuner("linux", 4)
	before := tuner.current()
	for i := 0; i < 2; i++ {
		tuner.observe(4*1024*1024, 400*time.Millisecond, nil) // 10 MiB/s baseline
	}
	probed := tuner.current()
	if probed == before {
		t.Fatalf("tuner did not probe a higher profile: before=%#v probed=%#v", before, probed)
	}
	tuner.observe(4*1024*1024, 800*time.Millisecond, nil) // 5 MiB/s, clear regression
	after := tuner.current()
	if after.lanes > probed.lanes || after.chunkSize > probed.chunkSize {
		t.Fatalf("tuner failed to reject a slower probe: probed=%#v after=%#v", probed, after)
	}
}

func TestLineEditorRedrawAvoidsCursorSaveRestore(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		out:    &out,
		active: true,
		prompt: "p2p[IPv6-DIRECT remote:/tmp]> ",
		line:   []rune("get 中文"),
		cursor: len([]rune("get 中")),
		status: "[GET] 50%",
	}
	e.mu.Lock()
	e.redrawLocked()
	e.mu.Unlock()
	got := out.String()
	if strings.Contains(got, "\x1b[s") || strings.Contains(got, "\x1b[u") {
		t.Fatalf("redraw still uses cursor save/restore: %q", got)
	}
	if !strings.Contains(got, e.prompt+"get 中文") || !strings.Contains(got, "[GET] 50%") {
		t.Fatalf("redraw missing prompt/input/status: %q", got)
	}
}

func ipv4EndpointAddr(t *testing.T, p *rtcPeer) string {
	t.Helper()
	for _, ep := range p.endpoints {
		if ep.family == 4 {
			port := ep.conn.LocalAddr().(*net.UDPAddr).Port
			return net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
		}
	}
	t.Fatal("no IPv4 endpoint")
	return ""
}

func TestQUICDialWaitsForDelayedHost(t *testing.T) {
	host, err := newPeer(true)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	join, err := newPeer(false)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Close()

	join.token = append([]byte(nil), host.token...)
	join.fingerprint = append([]byte(nil), host.fingerprint...)
	host.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, join), Type: "host"}})
	join.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, host), Type: "host"}})

	type connResult struct {
		conn net.Conn
		err  error
	}
	joinCh := make(chan connResult, 1)
	go func() {
		conn, err := join.dialQUIC()
		joinCh <- connResult{conn: conn, err: err}
	}()

	select {
	case r := <-joinCh:
		if r.conn != nil {
			_ = r.conn.Close()
		}
		t.Fatalf("join returned before host started listening: %v", r.err)
	case <-time.After(1500 * time.Millisecond):
	}

	hostCh := make(chan connResult, 1)
	go func() {
		conn, err := host.acceptQUIC()
		hostCh <- connResult{conn: conn, err: err}
	}()

	var joinConn net.Conn
	select {
	case r := <-joinCh:
		if r.err != nil {
			t.Fatalf("join failed after delayed host start: %v", r.err)
		}
		joinConn = r.conn
	case <-time.After(15 * time.Second):
		t.Fatal("join did not connect after host started")
	}
	defer joinConn.Close()

	select {
	case r := <-hostCh:
		if r.err != nil {
			t.Fatalf("host accept failed: %v", r.err)
		}
		_ = r.conn.Close()
	case <-time.After(15 * time.Second):
		t.Fatal("host did not accept delayed join")
	}
}

func TestQUICLoopbackParallelTransfer(t *testing.T) {
	host, err := newPeer(true)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	join, err := newPeer(false)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Close()

	join.token = append([]byte(nil), host.token...)
	join.fingerprint = append([]byte(nil), host.fingerprint...)
	host.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, join), Type: "host"}})
	join.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, host), Type: "host"}})

	type connResult struct {
		conn net.Conn
		err  error
	}
	hostCh := make(chan connResult, 1)
	go func() {
		conn, err := host.acceptQUIC()
		hostCh <- connResult{conn: conn, err: err}
	}()

	joinConn, err := join.dialQUIC()
	if err != nil {
		t.Fatalf("join QUIC dial: %v", err)
	}
	hr := <-hostCh
	if hr.err != nil {
		_ = joinConn.Close()
		t.Fatalf("host QUIC accept: %v", hr.err)
	}
	hostConn := hr.conn

	authErr := make(chan error, 1)
	go func() { authErr <- authenticateListener(hostConn, host.token, roleHost) }()
	if err := authenticateDialer(joinConn, join.token, roleJoin); err != nil {
		t.Fatalf("dialer auth: %v", err)
	}
	if err := <-authErr; err != nil {
		t.Fatalf("listener auth: %v", err)
	}

	hostStripeCh := make(chan int, 1)
	go func() { hostStripeCh <- setupDataStripes(hostConn, host.token) }()
	joinStripes := setupDataStripes(joinConn, join.token)
	hostStripes := <-hostStripeCh
	if joinStripes != maxDataConnections-primaryDataStreams {
		t.Fatalf("join data stripes=%d want=%d", joinStripes, maxDataConnections-primaryDataStreams)
	}
	if hostStripes != maxDataConnections-primaryDataStreams {
		t.Fatalf("host data stripes=%d want=%d", hostStripes, maxDataConnections-primaryDataStreams)
	}
	if jc, ok := joinConn.(*rtcConn); !ok || jc.DataConnectionCount() != maxDataConnections {
		t.Fatalf("join data connections=%v", joinConn)
	}
	if hc, ok := hostConn.(*rtcConn); !ok || hc.DataConnectionCount() != maxDataConnections {
		t.Fatalf("host data connections=%v", hostConn)
	}
	jc := joinConn.(*rtcConn)
	ports := map[int]struct{}{}
	for _, qc := range jc.dataQUICs() {
		addr, ok := qc.LocalAddr().(*net.UDPAddr)
		if !ok || addr == nil {
			t.Fatalf("unexpected QUIC local addr: %T %v", qc.LocalAddr(), qc.LocalAddr())
		}
		ports[addr.Port] = struct{}{}
	}
	if len(ports) != maxDataConnections {
		t.Fatalf("data QUICs did not use distinct UDP source ports: %v", ports)
	}

	hostDir := t.TempDir()
	joinDir := t.TempDir()
	payload := bytes.Repeat([]byte("quic-parallel-payload-"), 180000)
	if err := os.WriteFile(filepath.Join(joinDir, "source.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	hs := initPeerSession(hostConn, "HOST", hostDir)
	js := initPeerSession(joinConn, "JOIN", joinDir)
	defer hs.close(false)
	defer js.close(false)
	go hs.readLoop()
	go js.readLoop()

	if st := dataState(js); st == nil || len(st.lanes) != parallelLanes {
		t.Fatalf("join QUIC data lanes = %#v", st)
	}
	if st := dataState(hs); st == nil || len(st.lanes) != parallelLanes {
		t.Fatalf("host QUIC data lanes = %#v", st)
	}
	if err := js.put("source.bin", "received.bin"); err != nil {
		t.Fatalf("QUIC put: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(hostDir, "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("QUIC payload mismatch")
	}
	wantHash, err := fileSHA256(filepath.Join(joinDir, "source.bin"))
	if err != nil {
		t.Fatal(err)
	}
	gotHash, err := fileSHA256(filepath.Join(hostDir, "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantHash, gotHash) {
		t.Fatalf("QUIC hash mismatch sender=%x receiver=%x", wantHash, gotHash)
	}
}

func TestLineEditorInitialPromptUsesSingleRow(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		out:    &out,
		active: true,
		prompt: "p2p[IPv4-NAT-PUNCH remote:/tmp]> ",
		line:   nil,
		cursor: 0,
		status: "",
	}
	e.mu.Lock()
	e.redrawLocked()
	e.mu.Unlock()
	got := out.String()
	if !strings.Contains(got, e.prompt) {
		t.Fatalf("initial redraw missing prompt: %q", got)
	}
	if strings.Contains(got, "\x1b[1E") || strings.Contains(got, "\x1b[1F") {
		t.Fatalf("initial redraw still touches a second row: %q", got)
	}
}

func TestInitPeerSessionStoresLinkMode(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	s := initPeerSession(left, "test", t.TempDir())
	defer s.close(false)
	if s.linkMode == "" {
		t.Fatal("session link mode is empty")
	}
	if prompt := shellPrompt(s); !strings.Contains(prompt, s.linkMode) {
		t.Fatalf("prompt %q does not contain link mode %q", prompt, s.linkMode)
	}
}

func TestSessionRejectsSecondConcurrentTransfer(t *testing.T) {
	aLocal := t.TempDir()
	bLocal := t.TempDir()

	large := bytes.Repeat([]byte("single-transfer-lease-"), 1024*512)
	if err := os.WriteFile(filepath.Join(bLocal, "large.bin"), large, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bLocal, "second.bin"), []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, b := newSessionPair(t, aLocal, bLocal, 3*time.Millisecond)
	defer a.close(false)
	defer b.close(false)

	done := make(chan error, 1)
	go func() {
		done <- a.get("large.bin", "download.bin")
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lease := a.leaseSnapshot(); lease.ID != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if lease := a.leaseSnapshot(); lease.ID == 0 {
		t.Fatal("first transfer never acquired the session lease")
	}

	err := b.put("second.bin", "should-not-start.bin")
	if err == nil || !strings.Contains(err.Error(), "当前已有传输任务") {
		t.Fatalf("second concurrent transfer error=%v, want busy rejection", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("first transfer failed: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("first transfer did not finish")
	}

	if lease := a.leaseSnapshot(); lease.ID != 0 {
		t.Fatalf("lease not released after transfer: %#v", lease)
	}

	if err := b.put("second.bin", "after.bin"); err != nil {
		t.Fatalf("transfer after lease release failed: %v", err)
	}
}

func TestTransferLeaseBusyShowsRemoteOwnerToCoordinator(t *testing.T) {
	s := &peerSession{transferCoordinator: true}
	resp := s.handleTransferAcquire(rpcRequest{
		LeaseID:      1,
		TransferKind: "GET",
		Path:         "siyuan-3.6.4-win.exe",
	})
	if !resp.OK {
		t.Fatalf("remote lease acquire failed: %s", resp.Error)
	}

	_, err := s.acquireTransferLease("GET", "1GB.bin")
	if err == nil {
		t.Fatal("expected busy lease error")
	}
	if !strings.Contains(err.Error(), "对端发起") || strings.Contains(err.Error(), "本机发起") {
		t.Fatalf("wrong coordinator-side owner perspective: %q", err)
	}
}

func TestTransferLeaseBusyFlipsOwnerForRemoteRequester(t *testing.T) {
	s := &peerSession{transferCoordinator: true}
	if err := s.tryAcquireTransferLease(1, "local", "PUT", "local.bin"); err != nil {
		t.Fatal(err)
	}

	resp := s.handleTransferAcquire(rpcRequest{
		LeaseID:      2,
		TransferKind: "GET",
		Path:         "remote.bin",
	})
	if resp.OK {
		t.Fatal("expected busy lease response")
	}
	if !strings.Contains(resp.Error, "对端发起") || strings.Contains(resp.Error, "本机发起") {
		t.Fatalf("wrong requester-side owner perspective: %q", resp.Error)
	}
}

func TestSilentProgressProducesNoOutput(t *testing.T) {
	var out bytes.Buffer
	restore := setConsoleWriter(&out)
	defer restore()

	p := &progress{
		Start: time.Now().Add(-time.Second),
		LastPrint: time.Time{},
		Done: 512,
		Total: 1024,
		Current: "file.bin",
		Prefix: "[SEND]",
		Silent: true,
	}
	p.print(false)
	p.print(true)
	p.closeLine()
	if got := out.String(); got != "" {
		t.Fatalf("silent progress wrote output: %q", got)
	}
}

func TestGracefulByeIsNotTransportError(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()

	s := initPeerSession(left, "A", t.TempDir())
	var out bytes.Buffer
	restore := setConsoleWriter(&out)
	defer restore()

	go s.readLoop()

	peer := &peerSession{
		conn:       right,
		br:         bufio.NewReader(right),
		bw:         bufio.NewWriter(right),
		closed:     make(chan struct{}),
		pendingRPC: make(map[uint64]chan rpcResponse),
		pendingGet: make(map[uint64]*pendingGet),
		outbound:   make(map[uint64]*outboundTransfer),
		inbound:    make(map[uint64]*inboundTransfer),
	}
	if err := peer.writeFrame(frameBye, 0, nil); err != nil {
		t.Fatal(err)
	}

	select {
	case <-s.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not close after graceful bye")
	}
	got := out.String()
	if !strings.Contains(got, "对方已正常结束会话") {
		t.Fatalf("missing graceful close message: %q", got)
	}
	if strings.Contains(got, "异常") {
		t.Fatalf("graceful close reported as error: %q", got)
	}
}

func TestQUICApplicationCodeZeroIsExpectedClose(t *testing.T) {
	err := &quic.ApplicationError{
		ErrorCode:    0,
		ErrorMessage: "normal shutdown",
		Remote:       true,
	}
	if !isClosedErr(err) {
		t.Fatalf("QUIC application close code 0 should be treated as graceful: %v", err)
	}
}

func TestRemoteQUICCloseShowsPeerExitNotice(t *testing.T) {
	var out bytes.Buffer
	restore := setConsoleWriter(&out)
	defer restore()

	s := &peerSession{}
	s.handleReadError(&quic.ApplicationError{
		ErrorCode:    0,
		ErrorMessage: "normal shutdown",
		Remote:       true,
	})

	if !s.remoteBye.Load() {
		t.Fatal("remote graceful close did not mark remoteBye")
	}
	if !s.closing.Load() {
		t.Fatal("remote graceful close did not mark session closing")
	}
	if got := out.String(); !strings.Contains(got, "对方已正常结束会话") {
		t.Fatalf("missing peer graceful close notice: %q", got)
	}
}

func TestLocalQUICCloseDoesNotClaimPeerExit(t *testing.T) {
	var out bytes.Buffer
	restore := setConsoleWriter(&out)
	defer restore()

	s := &peerSession{}
	s.handleReadError(&quic.ApplicationError{
		ErrorCode:    0,
		ErrorMessage: "normal shutdown",
		Remote:       false,
	})

	if s.remoteBye.Load() {
		t.Fatal("local graceful close was misclassified as remote exit")
	}
	if strings.Contains(out.String(), "对方已正常结束会话") {
		t.Fatalf("local close printed peer exit notice: %q", out.String())
	}
}

func TestShutdownRemovesPartialReceive(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	s := initPeerSession(left, "A", t.TempDir())

	tmp, err := os.CreateTemp(t.TempDir(), ".p2p-friend-*.part")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}

	tr := &inboundTransfer{
		id:          42,
		currentFile: tmp,
		currentTemp: tmpPath,
		progress:    &progress{Silent: true},
	}
	s.transferMu.Lock()
	s.inbound[42] = tr
	s.transferMu.Unlock()

	s.cleanupTransfersForShutdown()
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("partial file still exists after shutdown: %v", err)
	}
}

func TestSignalCodePrefixesIdentifyRoles(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
	invite := signalCode{
		Version: signalEnvelopeVersion, Kind: "connect", Token: token,
		Candidates:  []signalCandidate{{Addr: "192.0.2.1:41001", Type: "host"}},
		Fingerprint: strings.Repeat("cd", 32),
	}
	inviteCode, err := encodeSignal(invite)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(inviteCode, signalInvitePrefix) {
		t.Fatalf("invite prefix=%q", inviteCode)
	}
	if _, err := decodeSignal(inviteCode, "confirm"); err == nil || !strings.Contains(err.Error(), "P2PF-INVITE") {
		t.Fatalf("wrong-role INVITE code should be explained, got %v", err)
	}

	rawToken, _ := base64.RawURLEncoding.DecodeString(token)
	reply := signalCode{
		Version: signalEnvelopeVersion, Kind: "confirm",
		SessionBinding: base64.RawURLEncoding.EncodeToString(makeSignalBinding(rawToken)),
		Candidates:  []signalCandidate{{Addr: "198.51.100.2:42002", Type: "srflx"}},
		Fingerprint: strings.Repeat("dc", 32),
	}
	replyCode, err := encodeSignal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(replyCode, signalReplyPrefix) {
		t.Fatalf("reply prefix=%q", replyCode)
	}
	if len(replyCode) >= 160 {
		t.Fatalf("compact REPLY unexpectedly long: %d chars: %s", len(replyCode), replyCode)
	}
	if _, err := decodeSignal(replyCode, "connect"); err == nil || !strings.Contains(err.Error(), "P2PF-REPLY") {
		t.Fatalf("wrong-role REPLY code should be explained, got %v", err)
	}
}

func TestSignalCandidateDeduplication(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	in := signalCode{
		Version: signalEnvelopeVersion, Kind: "connect", Token: token,
		Fingerprint: strings.Repeat("ef", 32),
		Candidates: []signalCandidate{
			{Addr: "203.0.113.9:45678", Type: "srflx"},
			{Addr: "203.0.113.9:45678", Type: "host"},
			{Addr: "[2001:db8::9]:45679", Type: "host"},
		},
	}
	code, err := encodeSignal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeSignal(code, "connect")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Candidates) != 2 {
		t.Fatalf("dedup candidate count=%d, want 2: %#v", len(out.Candidates), out.Candidates)
	}
	for _, cand := range out.Candidates {
		if cand.Addr == "203.0.113.9:45678" && cand.Type != "host" {
			t.Fatalf("duplicate endpoint should prefer host candidate: %#v", cand)
		}
	}
}

func TestQUICCanConnectWithCreateCodeOnly(t *testing.T) {
	host, err := newPeer(true)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	join, err := newPeer(false)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Close()

	join.token = append([]byte(nil), host.token...)
	join.fingerprint = append([]byte(nil), host.fingerprint...)
	join.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, host), Type: "host"}})
	// Deliberately do not give the creator any join-side candidate.
	// A directly reachable creator must be able to accept the incoming QUIC handshake.

	type result struct {
		conn net.Conn
		err  error
	}
	hostCh := make(chan result, 1)
	joinCh := make(chan result, 1)
	go func() {
		conn, err := host.acceptQUIC()
		hostCh <- result{conn: conn, err: err}
	}()
	go func() {
		conn, err := join.dialQUIC()
		joinCh <- result{conn: conn, err: err}
	}()

	var hc, jc net.Conn
	select {
	case r := <-hostCh:
		if r.err != nil {
			t.Fatal(r.err)
		}
		hc = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("creator did not accept one-code direct QUIC")
	}
	select {
	case r := <-joinCh:
		if r.err != nil {
			t.Fatal(r.err)
		}
		jc = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("joiner did not establish one-code direct QUIC")
	}
	_ = hc.Close()
	_ = jc.Close()
}

func TestDeterministicInviteReplyHandshake(t *testing.T) {
	host, invite, err := createConnectionCode()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	join, reply, token, err := createJoinConfirmation(invite)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Close()

	if !strings.HasPrefix(invite, signalInvitePrefix) {
		t.Fatalf("invite prefix=%q", invite)
	}
	if !strings.HasPrefix(reply, signalReplyPrefix) {
		t.Fatalf("reply prefix=%q", reply)
	}
	if err := host.applyConfirmation(reply); err != nil {
		t.Fatalf("apply reply: %v", err)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	hostCh := make(chan result, 1)
	joinCh := make(chan result, 1)
	go func() {
		conn, err := host.acceptQUIC()
		hostCh <- result{conn: conn, err: err}
	}()
	go func() {
		conn, err := join.waitConn()
		joinCh <- result{conn: conn, err: err}
	}()

	var hc, jc net.Conn
	select {
	case r := <-hostCh:
		if r.err != nil {
			t.Fatalf("creator accept failed: %v", r.err)
		}
		hc = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("creator accept timed out")
	}
	select {
	case r := <-joinCh:
		if r.err != nil {
			t.Fatalf("join dial failed: %v", r.err)
		}
		jc = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("join dial timed out")
	}
	defer hc.Close()
	defer jc.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- authenticateListener(hc, token, roleHost) }()
	if err := authenticateDialer(jc, token, roleJoin); err != nil {
		t.Fatalf("join auth failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("creator auth failed: %v", err)
	}
}


func TestSignalPortmapCandidateRoundTrip(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	rawToken, _ := base64.RawURLEncoding.DecodeString(token)
	in := signalCode{
		Version: signalEnvelopeVersion,
		Kind: "confirm",
		SessionBinding: base64.RawURLEncoding.EncodeToString(makeSignalBinding(rawToken)),
		Fingerprint: strings.Repeat("12", 32),
		Candidates: []signalCandidate{
			{Addr: "198.51.100.20:45670", Type: "portmap"},
			{Addr: "203.0.113.20:45671", Type: "srflx"},
		},
	}
	code, err := encodeSignal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeSignal(code, "confirm")
	if err != nil {
		t.Fatal(err)
	}
	if out.Fingerprint != in.Fingerprint {
		t.Fatalf("fingerprint=%q want=%q", out.Fingerprint, in.Fingerprint)
	}
	found := false
	for _, cand := range out.Candidates {
		if cand.Type == "portmap" && cand.Addr == "198.51.100.20:45670" {
			found = true
		}
	}
	if !found {
		t.Fatalf("portmap candidate missing: %#v", out.Candidates)
	}
}

func TestAuthenticatedPunchRejectsTamperAndReplay(t *testing.T) {
	host, err := newPeer(true)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	join, err := newPeer(false)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Close()
	join.token = append([]byte(nil), host.token...)

	pkt, err := buildPunchPacket(host)
	if err != nil {
		t.Fatal(err)
	}
	if !join.verifyPunchPacket(pkt) {
		t.Fatal("valid authenticated punch was rejected")
	}
	if join.verifyPunchPacket(pkt) {
		t.Fatal("replayed punch nonce was accepted")
	}

	tampered, err := buildPunchPacket(host)
	if err != nil {
		t.Fatal(err)
	}
	tampered[len(tampered)-1] ^= 0x01
	if join.verifyPunchPacket(tampered) {
		t.Fatal("tampered punch HMAC was accepted")
	}
}

func TestPeerReflexiveCandidateDeduplication(t *testing.T) {
	p := &rtcPeer{}
	c := signalCandidate{Addr: "198.51.100.44:50000", Type: "prflx"}
	if !p.addRemoteCandidate(c) {
		t.Fatal("first prflx candidate was not added")
	}
	if p.addRemoteCandidate(c) {
		t.Fatal("duplicate prflx candidate was added twice")
	}
	if got := p.remoteCandidates(); len(got) != 1 || got[0].Type != "prflx" {
		t.Fatalf("unexpected candidates: %#v", got)
	}
}


func TestBidirectionalQUICRaceKeepsWinnerAlive(t *testing.T) {
	host, err := newPeer(true)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	join, err := newPeer(false)
	if err != nil {
		t.Fatal(err)
	}
	defer join.Close()

	join.token = append([]byte(nil), host.token...)
	host.remoteFingerprint = append([]byte(nil), join.localFingerprint...)
	join.remoteFingerprint = append([]byte(nil), host.localFingerprint...)
	host.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, join), Type: "host"}})
	join.setRemoteCandidates([]signalCandidate{{Addr: ipv4EndpointAddr(t, host), Type: "host"}})

	type result struct {
		conn net.Conn
		err  error
	}
	hostCh := make(chan result, 1)
	joinCh := make(chan result, 1)
	go func() {
		conn, err := host.connectQUIC()
		hostCh <- result{conn: conn, err: err}
	}()
	go func() {
		conn, err := join.connectQUIC()
		joinCh <- result{conn: conn, err: err}
	}()

	var hc, jc net.Conn
	select {
	case r := <-hostCh:
		if r.err != nil {
			t.Fatalf("host connectQUIC failed: %v", r.err)
		}
		hc = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("host connectQUIC timed out")
	}
	select {
	case r := <-joinCh:
		if r.err != nil {
			t.Fatalf("join connectQUIC failed: %v", r.err)
		}
		jc = r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("join connectQUIC timed out")
	}
	defer hc.Close()
	defer jc.Close()

	// Give late race losers enough time to be discarded. A loser cleanup must not
	// close the shared transport used by the selected winner.
	time.Sleep(pathPreferenceWindow + 200*time.Millisecond)

	hostAuth := make(chan error, 1)
	go func() { hostAuth <- authenticatePeerConn(hc, host.token, roleHost) }()
	if err := authenticatePeerConn(jc, join.token, roleJoin); err != nil {
		t.Fatalf("join auth failed after path race settled: %v", err)
	}
	if err := <-hostAuth; err != nil {
		t.Fatalf("host auth failed after path race settled: %v", err)
	}

	if _, err := jc.Write([]byte("ping")); err != nil {
		t.Fatalf("winner write failed after loser cleanup: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(hc, buf); err != nil {
		t.Fatalf("winner read failed after loser cleanup: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("winner payload=%q want ping", string(buf))
	}
}

func TestCandidateDialDelayPrefersLANBeforeFallbacks(t *testing.T) {
	// Loopback is deliberately not considered a usable candidate, so use a
	// synthetic private address only to verify fallback ordering.
	srflx := candidateDialDelay(
		signalCandidate{Addr: "198.51.100.10:50000", Type: "srflx"},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 50000},
	)
	portmap := candidateDialDelay(
		signalCandidate{Addr: "198.51.100.11:50001", Type: "portmap"},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.11"), Port: 50001},
	)
	prflx := candidateDialDelay(
		signalCandidate{Addr: "198.51.100.12:50002", Type: "prflx"},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.12"), Port: 50002},
	)
	if !(prflx < portmap && portmap < srflx) {
		t.Fatalf("unexpected fallback delays: prflx=%v portmap=%v srflx=%v", prflx, portmap, srflx)
	}
}


func TestInboundPipelineReordersBeforeSequentialWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reorder.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	chunk := maxDataChunkSize
	size := int64(3 * chunk)
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}

	session := &peerSession{}
	in := &inboundTransfer{
		currentFile:      file,
		currentRemaining: size,
		progress:         &progress{Silent: true, Total: size},
	}
	st := startInboundData(session, 1, in, size, file)

	expected := make([]byte, size)
	for block := 0; block < 3; block++ {
		for i := 0; i < chunk; i++ {
			expected[block*chunk+i] = byte(0x31 + block)
		}
	}

	for _, block := range []int{2, 0, 1} {
		buf := acquireDataBuffer()
		copy(buf[dataHeaderSize:dataHeaderSize+chunk], expected[block*chunk:(block+1)*chunk])
		if !st.enqueue(inboundDataChunk{
			buf:        buf,
			offset:     int64(block * chunk),
			payloadLen: chunk,
		}) {
			releaseDataBuffer(buf)
			t.Fatal("pipeline rejected valid out-of-order chunk")
		}
	}

	select {
	case <-st.done:
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not finish")
	}
	written, sum, err := st.result()
	if err != nil {
		t.Fatal(err)
	}
	if written != size {
		t.Fatalf("written=%d want=%d", written, size)
	}
	clearInboundData(in)
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("reordered pipeline did not produce sequential file contents")
	}
	wantSum, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sum, wantSum) {
		t.Fatalf("pipeline hash=%x want=%x", sum, wantSum)
	}
}

func TestFastTransferProfileUsesBoundedOneMiBChunks(t *testing.T) {
	p := fastTransferProfile(parallelLanes)
	if p.chunkSize != 1024*1024 {
		t.Fatalf("chunk size=%d want=%d", p.chunkSize, 1024*1024)
	}
	if p.lanes != parallelLanes {
		t.Fatalf("lanes=%d want=%d", p.lanes, parallelLanes)
	}
	if p.pace != 0 {
		t.Fatalf("unexpected artificial pacing: %v", p.pace)
	}
	if got := parallelLanes * sendQueueDepthPerLane * maxDataChunkSize; got > 128*1024*1024 {
		t.Fatalf("pipeline user-space buffer budget too large: %d", got)
	}
}


func TestDirectoryProgressShowsCurrentFileAndTotal(t *testing.T) {
	var out bytes.Buffer
	restore := setConsoleWriter(&out)
	defer restore()

	p := &progress{
		Start:       time.Now().Add(-time.Second),
		LastPrint:   time.Time{},
		Done:        5 * 1024 * 1024,
		Total:       20 * 1024 * 1024,
		Current:     "dir/current.bin",
		CurrentDone: 3 * 1024 * 1024,
		CurrentSize: 4 * 1024 * 1024,
		Prefix:      "[GET]",
		Multi:       true,
	}
	p.print(false)
	got := out.String()
	if !strings.Contains(got, "75.00%") || !strings.Contains(got, "3.0 MiB / 4.0 MiB") {
		t.Fatalf("missing current-file progress: %q", got)
	}
	if !strings.Contains(got, "总计") || !strings.Contains(got, "25.00%") || !strings.Contains(got, "5.0 MiB / 20.0 MiB") {
		t.Fatalf("missing directory-total progress: %q", got)
	}
}


func TestReceiveWindowScalesButStaysBounded(t *testing.T) {
	cases := []struct {
		size int64
		want int
	}{
		{64 * 1024 * 1024, minReceiveWindowChunks},
		{512 * 1024 * 1024, midReceiveWindowChunks},
		{2 * 1024 * 1024 * 1024, maxReceiveWindowChunks},
		{100 * 1024 * 1024 * 1024, maxReceiveWindowChunks},
	}
	for _, tc := range cases {
		if got := receiveWindowChunks(tc.size); got != tc.want {
			t.Fatalf("receiveWindowChunks(%d)=%d want=%d", tc.size, got, tc.want)
		}
	}
	if maxReceiveWindowChunks*maxDataChunkSize > 256*1024*1024 {
		t.Fatalf("receive reorder window exceeds 256 MiB: %d", maxReceiveWindowChunks*maxDataChunkSize)
	}
}


func TestIPInSameSubnet(t *testing.T) {
	_, v4net, err := net.ParseCIDR("192.168.1.6/24")
	if err != nil {
		t.Fatal(err)
	}
	v4net.IP = net.ParseIP("192.168.1.6")
	_, v6net, err := net.ParseCIDR("240e:399:e80:3340::1/64")
	if err != nil {
		t.Fatal(err)
	}
	v6net.IP = net.ParseIP("240e:399:e80:3340::1")

	nets := []*net.IPNet{v4net, v6net}
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.100", true},
		{"192.168.2.100", false},
		{"118.112.118.32", false},
		{"240e:399:e80:3340:c218:50ff:fece:85dd", true},
		{"240e:399:e80:3341::2", false},
	}
	for _, tc := range cases {
		if got := ipInSameSubnet(net.ParseIP(tc.ip), nets); got != tc.want {
			t.Fatalf("ipInSameSubnet(%s)=%v want=%v", tc.ip, got, tc.want)
		}
	}
}

func TestSameSubnetHostCandidateDetection(t *testing.T) {
	_, localNet, err := net.ParseCIDR("192.168.1.6/24")
	if err != nil {
		t.Fatal(err)
	}
	localNet.IP = net.ParseIP("192.168.1.6")
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54731}
	if !strings.EqualFold(signalCandidate{Addr: addr.String(), Type: "host"}.Type, "host") {
		t.Fatal("host candidate type setup failed")
	}
	if !ipInSameSubnet(addr.IP, []*net.IPNet{localNet}) {
		t.Fatal("same-subnet HOST candidate was not recognized")
	}
	if ipInSameSubnet(net.ParseIP("118.112.118.32"), []*net.IPNet{localNet}) {
		t.Fatal("public srflx address incorrectly recognized as LAN")
	}
}


func TestStableSignalCarriesHostPrefixAndCapabilities(t *testing.T) {
	token := bytes.Repeat([]byte{0x51}, 32)
	in := signalCode{
		Version:      signalEnvelopeVersion,
		Capabilities: signalCapabilitiesCurrent,
		Kind:         "connect",
		Token:        base64.RawURLEncoding.EncodeToString(token),
		Fingerprint:  strings.Repeat("34", 32),
		Candidates: []signalCandidate{
			{Addr: "192.168.1.6:50000", Type: "host", PrefixKnown: true, PrefixBits: 24},
			{Addr: "[2001:db8:1::6]:50001", Type: "host", PrefixKnown: true, PrefixBits: 64},
			{Addr: "203.0.113.6:40000", Type: "srflx"},
		},
	}
	code, err := encodeSignal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeSignal(code, "connect")
	if err != nil {
		t.Fatal(err)
	}
	if out.Capabilities != signalCapabilitiesCurrent {
		t.Fatalf("capabilities=%x want=%x", out.Capabilities, signalCapabilitiesCurrent)
	}
	foundV4, foundV6 := false, false
	for _, cand := range out.Candidates {
		if cand.Addr == "192.168.1.6:50000" {
			foundV4 = cand.PrefixKnown && cand.PrefixBits == 24
		}
		if cand.Addr == "[2001:db8:1::6]:50001" {
			foundV6 = cand.PrefixKnown && cand.PrefixBits == 64
		}
	}
	if !foundV4 || !foundV6 {
		t.Fatalf("host prefixes were not preserved: %#v", out.Candidates)
	}
}

func TestMutualLANRequiresBothPrefixesToAgree(t *testing.T) {
	a := signalCandidate{Addr: "192.168.1.6:5000", Type: "host", PrefixKnown: true, PrefixBits: 24}
	b := signalCandidate{Addr: "192.168.1.100:6000", Type: "host", PrefixKnown: true, PrefixBits: 24}
	if !candidatesShareLAN(a, b) {
		t.Fatal("same /24 HOST candidates should be mutual LAN")
	}
	c := signalCandidate{Addr: "192.168.2.100:6000", Type: "host", PrefixKnown: true, PrefixBits: 24}
	if candidatesShareLAN(a, c) {
		t.Fatal("different /24 HOST candidates must not be treated as LAN")
	}
	d := signalCandidate{Addr: "192.168.1.100:6000", Type: "host"}
	if candidatesShareLAN(a, d) {
		t.Fatal("missing remote prefix must not force strict LAN mode")
	}
}

func TestReplySignalIsShorterThanInvite(t *testing.T) {
	token := bytes.Repeat([]byte{0x52}, 32)
	commonCandidates := []signalCandidate{
		{Addr: "192.168.1.6:5000", Type: "host", PrefixKnown: true, PrefixBits: 24},
		{Addr: "203.0.113.6:40000", Type: "srflx"},
	}
	invite, err := encodeSignal(signalCode{
		Version: signalEnvelopeVersion, Capabilities: signalCapabilitiesCurrent, Kind: "connect",
		Token: base64.RawURLEncoding.EncodeToString(token),
		Fingerprint: strings.Repeat("56", 32), Candidates: commonCandidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := encodeSignal(signalCode{
		Version: signalEnvelopeVersion, Capabilities: signalCapabilitiesCurrent, Kind: "confirm",
		SessionBinding: base64.RawURLEncoding.EncodeToString(makeSignalBinding(token)),
		Fingerprint: strings.Repeat("78", 32), Candidates: commonCandidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) >= len(invite) {
		t.Fatalf("reply should be shorter than invite: reply=%d invite=%d", len(reply), len(invite))
	}
}
