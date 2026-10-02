package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSignalCodeRoundTrip(t *testing.T) {
	in := signalCode{
		Version: signalVersion,
		Kind: "offer",
		Token: "abc",
		Candidates: []string{"[2001:db8::1]:5000", "203.0.113.1:40000"},
		Fingerprint: strings.Repeat("ab", 32),
	}
	s, err := encodeSignal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, signalPrefixOffer) {
		t.Fatalf("unexpected code prefix: %s", s)
	}
	out, err := decodeSignal(s, "offer")
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
	host.remote = []string{ipv4EndpointAddr(t, join)}
	join.remote = []string{ipv4EndpointAddr(t, host)}

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
