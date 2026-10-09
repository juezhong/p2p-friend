package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"
)

// 本文件仅在显式启用性能测试时才生成 2 GiB 文件，普通 go test 不会占用大量磁盘。
type perfTransfer struct {
	Direction string `json:"direction"`
	Seconds float64 `json:"seconds"`
	MiBPerSecond float64 `json:"mib_per_second"`
	AllocatedMiB float64 `json:"allocated_mib"`
	NumGC uint32 `json:"num_gc"`
	SHA256 string `json:"destination_sha256"`
}

type perfReport struct {
	OS string `json:"os"`
	Arch string `json:"arch"`
	GoVersion string `json:"go_version"`
	Runner string `json:"runner"`
	Commit string `json:"commit"`
	CPUs int `json:"cpus"`
	Mode string `json:"mode"`
	BytesPerTransfer int64 `json:"bytes_per_transfer"`
	DataConnections int `json:"data_connections"`
	GenerationSeconds float64 `json:"generation_seconds"`
	SourceSHA256 string `json:"source_sha256"`
	Transfers []perfTransfer `json:"transfers"`
}

func TestPerfQUIC2GiBLoopback(t *testing.T) {
	if os.Getenv("P2PF_PERF_TEST") != "1" {
		t.Skip("opt-in: P2PF_PERF_TEST=1")
	}
	size := int64(2 << 30)
	if raw := os.Getenv("P2PF_PERF_BYTES"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v <= 0 {
			t.Fatalf("invalid P2PF_PERF_BYTES=%q", raw)
		}
		size = v
	}
	// 输出前置元数据：即使长传输超时，CI 日志也能记录测试规模和平台。
	t.Logf("P2PF_PERF_START os=%s arch=%s go=%s bytes=%d cpus=%d", runtime.GOOS, runtime.GOARCH, runtime.Version(), size, runtime.NumCPU())
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
	host.setRemoteCapabilities(signalCapabilitiesCurrent)
	join.setRemoteCapabilities(signalCapabilitiesCurrent)

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

	if hc := hostConn.(*rtcConn); len(hc.lanes) != 0 {
		t.Fatalf("v0.16 primary host QUIC unexpectedly has %d data streams", len(hc.lanes))
	}
	if jc := joinConn.(*rtcConn); len(jc.lanes) != 0 {
		t.Fatalf("v0.16 primary join QUIC unexpectedly has %d data streams", len(jc.lanes))
	}

	setupDataStripes(hostConn, host.token)
	setupDataStripes(joinConn, join.token)

	waitDataLanes := func(name string, rc *rtcConn) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if rc.DataConnectionCount() == resilientDataLanes {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s data connections=%d want=%d", name, rc.DataConnectionCount(), resilientDataLanes)
	}
	waitDataLanes("join", joinConn.(*rtcConn))
	waitDataLanes("host", hostConn.(*rtcConn))
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

	generationStarted := time.Now()
	sourceFile := filepath.Join(joinDir, "source.bin")
	expectedHash, err := perfGenerateSource(sourceFile, size)
	if err != nil {
		t.Fatal(err)
	}
	generationSeconds := time.Since(generationStarted).Seconds()

	hs := initPeerSession(hostConn, "HOST", hostDir)
	js := initPeerSession(joinConn, "JOIN", joinDir)
	defer hs.close(false)
	defer js.close(false)
	go hs.readLoop()
	go js.readLoop()

	if dataState(js) != nil || dataState(hs) != nil {
		t.Fatal("v0.16 must not attach legacy primary data lanes")
	}
	if st := resilientStripeStateFor(joinConn.(*rtcConn)); st == nil || st.count() != resilientDataLanes {
		t.Fatalf("join resilient data lanes=%v", st)
	}
	if st := resilientStripeStateFor(hostConn.(*rtcConn)); st == nil || st.count() != resilientDataLanes {
		t.Fatalf("host resilient data lanes=%v", st)
	}

	report := perfReport{
		OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(),
		Runner: os.Getenv("RUNNER_NAME"), Commit: os.Getenv("GITHUB_SHA"),
		CPUs: runtime.NumCPU(), Mode: "same-machine-udp-loopback",
		BytesPerTransfer: size, DataConnections: jc.DataConnectionCount(),
		GenerationSeconds: generationSeconds, SourceSHA256: hex.EncodeToString(expectedHash),
	}
	put := perfTimeTransfer(t, "put", size, func() error {
		return js.put("source.bin", "received.bin")
	})
	put.SHA256 = perfVerifyDestination(t, filepath.Join(hostDir, "received.bin"), size, expectedHash)
	report.Transfers = append(report.Transfers, put)

	// 丢弃发送端原始文件，保证第二次传输时不会积累超过 4 GiB 文件数据。
	if err := os.Remove(sourceFile); err != nil {
		t.Fatal(err)
	}
	get := perfTimeTransfer(t, "get", size, func() error {
		return js.get("received.bin", "download.bin")
	})
	get.SHA256 = perfVerifyDestination(t, filepath.Join(joinDir, "download.bin"), size, expectedHash)
	report.Transfers = append(report.Transfers, get)
	if _, err := js.remotePwd(); err != nil {
		t.Fatalf("control channel failed after PUT/GET: %v", err)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("P2PF_PERF_RESULT\n%s", encoded)
	if dir := os.Getenv("P2PF_PERF_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "result.json"), encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// 使用可重复的伪随机数据分块写入文件，避免在内存里构造 2 GiB payload。
func perfGenerateSource(path string, size int64) ([]byte, error) {
	f, err := os.Create(path)
	if err != nil { return nil, err }
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	state := uint64(0x9e3779b97f4a7c15)
	for remaining := size; remaining > 0; {
		for i := 0; i < len(buf); i += 8 {
			state ^= state >> 12
			state ^= state << 25
			state ^= state >> 27
			binary.LittleEndian.PutUint64(buf[i:i+8], state*2685821657736338717)
		}
		n := int64(len(buf))
		if n > remaining { n = remaining }
		written, err := f.Write(buf[:int(n)])
		if err != nil { return nil, err }
		if written != int(n) { return nil, fmt.Errorf("short write: %d of %d", written, n) }
		if _, err := h.Write(buf[:int(n)]); err != nil { return nil, err }
		remaining -= n
	}
	if err := f.Close(); err != nil { return nil, err }
	return h.Sum(nil), nil
}

func perfVerifyDestination(t *testing.T, path string, size int64, want []byte) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Size() != size {
		t.Fatalf("size mismatch: %s got=%d want=%d", path, info.Size(), size)
	}
	got, err := fileSHA256(path)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, want) {
		t.Fatalf("SHA-256 mismatch: %s got=%x want=%x", path, got, want)
	}
	return hex.EncodeToString(got)
}

func perfTimeTransfer(t *testing.T, direction string, size int64, fn func() error) perfTransfer {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var profile *os.File
	if dir := os.Getenv("P2PF_PERF_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil { t.Fatal(err) }
		var err error
		profile, err = os.Create(filepath.Join(dir, direction+".cpu.pprof"))
		if err != nil { t.Fatal(err) }
		if err := pprof.StartCPUProfile(profile); err != nil { t.Fatal(err) }
	}
	started := time.Now()
	err := fn()
	elapsed := time.Since(started)
	if profile != nil {
		pprof.StopCPUProfile()
		_ = profile.Close()
	}
	if err != nil { t.Fatalf("%s transfer failed: %v", direction, err) }
	runtime.ReadMemStats(&after)
	result := perfTransfer{
		Direction: direction,
		Seconds: elapsed.Seconds(),
		MiBPerSecond: float64(size)/(1024*1024)/elapsed.Seconds(),
		AllocatedMiB: float64(after.TotalAlloc-before.TotalAlloc)/(1024*1024),
		NumGC: after.NumGC-before.NumGC,
	}
	t.Logf("P2PF_PERF %s: %.2f MiB/s; %.3fs; Go allocations %.1f MiB; GC %d",
		direction, result.MiBPerSecond, result.Seconds, result.AllocatedMiB, result.NumGC)
	return result
}

func TestResilientSlidingCancellationDoesNotWaitForUnavailableLane(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	managerCtx, managerCancel := context.WithCancel(context.Background())
	defer managerCancel()
	manager := &resilientStripeState{
		ctx: managerCtx,
		notify: make(chan struct{}, 1),
		slots: make(map[int]*managedDataLane),
	}
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x5a}, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &peerSession{
		closed: make(chan struct{}),
		pendingAck: make(map[uint64]*transferAckState),
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.sendFileResilientSliding(ctx, manager, 1, 1, path, 1<<20, &progress{Silent: true})
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sendFileResilientSliding failed to stop after context cancellation")
	}
}
