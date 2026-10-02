package main

import (
	"bufio"
	"context"
	"hash"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var appVersion = "dev"

const (
	protocolMagic   = "P2PF7"
	protocolVersion = 7

	roleHost = byte(1)
	roleJoin = byte(2)

	frameRPCRequest     = byte(1)
	frameRPCResponse    = byte(2)
	frameTransferStart  = byte(3)
	frameEntryStart     = byte(4)
	frameData           = byte(5)
	frameEntryEnd       = byte(6)
	frameTransferEnd    = byte(7)
	frameCancel         = byte(8)
	frameTransferResult = byte(9)
	frameBye            = byte(10)

	chunkSize       = 256 * 1024
	maxFramePayload = 16 * 1024 * 1024
)

type wireFrame struct {
	Type    byte
	ID      uint64
	Payload []byte
}

type rpcRequest struct {
	Op   string `json:"op"`
	Path string `json:"path,omitempty"`
}

type rpcResponse struct {
	OK         bool          `json:"ok"`
	Error      string        `json:"error,omitempty"`
	Cwd        string        `json:"cwd,omitempty"`
	Entries    []remoteEntry `json:"entries,omitempty"`
	TransferID uint64        `json:"transfer_id,omitempty"`
	Name       string        `json:"name,omitempty"`
}

type remoteEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

type transferStart struct {
	Name      string `json:"name"`
	Dest      string `json:"dest,omitempty"`
	Total     int64  `json:"total"`
	IsDir     bool   `json:"is_dir"`
	RequestID uint64 `json:"request_id,omitempty"`
}

type entryStart struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Size int64  `json:"size"`
	Dir  bool   `json:"dir"`
}

type transferEnd struct {
	Cancelled bool   `json:"cancelled,omitempty"`
	Error     string `json:"error,omitempty"`
}

type transferResult struct {
	OK        bool   `json:"ok"`
	Cancelled bool   `json:"cancelled,omitempty"`
	Error     string `json:"error,omitempty"`
}

type sendEntry struct {
	FullPath string
	RelPath  string
	Mode     os.FileMode
	Size     int64
	IsDir    bool
}

type progress struct {
	Start       time.Time
	LastPrint   time.Time
	Done        int64
	Total       int64
	Current     string
	CurrentDone int64
	CurrentSize int64
	Prefix      string
}

type pendingGet struct {
	dest string
	done chan error
}

type outboundTransfer struct {
	id     uint64
	ctx    context.Context
	cancel context.CancelCauseFunc
	result chan transferResult
	done   chan error
}

type inboundTransfer struct {
	mu         sync.Mutex
	id         uint64
	meta       transferStart
	targetRoot string
	cancelled  bool
	cancelWhy  string

	currentPath      string
	currentFile      *os.File
	currentTemp      string
	currentHash      hash.Hash
	currentRemaining int64
	currentMode      os.FileMode

	progress *progress
	getReqID uint64

	createdFiles []string
	createdDirs  []string
	overwritten  []string
}

type foregroundTransfer struct {
	direction string
	id        uint64
}

type peerSession struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	writeMu          sync.Mutex
	closed           chan struct{}
	closeOnce        sync.Once
	transportErrOnce sync.Once

	requestSeq  atomic.Uint64
	transferSeq atomic.Uint64

	pendingMu  sync.Mutex
	pendingRPC map[uint64]chan rpcResponse
	pendingGet map[uint64]*pendingGet

	transferMu sync.Mutex
	outbound   map[uint64]*outboundTransfer
	inbound    map[uint64]*inboundTransfer
	sendGate   sync.Mutex

	localMu      sync.RWMutex
	localCwd     string
	localPrevCwd string

	serveMu      sync.RWMutex
	serveCwd     string
	servePrevCwd string

	remoteMu  sync.RWMutex
	remoteCwd string

	stateMu   sync.RWMutex
	overwrite bool

	fgMu       sync.Mutex
	foreground foregroundTransfer

	roleName string
}

var consoleMu sync.Mutex
