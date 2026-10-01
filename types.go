package main

import (
	"bufio"
	"net"
	"os"
	"sync"
	"time"
)

var appVersion = "dev"

const (
	protocolMagic   = "P2PF3"
	protocolVersion = 3
	defaultPort     = "5000"

	roleHost = byte(1)
	roleJoin = byte(2)

	msgTransfer   = byte(1)
	msgGetRequest = byte(2)
	msgError      = byte(3)
	msgBye        = byte(4)

	recordDir  = byte(1)
	recordFile = byte(2)
	recordEnd  = byte(3)

	copyBufferSize = 1024 * 1024
	maxPathBytes   = 1024 * 1024
	maxTextBytes   = 1024 * 1024
)

var consoleMu sync.Mutex

type connectCode struct {
	Version     int    `json:"v"`
	Address     string `json:"a"`
	Token       string `json:"t"`
	Fingerprint string `json:"f"`
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

type peerSession struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	writeMu   sync.Mutex
	stateMu   sync.RWMutex
	cwd       string
	overwrite bool

	roleName  string
	closed    chan struct{}
	closeOnce sync.Once
}
