//go:build linux || darwin

package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func consoleInputReady(timeout time.Duration) bool {
	ms := int(timeout / time.Millisecond)
	if ms < 0 {
		ms = -1
	}
	fds := []unix.PollFd{{Fd: int32(os.Stdin.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, ms)
	return err == nil && n > 0 && fds[0].Revents&unix.POLLIN != 0
}
