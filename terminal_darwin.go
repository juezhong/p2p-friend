//go:build darwin

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type terminalState struct {
	termios syscall.Termios
}

func enterTerminalRaw() (*terminalState, error) {
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	if err := ioctlTermios(fd, syscall.TIOCGETA, &old); err != nil {
		return nil, err
	}
	raw := old
	raw.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := ioctlTermios(fd, syscall.TIOCSETA, &raw); err != nil {
		return nil, err
	}
	return &terminalState{termios: old}, nil
}

func restoreTerminal(state *terminalState) {
	if state == nil {
		return
	}
	_ = ioctlTermios(int(os.Stdin.Fd()), syscall.TIOCSETA, &state.termios)
}

func ioctlTermios(fd int, req uintptr, value *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(value)))
	if errno != 0 {
		return fmt.Errorf("ioctl terminal: %w", errno)
	}
	return nil
}

func readTerminalRune(r *bufio.Reader) (rune, int, error) {
	return r.ReadRune()
}
