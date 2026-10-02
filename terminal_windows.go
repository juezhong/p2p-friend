//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	enableProcessedInput            = 0x0001
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableVirtualTerminalInput      = 0x0200
	enableVirtualTerminalProcessing = 0x0004
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
	procReadConsoleW        = kernel32.NewProc("ReadConsoleW")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
)

type terminalState struct {
	inMode  uint32
	outMode uint32
}

func enterTerminalRaw() (*terminalState, error) {
	in := syscall.Handle(os.Stdin.Fd())
	out := syscall.Handle(os.Stdout.Fd())
	var inMode, outMode uint32
	if err := getConsoleMode(in, &inMode); err != nil {
		return nil, err
	}
	if err := getConsoleMode(out, &outMode); err != nil {
		return nil, err
	}

	newIn := inMode &^ (enableProcessedInput | enableLineInput | enableEchoInput)
	if err := setConsoleMode(in, newIn|enableVirtualTerminalInput); err != nil {
		// 老版本控制台可能不支持 VT input；Tab/Ctrl-C/Backspace 仍可使用。
		if err2 := setConsoleMode(in, newIn); err2 != nil {
			return nil, err2
		}
	}
	if err := setConsoleMode(out, outMode|enableVirtualTerminalProcessing); err != nil {
		_ = setConsoleMode(in, inMode)
		return nil, err
	}
	return &terminalState{inMode: inMode, outMode: outMode}, nil
}

func restoreTerminal(state *terminalState) {
	if state == nil {
		return
	}
	_ = setConsoleMode(syscall.Handle(os.Stdin.Fd()), state.inMode)
	_ = setConsoleMode(syscall.Handle(os.Stdout.Fd()), state.outMode)
}

func readTerminalRune(r *bufio.Reader) (rune, int, error) {
	// 菜单阶段可能已经由 bufio 预读了少量字节，优先消费它们。
	if r.Buffered() > 0 {
		return r.ReadRune()
	}
	first, err := readConsoleUTF16()
	if err != nil {
		return 0, 0, err
	}
	if first >= 0xD800 && first <= 0xDBFF {
		second, err := readConsoleUTF16()
		if err != nil {
			return 0, 0, err
		}
		rn := utf16.DecodeRune(rune(first), rune(second))
		return rn, 4, nil
	}
	return rune(first), 2, nil
}

func readConsoleUTF16() (uint16, error) {
	var ch uint16
	var n uint32
	r, _, e := procReadConsoleW.Call(
		uintptr(syscall.Handle(os.Stdin.Fd())),
		uintptr(unsafe.Pointer(&ch)),
		1,
		uintptr(unsafe.Pointer(&n)),
		0,
	)
	if r == 0 {
		return 0, fmt.Errorf("ReadConsoleW: %w", e)
	}
	if n != 1 {
		return 0, fmt.Errorf("ReadConsoleW returned %d UTF-16 units", n)
	}
	return ch, nil
}

func getConsoleMode(h syscall.Handle, mode *uint32) error {
	r, _, e := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(mode)))
	if r == 0 {
		return fmt.Errorf("GetConsoleMode: %w", e)
	}
	return nil
}

func setConsoleMode(h syscall.Handle, mode uint32) error {
	r, _, e := procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	if r == 0 {
		return fmt.Errorf("SetConsoleMode: %w", e)
	}
	return nil
}

func consoleInputReady(timeout time.Duration) bool {
	ms := uint32(timeout / time.Millisecond)
	if timeout < 0 {
		ms = 0xffffffff
	}
	r, _, _ := procWaitForSingleObject.Call(
		uintptr(syscall.Handle(os.Stdin.Fd())),
		uintptr(ms),
	)
	return uint32(r) == 0 // WAIT_OBJECT_0
}
