package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var errLineInterrupt = errors.New("line input interrupted")

var shellCommands = []string{
	"pwd", "ls", "cd",
	"lpwd", "lls", "lcd",
	"put", "get", "cancel",
	"overwrite", "status", "help", "quit", "exit",
}

type lineEditor struct {
	s      *peerSession
	reader *bufio.Reader
	out    io.Writer

	mu     sync.Mutex
	active bool
	prompt string
	line   []rune
	cursor int
	status string

	history    []string
	historyPos int
	scratch    string
}

type completionToken struct {
	value    string
	rawStart int
	rawEnd   int
	quote    rune
}

type completionCandidate struct {
	value string
	dir   bool
}

type completionResult struct {
	start      int
	end        int
	replace    []rune
	cursor     int
	candidates []completionCandidate
}

func newLineEditor(s *peerSession, r *bufio.Reader) *lineEditor {
	return &lineEditor{s: s, reader: r, out: os.Stdout}
}

func (e *lineEditor) ReadLine(prompt string) (string, error) {
	state, err := enterTerminalRaw()
	if err != nil {
		return "", fmt.Errorf("enter raw terminal mode: %w", err)
	}
	defer restoreTerminal(state)

	e.mu.Lock()
	e.active = true
	e.prompt = prompt
	e.line = e.line[:0]
	e.cursor = 0
	e.status = ""
	e.historyPos = len(e.history)
	e.scratch = ""
	e.redrawLocked()
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.active = false
		e.prompt = ""
		e.line = nil
		e.cursor = 0
		e.mu.Unlock()
	}()

	for {
		r, _, err := readTerminalRune(e.reader)
		if err != nil {
			return "", err
		}
		switch r {
		case '\r', '\n':
			e.mu.Lock()
			line := string(e.line)
			e.clearInteractiveLocked()
			e.status = ""
			fmt.Fprint(e.out, e.prompt, line, "\r\n")
			e.active = false
			e.mu.Unlock()
			if strings.TrimSpace(line) != "" {
				e.addHistory(line)
			}
			return line, nil
		case 3: // Ctrl-C
			e.mu.Lock()
			e.clearInteractiveLocked()
			e.status = ""
			fmt.Fprint(e.out, "^C\r\n")
			e.active = false
			e.mu.Unlock()
			return "", errLineInterrupt
		case 4: // Ctrl-D
			e.mu.Lock()
			if len(e.line) == 0 {
				e.clearInteractiveLocked()
				e.status = ""
				fmt.Fprint(e.out, "\r\n")
				e.active = false
				e.mu.Unlock()
				return "", io.EOF
			}
			if e.cursor < len(e.line) {
				e.line = append(e.line[:e.cursor], e.line[e.cursor+1:]...)
				e.redrawLocked()
			}
			e.mu.Unlock()
		case 1: // Ctrl-A
			e.mu.Lock()
			e.cursor = 0
			e.redrawLocked()
			e.mu.Unlock()
		case 5: // Ctrl-E
			e.mu.Lock()
			e.cursor = len(e.line)
			e.redrawLocked()
			e.mu.Unlock()
		case 12: // Ctrl-L
			e.mu.Lock()
			fmt.Fprint(e.out, "\x1b[2J\x1b[H")
			e.redrawLocked()
			e.mu.Unlock()
		case '\t':
			e.complete()
		case 8, 127:
			e.mu.Lock()
			if e.cursor > 0 {
				e.line = append(e.line[:e.cursor-1], e.line[e.cursor:]...)
				e.cursor--
				e.redrawLocked()
			}
			e.mu.Unlock()
		case 27:
			e.handleEscapeSequence()
		default:
			if unicode.IsControl(r) {
				continue
			}
			e.mu.Lock()
			e.line = append(e.line, 0)
			copy(e.line[e.cursor+1:], e.line[e.cursor:])
			e.line[e.cursor] = r
			e.cursor++
			e.redrawLocked()
			e.mu.Unlock()
		}
	}
}

func (e *lineEditor) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.active {
		return e.out.Write(p)
	}

	// 进度更新使用单独的状态行，不把每个刷新都插进命令历史区。
	// progress.print() 的非最终刷新格式固定为 "\r..." 且不带换行。
	if len(p) > 0 && p[0] == '\r' && !bytes.ContainsAny(p, "\n") {
		e.status = strings.TrimPrefix(string(p), "\r")
		e.redrawLocked()
		return len(p), nil
	}

	e.clearInteractiveLocked()
	e.status = ""
	text := string(p)
	text = strings.TrimPrefix(text, "\r")
	text = strings.TrimLeft(text, "\n")
	_, err := io.WriteString(e.out, text)
	if text != "" && !strings.HasSuffix(text, "\n") && !strings.HasSuffix(text, "\r") {
		fmt.Fprint(e.out, "\r\n")
	} else if strings.HasSuffix(text, "\r") {
		fmt.Fprint(e.out, "\n")
	}
	e.redrawLocked()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (e *lineEditor) clearInteractiveLocked() {
	// 光标始终停在输入行。显式清除输入行和下一行状态，避免依赖
	// Windows Console 对 ESC[s / ESC[u 保存恢复光标序列的兼容性。
	fmt.Fprint(e.out, "\r\x1b[2K\x1b[1E\x1b[2K\x1b[1F")
}

func (e *lineEditor) redrawLocked() {
	// 先完整画输入行。
	fmt.Fprint(e.out, "\r\x1b[2K", e.prompt, string(e.line))

	// 再画下一行状态。不要用 ESC[s / ESC[u：部分 Windows Terminal /
	// conhost 组合会把光标留在空白状态行，看起来像“没有提示符”。
	fmt.Fprint(e.out, "\x1b[1E\x1b[2K")
	if e.status != "" {
		fmt.Fprint(e.out, e.status)
	}

	// 回到输入行，并按显示宽度恢复到逻辑光标位置。
	fmt.Fprint(e.out, "\x1b[1F")
	col := displayWidthRunes([]rune(e.prompt)) + displayWidthRunes(e.line[:e.cursor])
	if col > 0 {
		fmt.Fprintf(e.out, "\x1b[%dC", col)
	}
}

func (e *lineEditor) handleEscapeSequence() {
	r2, _, err := readTerminalRune(e.reader)
	if err != nil || r2 != '[' {
		return
	}
	r3, _, err := readTerminalRune(e.reader)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch r3 {
	case 'D':
		if e.cursor > 0 {
			e.cursor--
		}
	case 'C':
		if e.cursor < len(e.line) {
			e.cursor++
		}
	case 'H':
		e.cursor = 0
	case 'F':
		e.cursor = len(e.line)
	case 'A':
		e.historyMoveLocked(-1)
	case 'B':
		e.historyMoveLocked(1)
	case '3':
		r4, _, _ := readTerminalRune(e.reader)
		if r4 == '~' && e.cursor < len(e.line) {
			e.line = append(e.line[:e.cursor], e.line[e.cursor+1:]...)
		}
	}
	e.redrawLocked()
}

func (e *lineEditor) addHistory(line string) {
	if len(e.history) > 0 && e.history[len(e.history)-1] == line {
		return
	}
	e.history = append(e.history, line)
	if len(e.history) > 500 {
		e.history = append([]string(nil), e.history[len(e.history)-500:]...)
	}
}

func (e *lineEditor) historyMoveLocked(delta int) {
	if len(e.history) == 0 {
		return
	}
	if e.historyPos == len(e.history) && delta < 0 {
		e.scratch = string(e.line)
	}
	next := e.historyPos + delta
	if next < 0 {
		next = 0
	}
	if next > len(e.history) {
		next = len(e.history)
	}
	e.historyPos = next
	if next == len(e.history) {
		e.line = []rune(e.scratch)
	} else {
		e.line = []rune(e.history[next])
	}
	e.cursor = len(e.line)
}

func (e *lineEditor) complete() {
	e.mu.Lock()
	line := append([]rune(nil), e.line...)
	cursor := e.cursor
	e.mu.Unlock()

	res := buildCompletion(e.s, line, cursor)
	if len(res.candidates) == 0 && len(res.replace) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if res.start >= 0 && res.end >= res.start && res.end <= len(e.line) && len(res.replace) > 0 {
		newLine := make([]rune, 0, len(e.line)-(res.end-res.start)+len(res.replace))
		newLine = append(newLine, e.line[:res.start]...)
		newLine = append(newLine, res.replace...)
		newLine = append(newLine, e.line[res.end:]...)
		e.line = newLine
		e.cursor = res.start + res.cursor
	}
	if len(res.candidates) > 1 {
		e.clearInteractiveLocked()
		e.status = ""
		fmt.Fprint(e.out, "\r\n")
		for _, c := range res.candidates {
			name := c.value
			if c.dir {
				name += "  [dir]"
			}
			fmt.Fprintln(e.out, name)
		}
	}
	e.redrawLocked()
}

func buildCompletion(s *peerSession, line []rune, cursor int) completionResult {
	if cursor < 0 || cursor > len(line) {
		return completionResult{}
	}
	tokens, current := scanCompletionPrefix(line[:cursor])
	// 目录补全会把光标放在闭合引号前；继续补全时一并替换旧的闭合引号，
	// 避免唯一候选完成后产生两个引号。
	if current.quote != 0 && current.rawEnd == cursor && cursor < len(line) && line[cursor] == current.quote {
		current.rawEnd++
	}
	argIndex := len(tokens) - 1
	if argIndex < 0 {
		argIndex = 0
	}

	var candidates []completionCandidate
	if argIndex == 0 {
		candidates = completeWords(current.value, shellCommands)
	} else if len(tokens) > 0 {
		cmd := strings.ToLower(tokens[0].value)
		switch cmd {
		case "cd":
			if argIndex == 1 {
				candidates = remotePathCandidates(s, current.value, true)
			}
		case "ls", "dir":
			if argIndex == 1 {
				candidates = remotePathCandidates(s, current.value, false)
			}
		case "lcd":
			if argIndex == 1 {
				candidates = localPathCandidates(s, current.value, true)
			}
		case "lls", "ldir":
			if argIndex == 1 {
				candidates = localPathCandidates(s, current.value, false)
			}
		case "put":
			if argIndex == 1 {
				candidates = localPathCandidates(s, current.value, false)
			} else if argIndex == 2 {
				candidates = remotePathCandidates(s, current.value, false)
			}
		case "get":
			if argIndex == 1 {
				candidates = remotePathCandidates(s, current.value, false)
			} else if argIndex == 2 {
				candidates = localPathCandidates(s, current.value, false)
			}
		case "overwrite":
			if argIndex == 1 {
				candidates = completeWords(current.value, []string{"on", "off"})
			}
		}
	}
	if len(candidates) == 0 {
		return completionResult{}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return strings.ToLower(candidates[i].value) < strings.ToLower(candidates[j].value)
	})

	if len(candidates) == 1 {
		raw, pos := renderCompletionToken(candidates[0])
		if argIndex == 0 {
			raw += " "
			pos = len([]rune(raw))
		}
		return completionResult{start: current.rawStart, end: current.rawEnd, replace: []rune(raw), cursor: pos, candidates: candidates}
	}

	common := commonCandidatePrefix(candidates)
	if len([]rune(common)) > len([]rune(current.value)) {
		raw, pos := renderCompletionPrefix(common)
		return completionResult{start: current.rawStart, end: current.rawEnd, replace: []rune(raw), cursor: pos, candidates: candidates}
	}
	return completionResult{start: current.rawStart, end: current.rawEnd, candidates: candidates}
}

func completeWords(prefix string, words []string) []completionCandidate {
	var out []completionCandidate
	for _, word := range words {
		if strings.HasPrefix(strings.ToLower(word), strings.ToLower(prefix)) {
			out = append(out, completionCandidate{value: word})
		}
	}
	return out
}

func commonCandidatePrefix(candidates []completionCandidate) string {
	if len(candidates) == 0 {
		return ""
	}
	prefix := []rune(candidates[0].value)
	for _, c := range candidates[1:] {
		r := []rune(c.value)
		n := len(prefix)
		if len(r) < n {
			n = len(r)
		}
		i := 0
		for i < n && unicode.ToLower(prefix[i]) == unicode.ToLower(r[i]) {
			i++
		}
		prefix = prefix[:i]
		if len(prefix) == 0 {
			break
		}
	}
	return string(prefix)
}

func renderCompletionPrefix(value string) (string, int) {
	if !needsQuoting(value) {
		return value, len([]rune(value))
	}
	quote := '"'
	if strings.ContainsRune(value, '"') && !strings.ContainsRune(value, '\'') {
		quote = '\''
	}
	if strings.ContainsRune(value, quote) {
		raw := escapeUnquotedToken(value)
		return raw, len([]rune(raw))
	}
	raw := string(quote) + value + string(quote)
	return raw, len([]rune(raw)) - 1
}

func renderCompletionToken(c completionCandidate) (string, int) {
	if !needsQuoting(c.value) {
		return c.value, len([]rune(c.value))
	}
	quote := '"'
	if strings.ContainsRune(c.value, '"') && !strings.ContainsRune(c.value, '\'') {
		quote = '\''
	}
	if strings.ContainsRune(c.value, quote) {
		raw := escapeUnquotedToken(c.value)
		return raw, len([]rune(raw))
	}
	raw := string(quote) + c.value + string(quote)
	pos := len([]rune(raw))
	if c.dir {
		pos-- // 目录补全后把光标留在闭合引号前，便于继续输入下一级。
	}
	return raw, pos
}

func needsQuoting(s string) bool {
	return strings.IndexFunc(s, unicode.IsSpace) >= 0 || strings.ContainsAny(s, "\"'")
}

func escapeUnquotedToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || r == '\'' || r == '"' {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func scanCompletionPrefix(line []rune) ([]completionToken, completionToken) {
	tokens := make([]completionToken, 0, 4)
	var b strings.Builder
	start := -1
	quote := rune(0)
	tokenQuote := rune(0)

	finish := func(end int) {
		if start < 0 {
			return
		}
		tokens = append(tokens, completionToken{value: b.String(), rawStart: start, rawEnd: end, quote: tokenQuote})
		b.Reset()
		start = -1
		quote = 0
		tokenQuote = 0
	}

	for i := 0; i < len(line); i++ {
		r := line[i]
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			b.WriteRune(r)
			continue
		}
		if unicode.IsSpace(r) {
			finish(i)
			continue
		}
		if start < 0 {
			start = i
		}
		if r == '\'' || r == '"' {
			if b.Len() == 0 && tokenQuote == 0 {
				tokenQuote = r
			}
			quote = r
			continue
		}
		if r == '\\' && i+1 < len(line) {
			n := line[i+1]
			if unicode.IsSpace(n) || n == '\'' || n == '"' {
				b.WriteRune(n)
				i++
				continue
			}
		}
		b.WriteRune(r)
	}
	if start >= 0 {
		cur := completionToken{value: b.String(), rawStart: start, rawEnd: len(line), quote: tokenQuote}
		tokens = append(tokens, cur)
		return tokens, cur
	}
	cur := completionToken{rawStart: len(line), rawEnd: len(line)}
	tokens = append(tokens, cur)
	return tokens, cur
}

func localPathCandidates(s *peerSession, prefix string, dirsOnly bool) []completionCandidate {
	base := s.getLocalCwd()
	dirPrefix, namePrefix := splitLocalCompletionPath(prefix)
	query := dirPrefix
	if query == "" {
		query = "."
	}
	resolved, err := cleanExistingPath(base, query)
	if err != nil {
		return nil
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.IsDir() {
		return nil
	}
	items, err := os.ReadDir(resolved)
	if err != nil {
		return nil
	}
	sep := string(os.PathSeparator)
	if runtime.GOOS == "windows" && strings.Contains(dirPrefix, "/") && !strings.Contains(dirPrefix, "\\") {
		sep = "/"
	}
	var out []completionCandidate
	for _, item := range items {
		if dirsOnly && !item.IsDir() {
			continue
		}
		if !pathPrefixMatch(item.Name(), namePrefix, runtime.GOOS == "windows") {
			continue
		}
		v := dirPrefix + item.Name()
		if item.IsDir() {
			v += sep
		}
		out = append(out, completionCandidate{value: v, dir: item.IsDir()})
	}
	return out
}

func splitLocalCompletionPath(p string) (dirPrefix, namePrefix string) {
	seps := string(os.PathSeparator)
	if runtime.GOOS == "windows" {
		seps = "\\/"
	}
	idx := strings.LastIndexAny(p, seps)
	if idx < 0 {
		return "", p
	}
	return p[:idx+1], p[idx+1:]
}

func remotePathCandidates(s *peerSession, prefix string, dirsOnly bool) []completionCandidate {
	remoteCwd := s.getRemoteCwd()
	dirPrefix, namePrefix, sep := splitRemoteCompletionPath(prefix, remoteCwd)
	query := dirPrefix
	if query == "" {
		query = "."
	}
	resp, err := s.callRPC("ls", query, 3*time.Second)
	if err != nil {
		return nil
	}
	windowsStyle := sep == "\\"
	var out []completionCandidate
	for _, entry := range resp.Entries {
		if dirsOnly && !entry.Dir {
			continue
		}
		if !pathPrefixMatch(entry.Name, namePrefix, windowsStyle) {
			continue
		}
		v := dirPrefix + entry.Name
		if entry.Dir {
			v += sep
		}
		out = append(out, completionCandidate{value: v, dir: entry.Dir})
	}
	return out
}

func pathPrefixMatch(name, prefix string, fold bool) bool {
	if fold {
		return strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix))
	}
	return strings.HasPrefix(name, prefix)
}

func splitRemoteCompletionPath(p, cwd string) (dirPrefix, namePrefix, sep string) {
	sep = remotePathSeparator(p, cwd)
	idx := strings.LastIndex(p, sep)
	if sep == "\\" {
		if slash := strings.LastIndex(p, "/"); slash > idx {
			idx = slash
		}
	} else if backslash := strings.LastIndex(p, "\\"); backslash > idx && looksWindowsPath(p) {
		idx = backslash
		sep = "\\"
	}
	if idx < 0 {
		return "", p, sep
	}
	return p[:idx+1], p[idx+1:], sep
}

func remotePathSeparator(p, cwd string) string {
	if looksWindowsPath(p) || looksWindowsPath(cwd) {
		return "\\"
	}
	return "/"
}

func looksWindowsPath(p string) bool {
	if strings.Contains(p, "\\") {
		return true
	}
	r := []rune(p)
	return len(r) >= 2 && unicode.IsLetter(r[0]) && r[1] == ':'
}

func displayWidthRunes(rs []rune) int {
	w := 0
	for _, r := range rs {
		if r == 0 {
			continue
		}
		if isWideRune(r) {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func isWideRune(r rune) bool {
	return r >= 0x1100 && (r <= 0x115f ||
		r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff))
}

func shellPrompt(s *peerSession) string {
	remote := s.getRemoteCwd()
	if remote == "" {
		remote = "?"
	}
	const maxRunes = 52
	if utf8.RuneCountInString(remote) > maxRunes {
		r := []rune(remote)
		remote = "…" + string(r[len(r)-(maxRunes-1):])
	}
	return "p2p[" + s.roleName + " remote:" + remote + "]> "
}
