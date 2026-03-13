package mux

import (
	"fmt"
	"image"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"
)

// CellSnapshot holds a copied cell's content and style.
type CellSnapshot struct {
	Content string
	Width   int
	Style   uv.Style
}

const (
	maxCols        = 500
	maxRows        = 300
	maxWriters     = 100
	scrollbackSize = 10 * 1024 * 1024 // 10MB
)

// Pane is a pseudo-terminal backed by a VT emulator.
type Pane struct {
	ID   int
	ptmx *os.File
	cmd  *exec.Cmd
	term *vt.SafeEmulator

	mu         sync.Mutex
	writers    []io.Writer
	dead       bool
	title      string
	clipboard  []byte
	scrollback ringBuffer
	closeOnce  sync.Once
	doneCh     chan struct{}

	// Atomic flags set by VT callbacks (called under term's lock, can't use p.mu)
	bell          atomic.Bool
	cursorVisible atomic.Bool
}

// NewPane spawns a shell in a new PTY with the given dimensions.
// scrollbackLines controls VT scrollback depth; 0 means default (10000).
func NewPane(id int, cols, rows int, shell string, scrollbackLines ...int) (*Pane, error) {
	cols, rows = clamp(cols, rows)
	if shell == "" {
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
	}

	cmd := exec.Command(shell, "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	sbLines := 10000
	if len(scrollbackLines) > 0 && scrollbackLines[0] > 0 {
		sbLines = scrollbackLines[0]
	}

	emu := vt.NewSafeEmulator(cols, rows)
	emu.SetScrollbackSize(sbLines)

	p := &Pane{
		ID:     id,
		ptmx:   ptmx,
		cmd:    cmd,
		term:   emu,
		doneCh: make(chan struct{}),
	}
	p.cursorVisible.Store(true)
	p.scrollback.buf = make([]byte, scrollbackSize)

	p.term.SetCallbacks(vt.Callbacks{
		Bell: func() {
			p.bell.Store(true)
		},
		CursorVisibility: func(visible bool) {
			p.cursorVisible.Store(visible)
		},
	})
	p.term.RegisterOscHandler(0, p.setTitle)
	p.term.RegisterOscHandler(2, p.setTitle)
	p.term.RegisterOscHandler(52, p.handleClipboard)

	go p.readLoop()
	return p, nil
}

func (p *Pane) setTitle(data []byte) bool {
	p.mu.Lock()
	p.title = string(data)
	p.mu.Unlock()
	return false
}

func (p *Pane) handleClipboard(data []byte) bool {
	p.mu.Lock()
	// Store OSC 52 payload for forwarding to the client terminal.
	p.clipboard = make([]byte, len(data))
	copy(p.clipboard, data)
	p.mu.Unlock()
	return true // consumed
}

// DrainClipboard returns and clears any pending OSC 52 clipboard data.
func (p *Pane) DrainClipboard() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.clipboard
	p.clipboard = nil
	return c
}

// DrainBell returns true if a bell has fired since the last drain.
func (p *Pane) DrainBell() bool {
	return p.bell.Swap(false)
}

// CursorVisible returns whether the cursor should be shown.
func (p *Pane) CursorVisible() bool {
	return p.cursorVisible.Load()
}

func (p *Pane) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "pane %d readLoop panic: %v\n%s", p.ID, r, debug.Stack())
		}
		p.mu.Lock()
		p.dead = true
		p.mu.Unlock()
		close(p.doneCh)
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := p.ptmx.Read(buf)
		if n > 0 {
			data := buf[:n]
			p.mu.Lock()
			p.term.Write(data)
			p.scrollback.Write(data)
			alive := p.writers[:0]
			for _, w := range p.writers {
				if _, werr := w.Write(data); werr == nil {
					alive = append(alive, w)
				}
			}
			p.writers = alive
			p.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// Snapshot returns the current screen state as ANSI escape sequences.
func (p *Pane) Snapshot() []byte {
	p.mu.Lock()
	rendered := p.term.Render()
	p.mu.Unlock()
	if len(rendered) == 0 {
		return nil
	}
	out := make([]byte, 0, 2+len(rendered))
	out = append(out, '\x1b', 'c') // RIS: Reset to Initial State
	out = append(out, []byte(rendered)...)
	return out
}

// ScreenState holds a snapshot of the pane's visible screen, cursor position,
// and dimensions. Cells is a flat slice indexed as [row*W+col].
type ScreenState struct {
	Cells  []CellSnapshot
	Cursor image.Point
	W, H   int
}

// Screen returns a snapshot of the pane's visible screen under the lock.
// Safe to read concurrently with readLoop writing to the VT emulator.
func (p *Pane) Screen() ScreenState {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.term.Height()
	w := p.term.Width()
	cells := make([]CellSnapshot, w*h)
	for row := 0; row < h; row++ {
		off := row * w
		for col := 0; col < w; col++ {
			c := p.term.CellAt(col, row)
			if c != nil {
				cells[off+col] = CellSnapshot{
					Content: c.Content,
					Width:   c.Width,
					Style:   c.Style,
				}
			}
		}
	}
	return ScreenState{
		Cells:  cells,
		Cursor: p.term.CursorPosition(),
		W:      w,
		H:      h,
	}
}

// ScrollbackLen returns the number of lines in the scrollback buffer.
func (p *Pane) ScrollbackLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.term.ScrollbackLen()
}

// ScrollScreen returns a screen snapshot scrolled up by offset lines into
// the scrollback buffer. offset=0 means the live screen. The returned
// ScreenState has dimensions viewW x viewH.
func (p *Pane) ScrollScreen(offset, viewW, viewH int) ScreenState {
	p.mu.Lock()
	defer p.mu.Unlock()

	sbLen := p.term.ScrollbackLen()
	if offset > sbLen {
		offset = sbLen
	}
	if offset < 0 {
		offset = 0
	}

	h := p.term.Height()
	w := p.term.Width()

	cells := make([]CellSnapshot, viewW*viewH)

	// How many rows come from scrollback vs live screen.
	// offset is the number of lines scrolled up from the bottom.
	// The viewport shows: (sbLen-offset) to (sbLen-offset+viewH-1) in
	// the combined scrollback+screen space.
	//
	// scrollback lines: indices 0..sbLen-1 (0 = oldest)
	// live screen lines: indices sbLen..sbLen+h-1
	//
	// The viewport starts at: sbLen - offset
	// So the first visible line is at combined index: sbLen - offset

	viewStart := sbLen - offset

	for row := 0; row < viewH; row++ {
		combined := viewStart + row
		off := row * viewW
		for col := 0; col < viewW; col++ {
			if combined < sbLen {
				// This row is from scrollback
				c := p.term.ScrollbackCellAt(col, combined)
				if c != nil && col < w {
					cells[off+col] = CellSnapshot{
						Content: c.Content,
						Width:   c.Width,
						Style:   c.Style,
					}
				}
			} else {
				// This row is from the live screen
				screenRow := combined - sbLen
				if screenRow < h && col < w {
					c := p.term.CellAt(col, screenRow)
					if c != nil {
						cells[off+col] = CellSnapshot{
							Content: c.Content,
							Width:   c.Width,
							Style:   c.Style,
						}
					}
				}
			}
		}
	}

	return ScreenState{
		Cells:  cells,
		Cursor: image.Point{-1, -1}, // no cursor in scroll mode
		W:      viewW,
		H:      viewH,
	}
}

// CursorPos returns the cursor position under the lock.
func (p *Pane) CursorPos() image.Point {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.term.CursorPosition()
}

// Redraw sends SIGWINCH to force the child process to repaint.
func (p *Pane) Redraw() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd.Process != nil {
		p.cmd.Process.Signal(syscall.SIGWINCH)
	}
}

// WriteInput writes user input to the PTY.
func (p *Pane) WriteInput(data []byte) (int, error) {
	return p.ptmx.Write(data)
}

// AddWriter registers a writer to receive raw PTY output.
// Silently drops the registration if the per-pane writer limit is reached.
func (p *Pane) AddWriter(w io.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.writers) >= maxWriters {
		return
	}
	p.writers = append(p.writers, w)
}

// RemoveWriter unregisters a previously added writer.
func (p *Pane) RemoveWriter(w io.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, ww := range p.writers {
		if ww == w {
			p.writers = append(p.writers[:i], p.writers[i+1:]...)
			return
		}
	}
}

// Resize updates the PTY and VT emulator dimensions.
func (p *Pane) Resize(cols, rows int) {
	cols, rows = clamp(cols, rows)
	p.mu.Lock()
	p.term.Resize(cols, rows)
	if !p.dead {
		pty.Setsize(p.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	}
	p.mu.Unlock()
}

// Dead reports whether the pane's shell process has exited.
func (p *Pane) Dead() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dead
}

// Title returns the pane's OSC title, or "shell" if unset.
func (p *Pane) Title() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.title != "" {
		return p.title
	}
	return "shell"
}

// Wait blocks until the pane's read loop exits.
func (p *Pane) Wait() {
	<-p.doneCh
}

// Close sends SIGHUP and reaps the child process.
func (p *Pane) Close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.dead = true
		if p.cmd.Process != nil {
			p.cmd.Process.Signal(syscall.SIGHUP)
		}
		p.ptmx.Close()
		p.mu.Unlock()

		// Reap the child process in the background so callers are not
		// blocked while the shell exits.
		go func() {
			done := make(chan error, 1)
			go func() { done <- p.cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				p.cmd.Process.Kill()
				<-done
			}
		}()
	})
}

func clamp(cols, rows int) (int, int) {
	if cols < 1 {
		cols = 80
	} else if cols > maxCols {
		cols = maxCols
	}
	if rows < 1 {
		rows = 24
	} else if rows > maxRows {
		rows = maxRows
	}
	return cols, rows
}

// ringBuffer is a fixed-size circular buffer.
type ringBuffer struct {
	buf  []byte
	pos  int
	full bool
}

func (r *ringBuffer) Write(p []byte) {
	for len(p) > 0 {
		n := copy(r.buf[r.pos:], p)
		r.pos += n
		if r.pos >= len(r.buf) {
			r.pos = 0
			r.full = true
		}
		p = p[n:]
	}
}

func (r *ringBuffer) Bytes() []byte {
	if !r.full {
		return r.buf[:r.pos]
	}
	out := make([]byte, len(r.buf))
	n := copy(out, r.buf[r.pos:])
	copy(out[n:], r.buf[:r.pos])
	return out
}
