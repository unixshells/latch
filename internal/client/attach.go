package client

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/pkg/proto"
)

// Attach connects to the server, sends an attach or new-session
// command, and pipes the terminal with prefix key interception.
// pfxKey is the prefix key byte (0 = default Ctrl-]).
func Attach(sockPath string, name string, create bool, pfxKey byte) error {
	if pfxKey == 0 {
		pfxKey = 0x1d
	}
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	raw, err := EnterRawMode()
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer raw.Restore()

	cols, rows, err := raw.Size()
	if err != nil {
		return fmt.Errorf("terminal size: %w", err)
	}

	if create {
		if err := proto.Encode(conn, proto.MsgNewSession, []byte(name)); err != nil {
			return err
		}
	} else {
		if err := proto.Encode(conn, proto.MsgAttach, []byte(name)); err != nil {
			return err
		}
	}

	if err := proto.Encode(conn, proto.MsgResize, proto.EncodeResize(cols, rows)); err != nil {
		return err
	}

	stopResize := OnResize(func(c, r uint16) {
		proto.Encode(conn, proto.MsgResize, proto.EncodeResize(c, r))
	})
	defer stopResize()

	var adminPtr atomic.Pointer[mux.AdminState]

	done := make(chan error, 1)
	go func() {
		done <- readOutput(conn, &adminPtr)
	}()

	go func() {
		done <- readInput(conn, pfxKey, &adminPtr)
	}()

	err = <-done
	// Disable mouse, bracketed paste, focus events; clear screen on detach
	os.Stdout.Write([]byte("\x1b[?1000l\x1b[?1002l\x1b[?1006l\x1b[?2004l\x1b[?1004l\x1b[?25h\x1b[0m\x1b[2J\x1b[H"))
	return err
}

// inputProcessor handles prefix key state and translates keystrokes into
// proto messages. Extracted for testability.
type inputProcessor struct {
	prefixKey      byte
	adminPtr       *atomic.Pointer[mux.AdminState]
	prefix         bool
	hudLocked      bool
	gotoMode       bool
	adminOpen      bool
	scrollMode     bool
	gotoBuf        []byte
	lastPrefixTime time.Time
}

// processInput processes a buffer of input bytes and writes proto messages to w.
// Returns the number of bytes consumed (always n) and any write error.
func (p *inputProcessor) processInput(w io.Writer, buf []byte, n int) error {
	for i := 0; i < n; i++ {
		b := buf[i]

		// Admin panel mode: intercept navigation keys.
		if p.adminOpen {
			switch b {
			case 'q', 0x1b: // q or Esc: close
				p.adminOpen = false
				proto.Encode(w, proto.MsgAdminPanel, []byte{0})
			case 'j': // down
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminNavDown, 0))
			case 'k': // up
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminNavUp, 0))
			case 'x': // kick selected
				if s := p.adminPtr.Load(); s != nil && s.Selected < len(s.Conns) {
					id := s.Conns[s.Selected].ID
					proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminKick, id))
				}
			case '1': // toggle SSH
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleSSH, 0))
			case '2': // toggle web
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleWeb, 0))
			case '3': // toggle relay
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleRelay, 0))
			case '4': // toggle session SSH access
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleSSH, 0))
			case '5': // toggle session web access
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleWeb, 0))
			case '6': // toggle session relay access
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleRelay, 0))
			}
			continue
		}

		// Scroll mode: intercept navigation keys.
		if p.scrollMode {
			// Handle escape sequences (arrow keys, page up/down) first.
			if b == 0x1b && i+2 < n && buf[i+1] == '[' {
				switch buf[i+2] {
				case 'A': // up arrow
					proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollUp})
					i += 2
				case 'B': // down arrow
					proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollDown})
					i += 2
				case '5': // Page Up: ESC[5~
					if i+3 < n && buf[i+3] == '~' {
						proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfUp})
						i += 3
					}
				case '6': // Page Down: ESC[6~
					if i+3 < n && buf[i+3] == '~' {
						proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfDown})
						i += 3
					}
				}
				continue
			}
			switch b {
			case 'q', 0x1b: // q or Esc: exit scroll mode
				p.scrollMode = false
				proto.Encode(w, proto.MsgScrollMode, []byte{0})
			case 'k': // up one line
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollUp})
			case 'j': // down one line
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollDown})
			case 0x15: // Ctrl-u: half page up
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfUp})
			case 0x04: // Ctrl-d: half page down
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfDown})
			case 'g': // top of scrollback
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollTop})
			case 'G': // bottom (exit scroll)
				p.scrollMode = false
				proto.Encode(w, proto.MsgScrollMode, []byte{0})
			}
			continue
		}

		// Goto-window mode: collect digits, Enter commits, Esc/other cancels
		if p.gotoMode {
			if b >= '0' && b <= '9' {
				p.gotoBuf = append(p.gotoBuf, b)
				continue
			}
			if (b == '\r' || b == '\n') && len(p.gotoBuf) > 0 {
				idx := 0
				for _, d := range p.gotoBuf {
					idx = idx*10 + int(d-'0')
				}
				if idx <= 253 {
					proto.Encode(w, proto.MsgSelectWin, []byte{byte(idx)})
				}
			}
			p.gotoMode = false
			p.gotoBuf = nil
			if !p.hudLocked {
				proto.Encode(w, proto.MsgHUD, []byte{0})
			}
			continue
		}

		if p.prefix {
			p.prefix = false

			// Double-tap: toggle HUD lock
			if b == p.prefixKey {
				now := time.Now()
				if now.Sub(p.lastPrefixTime) < 300*time.Millisecond {
					p.hudLocked = !p.hudLocked
					if !p.hudLocked {
						proto.Encode(w, proto.MsgHUD, []byte{0})
					}
					p.lastPrefixTime = time.Time{}
				} else {
					// Not double-tap, send literal prefix key
					proto.Encode(w, proto.MsgInput, []byte{p.prefixKey})
					if !p.hudLocked {
						proto.Encode(w, proto.MsgHUD, []byte{0})
					}
				}
				continue
			}

			// Admin panel
			if b == 's' {
				p.adminOpen = true
				proto.Encode(w, proto.MsgAdminPanel, []byte{1})
				if !p.hudLocked {
					proto.Encode(w, proto.MsgHUD, []byte{0})
				}
				continue
			}

			// Scroll mode
			if b == '[' {
				p.scrollMode = true
				proto.Encode(w, proto.MsgScrollMode, []byte{1})
				if !p.hudLocked {
					proto.Encode(w, proto.MsgHUD, []byte{0})
				}
				continue
			}

			// Goto window mode
			if b == 'g' {
				p.gotoMode = true
				p.gotoBuf = nil
				continue
			}

			consumed, err := handlePrefixW(w, b)
			if err != nil {
				return err
			}
			if consumed {
				if !p.hudLocked {
					proto.Encode(w, proto.MsgHUD, []byte{0})
				}
				continue
			}
			// Not a recognized prefix command — send both bytes
			if err := proto.Encode(w, proto.MsgInput, []byte{p.prefixKey, b}); err != nil {
				return err
			}
			if !p.hudLocked {
				proto.Encode(w, proto.MsgHUD, []byte{0})
			}
			continue
		}

		if b == p.prefixKey {
			p.prefix = true
			p.lastPrefixTime = time.Now()
			proto.Encode(w, proto.MsgHUD, []byte{1})
			continue
		}

		// Pass through mouse sequences and everything else to the pane
		if b == 0x1b && i+2 < n && buf[i+1] == '[' && buf[i+2] == '<' {
			end := i + 3
			for end < n && buf[end] != 'M' && buf[end] != 'm' {
				end++
			}
			if end < n {
				end++ // consume M/m
				proto.Encode(w, proto.MsgInput, buf[i:end])
				i = end - 1
				continue
			}
		}

		// Send remaining bytes as a batch
		end := i + 1
		for end < n && buf[end] != p.prefixKey && buf[end] != 0x1b {
			end++
		}
		if werr := proto.Encode(w, proto.MsgInput, buf[i:end]); werr != nil {
			return werr
		}
		i = end - 1
	}
	return nil
}

// readInput reads stdin and handles prefix key sequences.
func readInput(conn net.Conn, prefixKey byte, adminPtr *atomic.Pointer[mux.AdminState]) error {
	p := &inputProcessor{prefixKey: prefixKey, adminPtr: adminPtr}
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return err
		}
		if err := p.processInput(conn, buf, n); err != nil {
			return err
		}
	}
}

// handlePrefixW processes the byte after the prefix key, writing to w.
func handlePrefixW(w io.Writer, b byte) (bool, error) {
	var err error
	switch b {
	case 'd': // detach
		err = proto.Encode(w, proto.MsgDetach, nil)
		return true, err
	case 'c': // new window
		err = proto.Encode(w, proto.MsgNewWindow, nil)
		return true, err
	case 'n': // next window
		err = proto.Encode(w, proto.MsgSelectWin, []byte{proto.WindowNext})
		return true, err
	case 'p': // prev window
		err = proto.Encode(w, proto.MsgSelectWin, []byte{proto.WindowPrev})
		return true, err
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		err = proto.Encode(w, proto.MsgSelectWin, []byte{b - '0'})
		return true, err
	case 'x': // close window
		err = proto.Encode(w, proto.MsgCloseWindow, nil)
		return true, err
	}
	return false, nil
}

func readOutput(conn net.Conn, adminPtr *atomic.Pointer[mux.AdminState]) error {
	for {
		typ, payload, err := proto.Decode(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch typ {
		case proto.MsgOutput:
			if _, err := os.Stdout.Write(payload); err != nil {
				return err
			}
		case proto.MsgAdminState:
			if s := mux.DecodeAdminState(payload); s != nil {
				adminPtr.Store(s)
			}
		case proto.MsgDetached:
			return nil
		case proto.MsgSessionDead:
			return nil
		case proto.MsgError:
			return fmt.Errorf("server: %s", payload)
		}
	}
}

// List sends a list command and prints sessions.
func List(sockPath string) error {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if err := proto.Encode(conn, proto.MsgList, nil); err != nil {
		return err
	}
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		return err
	}
	if typ == proto.MsgError {
		return fmt.Errorf("server: %s", payload)
	}
	if len(payload) == 0 {
		fmt.Println("no sessions")
	} else {
		fmt.Println(string(payload))
	}
	return nil
}

// EnableSSH tells the running daemon to start the SSH listener.
func EnableSSH(sockPath, addr string) error {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if err := proto.Encode(conn, proto.MsgEnableSSH, []byte(addr)); err != nil {
		return err
	}
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		return err
	}
	if typ == proto.MsgError {
		return fmt.Errorf("server: %s", payload)
	}
	fmt.Println(string(payload))
	return nil
}

// EnableWeb tells the running daemon to start the web listener.
func EnableWeb(sockPath, addr string) error {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if err := proto.Encode(conn, proto.MsgEnableWeb, []byte(addr)); err != nil {
		return err
	}
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		return err
	}
	if typ == proto.MsgError {
		return fmt.Errorf("server: %s", payload)
	}
	fmt.Println(string(payload))
	return nil
}

// Kill sends a kill command.
func Kill(sockPath string, name string) error {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if err := proto.Encode(conn, proto.MsgKillSession, []byte(name)); err != nil {
		return err
	}
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		return err
	}
	if typ == proto.MsgError {
		return fmt.Errorf("server: %s", payload)
	}
	fmt.Println(string(payload))
	return nil
}
