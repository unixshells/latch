package client

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"

	"github.com/unixshells/latch/internal/input"
	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/pkg/proto"
	"golang.org/x/term"
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

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// No TTY — create the session but don't attach interactively.
		if create {
			if err := proto.Encode(conn, proto.MsgNewSession, []byte(name)); err != nil {
				return err
			}
		}
		return nil
	}

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
	os.Stdout.Write([]byte("\x1b[?1000l\x1b[?1002l\x1b[?1006l\x1b[?2004l\x1b[?25h\x1b[0m\x1b[2J\x1b[H"))
	return err
}

// inputProcessor wraps input.Processor for local client use.
type inputProcessor struct {
	p input.Processor
}

// readInput reads stdin and handles prefix key sequences.
func readInput(conn net.Conn, prefixKey byte, adminPtr *atomic.Pointer[mux.AdminState]) error {
	p := &inputProcessor{p: input.Processor{
		PrefixKey:  prefixKey,
		AdminState: func() *mux.AdminState { return adminPtr.Load() },
	}}
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return err
		}
		if err := p.p.Process(conn, buf, n); err != nil {
			return err
		}
	}
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
