package client

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

type RawTerminal struct {
	fd       int
	oldState *term.State
}

func EnterRawMode() (*RawTerminal, error) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return &RawTerminal{fd: fd, oldState: old}, nil
}

func (r *RawTerminal) Restore() {
	if err := term.Restore(r.fd, r.oldState); err != nil {
		fmt.Fprintf(os.Stderr, "terminal restore: %v\n", err)
	}
}

func (r *RawTerminal) Size() (cols, rows uint16, err error) {
	w, h, err := term.GetSize(r.fd)
	return uint16(w), uint16(h), err
}

// OnResize calls fn on terminal resize. Returns a stop function.
func OnResize(fn func(cols, rows uint16)) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				w, h, err := term.GetSize(int(os.Stdin.Fd()))
				if err == nil {
					fn(uint16(w), uint16(h))
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
