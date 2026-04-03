package input

import (
	"io"
	"time"

	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/pkg/proto"
)

// AdminStateFunc returns the current admin panel state.
// Used by the kick action to resolve the selected connection ID.
type AdminStateFunc func() *mux.AdminState

// Processor handles prefix key state and translates raw input bytes into
// proto messages. Used by both the local client and SSH/relay bridges.
type Processor struct {
	PrefixKey      byte
	AdminState     AdminStateFunc
	Prefix         bool
	HUDLocked      bool
	GotoMode       bool
	AdminOpen      bool
	ScrollMode     bool
	GotoBuf        []byte
	LastPrefixTime time.Time
}

// Process processes a buffer of input bytes and writes proto messages to w.
func (p *Processor) Process(w io.Writer, buf []byte, n int) error {
	for i := 0; i < n; i++ {
		b := buf[i]

		// Admin panel mode: intercept navigation keys.
		if p.AdminOpen {
			switch b {
			case 'q', 0x1b:
				p.AdminOpen = false
				proto.Encode(w, proto.MsgAdminPanel, []byte{0})
			case 'j':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminNavDown, 0))
			case 'k':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminNavUp, 0))
			case 'x':
				if p.AdminState != nil {
					if s := p.AdminState(); s != nil && s.Selected < len(s.Conns) {
						id := s.Conns[s.Selected].ID
						proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminKick, id))
					}
				}
			case '1':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleSSH, 0))
			case '2':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleWeb, 0))
			case '3':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleRelay, 0))
			case '4':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleSSH, 0))
			case '5':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleWeb, 0))
			case '6':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleRelay, 0))
			case '7':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminToggleAPI, 0))
			case '8':
				proto.Encode(w, proto.MsgAdminAction, mux.EncodeAdminAction(mux.AdminSessionToggleAPI, 0))
			}
			continue
		}

		// Scroll mode: intercept navigation keys.
		if p.ScrollMode {
			if b == 0x1b && i+2 < n && buf[i+1] == '[' {
				switch buf[i+2] {
				case 'A':
					proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollUp})
					i += 2
				case 'B':
					proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollDown})
					i += 2
				case '5':
					if i+3 < n && buf[i+3] == '~' {
						proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfUp})
						i += 3
					}
				case '6':
					if i+3 < n && buf[i+3] == '~' {
						proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfDown})
						i += 3
					}
				}
				continue
			}
			switch b {
			case 'q', 0x1b:
				p.ScrollMode = false
				proto.Encode(w, proto.MsgScrollMode, []byte{0})
			case 'k':
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollUp})
			case 'j':
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollDown})
			case 0x15:
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfUp})
			case 0x04:
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollHalfDown})
			case 'g':
				proto.Encode(w, proto.MsgScrollAction, []byte{mux.ScrollTop})
			case 'G':
				p.ScrollMode = false
				proto.Encode(w, proto.MsgScrollMode, []byte{0})
			}
			continue
		}

		// Goto-window mode: collect digits, Enter commits, Esc/other cancels
		if p.GotoMode {
			if b >= '0' && b <= '9' {
				p.GotoBuf = append(p.GotoBuf, b)
				continue
			}
			if (b == '\r' || b == '\n') && len(p.GotoBuf) > 0 {
				idx := 0
				for _, d := range p.GotoBuf {
					idx = idx*10 + int(d-'0')
				}
				if idx <= 253 {
					proto.Encode(w, proto.MsgSelectWin, []byte{byte(idx)})
				}
			}
			p.GotoMode = false
			p.GotoBuf = nil
			if !p.HUDLocked {
				proto.Encode(w, proto.MsgHUD, []byte{0})
			}
			continue
		}

		if p.Prefix {
			p.Prefix = false

			// Double-tap: toggle HUD lock
			if b == p.PrefixKey {
				now := time.Now()
				if now.Sub(p.LastPrefixTime) < 300*time.Millisecond {
					p.HUDLocked = !p.HUDLocked
					if !p.HUDLocked {
						proto.Encode(w, proto.MsgHUD, []byte{0})
					}
					p.LastPrefixTime = time.Time{}
				} else {
					proto.Encode(w, proto.MsgInput, []byte{p.PrefixKey})
					if !p.HUDLocked {
						proto.Encode(w, proto.MsgHUD, []byte{0})
					}
				}
				continue
			}

			// Admin panel
			if b == 's' {
				p.AdminOpen = true
				proto.Encode(w, proto.MsgAdminPanel, []byte{1})
				if !p.HUDLocked {
					proto.Encode(w, proto.MsgHUD, []byte{0})
				}
				continue
			}

			// Scroll mode
			if b == '[' {
				p.ScrollMode = true
				proto.Encode(w, proto.MsgScrollMode, []byte{1})
				if !p.HUDLocked {
					proto.Encode(w, proto.MsgHUD, []byte{0})
				}
				continue
			}

			// Goto window mode
			if b == 'g' {
				p.GotoMode = true
				p.GotoBuf = nil
				continue
			}

			consumed, err := HandlePrefix(w, b)
			if err != nil {
				return err
			}
			if consumed {
				if !p.HUDLocked {
					proto.Encode(w, proto.MsgHUD, []byte{0})
				}
				continue
			}
			// Not a recognized prefix command — send both bytes
			if err := proto.Encode(w, proto.MsgInput, []byte{p.PrefixKey, b}); err != nil {
				return err
			}
			if !p.HUDLocked {
				proto.Encode(w, proto.MsgHUD, []byte{0})
			}
			continue
		}

		if b == p.PrefixKey {
			p.Prefix = true
			p.LastPrefixTime = time.Now()
			proto.Encode(w, proto.MsgHUD, []byte{1})
			continue
		}

		// Pass through mouse sequences
		if b == 0x1b && i+2 < n && buf[i+1] == '[' && buf[i+2] == '<' {
			end := i + 3
			for end < n && buf[end] != 'M' && buf[end] != 'm' {
				end++
			}
			if end < n {
				end++
				proto.Encode(w, proto.MsgInput, buf[i:end])
				i = end - 1
				continue
			}
		}

		// Send remaining bytes as a batch
		end := i + 1
		for end < n && buf[end] != p.PrefixKey && buf[end] != 0x1b {
			end++
		}
		if werr := proto.Encode(w, proto.MsgInput, buf[i:end]); werr != nil {
			return werr
		}
		i = end - 1
	}
	return nil
}

// HandlePrefix processes the byte after the prefix key.
func HandlePrefix(w io.Writer, b byte) (bool, error) {
	var err error
	switch b {
	case 'd':
		err = proto.Encode(w, proto.MsgDetach, nil)
		return true, err
	case 'c':
		err = proto.Encode(w, proto.MsgNewWindow, nil)
		return true, err
	case 'n':
		err = proto.Encode(w, proto.MsgSelectWin, []byte{proto.WindowNext})
		return true, err
	case 'p':
		err = proto.Encode(w, proto.MsgSelectWin, []byte{proto.WindowPrev})
		return true, err
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		err = proto.Encode(w, proto.MsgSelectWin, []byte{b - '0'})
		return true, err
	case 'x':
		err = proto.Encode(w, proto.MsgCloseWindow, nil)
		return true, err
	}
	return false, nil
}
