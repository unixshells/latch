package mux

import "encoding/binary"

// AdminState holds the data for the admin panel overlay.
type AdminState struct {
	Conns        []AdminConn
	SSHEnabled   bool
	WebEnabled   bool
	RelayEnabled bool
	Selected     int

	// Per-session access flags for the attached session.
	SessionAllowSSH   bool
	SessionAllowWeb   bool
	SessionAllowRelay bool

	APIEnabled      bool
	SessionAllowAPI bool

	// RelayConfigured is true when the user has a relay account set up.
	RelayConfigured bool
}

// AdminConn describes a connection for display in the admin panel.
type AdminConn struct {
	ID         uint64
	Source     string
	RemoteAddr string
	KeyComment string
	Session    string
	Duration   string // pre-formatted
}

// Admin action types sent from client to server.
const (
	AdminToggleSSH   byte = 0x01
	AdminToggleRelay byte = 0x02
	AdminKick        byte = 0x03
	AdminNavUp       byte = 0x04
	AdminNavDown     byte = 0x05
	AdminToggleWeb   byte = 0x06

	// Per-session access toggles.
	AdminSessionToggleSSH   byte = 0x07
	AdminSessionToggleWeb   byte = 0x08
	AdminSessionToggleRelay byte = 0x09

	AdminToggleAPI        byte = 0x0A
	AdminSessionToggleAPI byte = 0x0B
)

// RenderAdmin draws a centered admin panel overlay.
func RenderAdmin(state *AdminState, cols, rows int) []byte {
	if cols < 40 || rows < 10 {
		return nil
	}

	const (
		bg  = "\x1b[48;5;235m"
		fg  = "\x1b[38;5;252m"
		dim = "\x1b[38;5;242m"
		k   = "\x1b[1;38;5;75m"
		grn = "\x1b[38;5;76m"
		red = "\x1b[38;5;196m"
		sel = "\x1b[48;5;238m"
		rst = "\x1b[0m"
		bdr = "\x1b[38;5;238m"
	)

	// Panel dimensions.
	pw := cols - 8
	if pw > 72 {
		pw = 72
	}
	// Count toggle rows: ssh + web + api always, relay only if configured.
	globalToggles := 3
	sessionToggles := 3
	if state.RelayConfigured {
		globalToggles = 4
		sessionToggles = 4
	}
	// borders(2) + header(1) + sep(1) + globalToggles + sep(1) + sessHeader(1)
	// + sessionToggles + sep(1) + connHeader(1) + footer(1) = 9 + toggles*2
	fixedRows := 9 + globalToggles + sessionToggles
	maxConns := rows - fixedRows - 3
	if maxConns < 1 {
		maxConns = 1
	}
	nConns := len(state.Conns)
	if nConns > maxConns {
		nConns = maxConns
	}
	ph := fixedRows + nConns
	if nConns == 0 {
		ph++ // "no connections" line
	}

	x0 := (cols - pw) / 2
	y0 := (rows - ph) / 2
	if y0 < 1 {
		y0 = 1
	}

	var buf []byte

	line := func(row int, content []byte) {
		buf = appendCUP(buf, y0+row, x0+1)
		buf = append(buf, bg...)
		buf = append(buf, bdr...)
		buf = append(buf, "│"...)
		buf = append(buf, fg...)
		buf = append(buf, content...)
		// Pad to panel width (pw - 2 for borders).
		vis := visLen(content)
		inner := pw - 2
		if vis < inner {
			buf = appendSpaces(buf, inner-vis)
		}
		buf = append(buf, bdr...)
		buf = append(buf, "│"...)
		buf = append(buf, rst...)
	}

	hbar := func(row int) {
		buf = appendCUP(buf, y0+row, x0+1)
		buf = append(buf, bg...)
		buf = append(buf, bdr...)
		buf = append(buf, "├"...)
		for i := 0; i < pw-2; i++ {
			buf = append(buf, "─"...)
		}
		buf = append(buf, "┤"...)
		buf = append(buf, rst...)
	}

	topBar := func(row int) {
		buf = appendCUP(buf, y0+row, x0+1)
		buf = append(buf, bg...)
		buf = append(buf, bdr...)
		buf = append(buf, "┌"...)
		for i := 0; i < pw-2; i++ {
			buf = append(buf, "─"...)
		}
		buf = append(buf, "┐"...)
		buf = append(buf, rst...)
	}

	botBar := func(row int) {
		buf = appendCUP(buf, y0+row, x0+1)
		buf = append(buf, bg...)
		buf = append(buf, bdr...)
		buf = append(buf, "└"...)
		for i := 0; i < pw-2; i++ {
			buf = append(buf, "─"...)
		}
		buf = append(buf, "┘"...)
		buf = append(buf, rst...)
	}

	row := 0

	// Top border.
	topBar(row)
	row++

	// Title.
	var title []byte
	title = append(title, " "...)
	title = append(title, fg...)
	title = append(title, "admin"...)
	line(row, title)
	row++

	hbar(row)
	row++

	// SSH toggle.
	var sshLine []byte
	sshLine = append(sshLine, " ssh   "...)
	if state.SSHEnabled {
		sshLine = append(sshLine, grn...)
		sshLine = append(sshLine, "● on "...)
	} else {
		sshLine = append(sshLine, red...)
		sshLine = append(sshLine, "○ off"...)
	}
	sshLine = append(sshLine, dim...)
	sshLine = append(sshLine, "  "...)
	sshLine = append(sshLine, k...)
	sshLine = append(sshLine, "1"...)
	sshLine = append(sshLine, dim...)
	sshLine = append(sshLine, " toggle"...)
	line(row, sshLine)
	row++

	// Web toggle.
	var webLine []byte
	webLine = append(webLine, " web   "...)
	if state.WebEnabled {
		webLine = append(webLine, grn...)
		webLine = append(webLine, "● on "...)
	} else {
		webLine = append(webLine, red...)
		webLine = append(webLine, "○ off"...)
	}
	webLine = append(webLine, dim...)
	webLine = append(webLine, "  "...)
	webLine = append(webLine, k...)
	webLine = append(webLine, "2"...)
	webLine = append(webLine, dim...)
	webLine = append(webLine, " toggle"...)
	line(row, webLine)
	row++

	// Relay toggle (only if configured).
	if state.RelayConfigured {
		var relayLine []byte
		relayLine = append(relayLine, " relay "...)
		if state.RelayEnabled {
			relayLine = append(relayLine, grn...)
			relayLine = append(relayLine, "● on "...)
		} else {
			relayLine = append(relayLine, red...)
			relayLine = append(relayLine, "○ off"...)
		}
		relayLine = append(relayLine, dim...)
		relayLine = append(relayLine, "  "...)
		relayLine = append(relayLine, k...)
		relayLine = append(relayLine, "3"...)
		relayLine = append(relayLine, dim...)
		relayLine = append(relayLine, " toggle"...)
		line(row, relayLine)
		row++
	}

	// API toggle.
	var apiLine []byte
	apiLine = append(apiLine, " api   "...)
	if state.APIEnabled {
		apiLine = append(apiLine, grn...)
		apiLine = append(apiLine, "● on "...)
	} else {
		apiLine = append(apiLine, red...)
		apiLine = append(apiLine, "○ off"...)
	}
	apiLine = append(apiLine, dim...)
	apiLine = append(apiLine, "  "...)
	apiLine = append(apiLine, k...)
	apiLine = append(apiLine, "7"...)
	apiLine = append(apiLine, dim...)
	apiLine = append(apiLine, " toggle"...)
	line(row, apiLine)
	row++

	hbar(row)
	row++

	// Session access section.
	var sessHdr []byte
	sessHdr = append(sessHdr, " "...)
	sessHdr = append(sessHdr, dim...)
	sessHdr = append(sessHdr, "session access"...)
	line(row, sessHdr)
	row++

	sessToggle := func(label string, enabled bool, key string) {
		var ln []byte
		ln = append(ln, " "...)
		ln = append(ln, label...)
		for j := len(label); j < 6; j++ {
			ln = append(ln, ' ')
		}
		if enabled {
			ln = append(ln, grn...)
			ln = append(ln, "● on "...)
		} else {
			ln = append(ln, red...)
			ln = append(ln, "○ off"...)
		}
		ln = append(ln, dim...)
		ln = append(ln, "  "...)
		ln = append(ln, k...)
		ln = append(ln, key...)
		ln = append(ln, dim...)
		ln = append(ln, " toggle"...)
		line(row, ln)
		row++
	}
	sessToggle("ssh", state.SessionAllowSSH, "4")
	sessToggle("web", state.SessionAllowWeb, "5")
	if state.RelayConfigured {
		sessToggle("relay", state.SessionAllowRelay, "6")
	}
	sessToggle("api", state.SessionAllowAPI, "8")

	hbar(row)
	row++

	// Connections header.
	var hdr []byte
	hdr = append(hdr, " "...)
	hdr = append(hdr, dim...)
	hdr = append(hdr, "connections"...)
	line(row, hdr)
	row++

	// Connection rows.
	if nConns == 0 {
		var empty []byte
		empty = append(empty, " "...)
		empty = append(empty, dim...)
		empty = append(empty, "none"...)
		line(row, empty)
		row++
	}
	for i := 0; i < nConns; i++ {
		c := state.Conns[i]
		var cline []byte
		if i == state.Selected {
			cline = append(cline, sel...)
		}
		cline = append(cline, " "...)
		cline = append(cline, fg...)

		// Source.
		src := c.Source
		if len(src) > 5 {
			src = src[:5]
		}
		cline = append(cline, src...)
		for j := len(src); j < 6; j++ {
			cline = append(cline, ' ')
		}

		// Name/comment or remote addr.
		name := c.KeyComment
		if name == "" {
			name = c.RemoteAddr
		}
		if len(name) > 24 {
			name = name[:24]
		}
		cline = append(cline, dim...)
		cline = append(cline, name...)
		for j := len(name); j < 25; j++ {
			cline = append(cline, ' ')
		}

		// Duration.
		cline = append(cline, dim...)
		cline = append(cline, c.Duration...)

		if i == state.Selected {
			// Reset selection background at end.
			cline = append(cline, bg...)
		}

		line(row, cline)
		row++
	}

	hbar(row)
	row++

	// Footer.
	var footer []byte
	footer = append(footer, " "...)
	footer = append(footer, k...)
	footer = append(footer, "j/k"...)
	footer = append(footer, dim...)
	footer = append(footer, " nav  "...)
	footer = append(footer, k...)
	footer = append(footer, "x"...)
	footer = append(footer, dim...)
	footer = append(footer, " kick  "...)
	footer = append(footer, k...)
	footer = append(footer, "q"...)
	footer = append(footer, dim...)
	footer = append(footer, " close"...)
	line(row, footer)
	row++

	botBar(row)

	return buf
}

// visLen estimates the visible length of a byte slice, skipping ANSI escapes.
func visLen(b []byte) int {
	n := 0
	esc := false
	for _, c := range b {
		if esc {
			if c == 'm' {
				esc = false
			}
			continue
		}
		if c == 0x1b {
			esc = true
			continue
		}
		n++
	}
	return n
}

// EncodeAdminState serializes AdminState for proto transport.
// Format: [ssh:1][web:1][relay:1][sessSSH:1][sessWeb:1][sessRelay:1][selected:1][nconns:1]
//
//	then per conn: [id:8][srcLen:1][src][addrLen:1][addr][commentLen:1][comment][sessionLen:1][session][durLen:1][dur]
func EncodeAdminState(s *AdminState) []byte {
	var buf []byte
	b := func(v bool) byte {
		if v {
			return 1
		}
		return 0
	}
	buf = append(buf, b(s.SSHEnabled), b(s.WebEnabled), b(s.RelayEnabled),
		b(s.SessionAllowSSH), b(s.SessionAllowWeb), b(s.SessionAllowRelay),
		b(s.RelayConfigured),
		byte(s.Selected), byte(len(s.Conns)),
		b(s.APIEnabled), b(s.SessionAllowAPI))
	for _, c := range s.Conns {
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], c.ID)
		buf = append(buf, id[:]...)
		buf = appendField(buf, c.Source)
		buf = appendField(buf, c.RemoteAddr)
		buf = appendField(buf, c.KeyComment)
		buf = appendField(buf, c.Session)
		buf = appendField(buf, c.Duration)
	}
	return buf
}

// DecodeAdminState deserializes AdminState from proto transport.
func DecodeAdminState(data []byte) *AdminState {
	if len(data) < 11 {
		return nil
	}
	s := &AdminState{
		SSHEnabled:        data[0] != 0,
		WebEnabled:        data[1] != 0,
		RelayEnabled:      data[2] != 0,
		SessionAllowSSH:   data[3] != 0,
		SessionAllowWeb:   data[4] != 0,
		SessionAllowRelay: data[5] != 0,
		RelayConfigured:   data[6] != 0,
		Selected:          int(data[7]),
	}
	n := int(data[8])
	s.APIEnabled = data[9] != 0
	s.SessionAllowAPI = data[10] != 0
	data = data[11:]
	for i := 0; i < n; i++ {
		if len(data) < 8 {
			break
		}
		id := binary.BigEndian.Uint64(data[:8])
		data = data[8:]
		var src, addr, comment, session, dur string
		src, data = readField(data)
		addr, data = readField(data)
		comment, data = readField(data)
		session, data = readField(data)
		dur, data = readField(data)
		s.Conns = append(s.Conns, AdminConn{
			ID:         id,
			Source:     src,
			RemoteAddr: addr,
			KeyComment: comment,
			Session:    session,
			Duration:   dur,
		})
	}
	return s
}

func appendField(buf []byte, s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	buf = append(buf, byte(len(s)))
	buf = append(buf, s...)
	return buf
}

func readField(data []byte) (string, []byte) {
	if len(data) < 1 {
		return "", nil
	}
	n := int(data[0])
	data = data[1:]
	if n > len(data) {
		n = len(data)
	}
	return string(data[:n]), data[n:]
}

// EncodeAdminAction serializes an admin action.
// Format: [action:1][id:8] (id only used for kick)
func EncodeAdminAction(action byte, connID uint64) []byte {
	buf := make([]byte, 9)
	buf[0] = action
	binary.BigEndian.PutUint64(buf[1:], connID)
	return buf
}

// DecodeAdminAction deserializes an admin action.
func DecodeAdminAction(data []byte) (action byte, connID uint64) {
	if len(data) < 1 {
		return 0, 0
	}
	action = data[0]
	if len(data) >= 9 {
		connID = binary.BigEndian.Uint64(data[1:9])
	}
	return action, connID
}
