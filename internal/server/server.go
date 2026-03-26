package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/unixshells/latch/internal/config"
	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/pkg/proto"
	"github.com/unixshells/latch/pkg/relay"
)

// Server is the latch daemon, managing sessions over a unix socket.
type Server struct {
	mu       sync.Mutex
	sessions []*mux.Session
	clients  []*notifyWriter // tracked for shutdown
	sockPath string
	ln       net.Listener
	remoteLn net.Listener
	webLn    net.Listener
	cfg      *config.Config
	sshAddr  string
	webAddr  string
	limiter  *connLimiter
	tracker  *connTracker
	access   *accessState
	audit    *auditLog
	metaMu   sync.Mutex
	connMeta map[net.Conn]*ConnInfo // metadata set before handle() is called
	relayCon *relay.PersistentConn
}

// SocketPath returns the path to the latch unix socket.
func SocketPath() string {
	dir := os.Getenv("HOME")
	if dir == "" {
		panic("latch: HOME not set")
	}
	return filepath.Join(dir, ".latch", "sock")
}

// New returns a new server using the default socket path and given config.
func New(cfg *config.Config) *Server {
	if cfg == nil {
		cfg = config.Default()
	}
	return &Server{
		sockPath: SocketPath(),
		cfg:      cfg,
		limiter:  newConnLimiter(10),
		tracker:  newConnTracker(),
		access:   newAccessState(),
		audit:    newAuditLog(),
		connMeta: make(map[net.Conn]*ConnInfo),
	}
}

// Listen creates the unix socket and starts listening.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.sockPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Create authorized_keys with safe permissions if it doesn't exist.
	authKeysPath := filepath.Join(dir, "authorized_keys")
	if _, err := os.Stat(authKeysPath); os.IsNotExist(err) {
		os.WriteFile(authKeysPath, nil, 0600)
	}

	os.Remove(s.sockPath)

	// Set restrictive umask so the socket is created with 0700 from the
	// start — no window where it's world-accessible.
	old := syscall.Umask(0077)
	ln, err := net.Listen("unix", s.sockPath)
	syscall.Umask(old)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.ln = ln
	return nil
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Close shuts down all listeners and sessions.
func (s *Server) Close() {
	if s.ln != nil {
		s.ln.Close()
	}
	if s.remoteLn != nil {
		s.remoteLn.Close()
	}
	if s.webLn != nil {
		s.webLn.Close()
	}
	s.StopRelay()
	os.Remove(s.sockPath)
	s.mu.Lock()
	for _, sess := range s.sessions {
		sess.Close()
	}
	for _, w := range s.clients {
		w.Close()
	}
	s.clients = nil
	s.mu.Unlock()
	s.audit.close()
}

func (s *Server) setConnMeta(conn net.Conn, info *ConnInfo) {
	s.metaMu.Lock()
	s.connMeta[conn] = info
	s.metaMu.Unlock()
}

func (s *Server) popConnMeta(conn net.Conn) *ConnInfo {
	s.metaMu.Lock()
	info := s.connMeta[conn]
	delete(s.connMeta, conn)
	s.metaMu.Unlock()
	if info != nil {
		return info
	}
	addr := ""
	if conn.RemoteAddr() != nil {
		addr = conn.RemoteAddr().String()
	}
	return &ConnInfo{Source: "local", RemoteAddr: addr}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	// Handshake timeout: clients must send their first message within 10s.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	for {
		typ, payload, err := proto.Decode(conn)
		if err != nil {
			return
		}
		switch typ {
		case proto.MsgNewSession:
			conn.SetReadDeadline(time.Time{}) // clear deadline
			s.handleNew(conn, string(payload))
			return
		case proto.MsgAttach:
			conn.SetReadDeadline(time.Time{}) // clear deadline
			s.handleAttach(conn, string(payload))
			return
		case proto.MsgList:
			s.handleList(conn)
		case proto.MsgKillSession:
			s.handleKill(conn, string(payload))
		case proto.MsgEnableSSH:
			s.handleEnableSSH(conn, string(payload))
		case proto.MsgEnableWeb:
			s.handleEnableWeb(conn, string(payload))
		default:
			proto.Encode(conn, proto.MsgError, []byte("unknown command"))
		}
	}
}

func (s *Server) handleNew(conn net.Conn, name string) {
	if name == "" {
		name = "default"
	}
	if mux.ValidateSessionName(name) != nil {
		name = "default"
	}

	s.mu.Lock()
	s.reap()
	for _, sess := range s.sessions {
		if sess.Name == name && !sess.Dead() {
			s.mu.Unlock()
			s.attachSession(conn, sess)
			return
		}
	}
	if len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		proto.Encode(conn, proto.MsgError, []byte("too many sessions"))
		return
	}

	sess, err := mux.NewSession(name, 80, 24, s.cfg.Shell)
	if err != nil {
		s.mu.Unlock()
		proto.Encode(conn, proto.MsgError, []byte(err.Error()))
		return
	}
	s.sessions = append(s.sessions, sess)
	s.mu.Unlock()

	s.pushSessionsToRelay()
	s.attachSession(conn, sess)
}

func (s *Server) handleAttach(conn net.Conn, name string) {
	if name == "" {
		name = "default"
	}

	s.mu.Lock()
	var target *mux.Session
	for _, sess := range s.sessions {
		if sess.Name == name && !sess.Dead() {
			target = sess
			break
		}
	}
	s.mu.Unlock()

	if target == nil {
		proto.Encode(conn, proto.MsgError, []byte(fmt.Sprintf("no session: %s", name)))
		return
	}

	s.attachSession(conn, target)
}

// attachSession is the core loop for an attached client.
// It sets up a render loop and processes client commands.
func (s *Server) attachSession(conn net.Conn, sess *mux.Session) {
	meta := s.popConnMeta(conn)
	meta.Session = sess.Name
	meta.closer = conn

	// Per-session access control for remote clients.
	reject := func(reason string) {
		s.audit.emit(AuditEvent{
			Event:      "reject",
			Source:     meta.Source,
			RemoteAddr: meta.RemoteAddr,
			KeyFP:      meta.KeyFP,
			KeyComment: meta.KeyComment,
			Session:    sess.Name,
			Reason:     reason,
		})
		proto.Encode(conn, proto.MsgError, []byte(reason))
	}
	switch meta.Source {
	case "ssh":
		if !sess.AllowSSH() {
			reject("session does not allow SSH access")
			return
		}
	case "web":
		if !sess.AllowWeb() {
			reject("session does not allow web access")
			return
		}
	case "relay":
		if !sess.AllowRelay() {
			reject("session does not allow relay access")
			return
		}
	case "web-relay":
		if !sess.AllowRelay() || !sess.AllowWeb() {
			reject("session does not allow web-relay access")
			return
		}
	}

	connID := s.tracker.register(meta)
	defer s.tracker.deregister(connID)

	s.audit.emit(AuditEvent{
		Event:      "connect",
		Source:     meta.Source,
		RemoteAddr: meta.RemoteAddr,
		KeyFP:      meta.KeyFP,
		KeyComment: meta.KeyComment,
		Session:    meta.Session,
	})
	defer func() {
		s.audit.emit(AuditEvent{
			Event:      "disconnect",
			Source:     meta.Source,
			RemoteAddr: meta.RemoteAddr,
			KeyFP:      meta.KeyFP,
			KeyComment: meta.KeyComment,
			Session:    meta.Session,
			Duration:   time.Since(meta.ConnectedAt).Truncate(time.Second).String(),
		})
	}()

	var cols, rows int = 80, 24
	var hudVisible bool
	var adminVisible bool
	var adminSelected int
	var scrollActive bool
	var scrollOffset int

	// Serialize all writes to conn and access to cols/rows.
	var connMu sync.Mutex

	// Send mouse and bracketed paste enable sequences once at attach, not every frame.
	if s.cfg.Mouse {
		sendOutput(conn, []byte("\x1b[?1000h\x1b[?1002h\x1b[?1006h"))
	}
	sendOutput(conn, []byte("\x1b[?2004h"))

	buildAdminState := func() *mux.AdminState {
		conns := s.tracker.list()
		relayCfg := s.cfg.RelayUser != "" && s.cfg.RelayDevice != ""
		state := &mux.AdminState{
			SSHEnabled:        s.access.SSH(),
			WebEnabled:        s.access.Web(),
			RelayEnabled:      s.access.Relay(),
			SessionAllowSSH:   sess.AllowSSH(),
			SessionAllowWeb:   sess.AllowWeb(),
			SessionAllowRelay: sess.AllowRelay(),
			RelayConfigured:   relayCfg,
			Selected:          adminSelected,
		}
		for i := range conns {
			dur := time.Since(conns[i].ConnectedAt).Truncate(time.Second).String()
			state.Conns = append(state.Conns, mux.AdminConn{
				ID:         conns[i].ID,
				Source:     conns[i].Source,
				RemoteAddr: conns[i].RemoteAddr,
				KeyComment: conns[i].KeyComment,
				Session:    conns[i].Session,
				Duration:   dur,
			})
		}
		if adminSelected >= len(state.Conns) {
			adminSelected = len(state.Conns) - 1
			if adminSelected < 0 {
				adminSelected = 0
			}
			state.Selected = adminSelected
		}
		return state
	}

	sendAdminState := func() {
		state := buildAdminState()
		data := mux.EncodeAdminState(state)
		connMu.Lock()
		proto.Encode(conn, proto.MsgAdminState, data)
		connMu.Unlock()
	}

	// connDead is closed when a write to conn fails, stopping the render loop.
	connDead := make(chan struct{})
	var connDeadOnce sync.Once
	markDead := func() {
		connDeadOnce.Do(func() { close(connDead) })
	}

	sendRender := func() {
		select {
		case <-connDead:
			return
		default:
		}
		connMu.Lock()
		if scrollActive {
			frame := mux.RenderScroll(sess, cols, rows, scrollOffset)
			if len(frame) > 0 {
				if sendOutput(conn, frame) != nil {
					markDead()
				}
			}
			connMu.Unlock()
			return
		}
		var hud *mux.HUDInfo
		if hudVisible {
			s.mu.Lock()
			relayAddr := ""
			if s.relayCon != nil {
				node := s.cfg.RelayNode
				if node == "" {
					node = "relay.unixshells.com"
				}
				relayAddr = s.cfg.RelayUser + "@" + node
			}
			hud = &mux.HUDInfo{
				SSHAddr:   s.sshAddr,
				WebAddr:   s.webAddr,
				RelayAddr: relayAddr,
				PrefixKey: s.cfg.PrefixKey,
			}
			s.mu.Unlock()
		}
		frame := mux.Render(sess, cols, rows, hud)
		if adminVisible {
			state := buildAdminState()
			frame = append(frame, mux.RenderAdmin(state, cols, rows)...)
		}
		if len(frame) > 0 {
			if sendOutput(conn, frame) != nil {
				markDead()
			}
		}
		connMu.Unlock()
	}

	w := newNotifyWriter()
	notify := w.ch
	s.mu.Lock()
	s.clients = append(s.clients, w)
	s.mu.Unlock()

	// Channel signaled when any watched pane's process exits.
	paneDied := make(chan struct{}, 1)
	var watchedPanes map[*mux.Pane]struct{}

	// Register the active window's pane for output notifications
	// and watch all panes for death.
	registerAllPanes := func() {
		for _, win := range sess.Windows() {
			for _, p := range win.Panes() {
				p.RemoveWriter(w)
			}
		}
		activeWin := sess.ActiveWindow()
		if activeWin != nil {
			for _, p := range activeWin.Panes() {
				p.AddWriter(w)
			}
		}
		newWatched := make(map[*mux.Pane]struct{})
		for _, win := range sess.Windows() {
			for _, p := range win.Panes() {
				newWatched[p] = struct{}{}
				if _, already := watchedPanes[p]; !already {
					go func(pane *mux.Pane) {
						pane.Wait()
						select {
						case paneDied <- struct{}{}:
						default:
						}
					}(p)
				}
			}
		}
		watchedPanes = newWatched
	}
	registerAllPanes()

	defer func() {
		for _, win := range sess.Windows() {
			for _, p := range win.Panes() {
				p.RemoveWriter(w)
			}
		}
		s.mu.Lock()
		for i, c := range s.clients {
			if c == w {
				s.clients = append(s.clients[:i], s.clients[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		s.shutdownIfEmpty()
	}()

	// Background render loop: coalesce notifications and re-render.
	// Exits when notify is closed (client disconnect) or connDead is closed (write failure).
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case _, ok := <-notify:
				if !ok {
					return
				}
			case <-connDead:
				return
			}
			time.Sleep(time.Duration(s.cfg.RenderCoalesceMs) * time.Millisecond)
		drain:
			for {
				select {
				case <-notify:
				case <-connDead:
					return
				default:
					break drain
				}
			}
			sendRender()
		}
	}()

	sendRender()

	type clientMsg struct {
		typ     byte
		payload []byte
		err     error
	}
	msgCh := make(chan clientMsg, 1)
	go func() {
		for {
			typ, payload, err := proto.Decode(conn)
			msgCh <- clientMsg{typ, payload, err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case msg := <-msgCh:
			if msg.err != nil {
				w.Close()
				<-done
				return
			}

			switch msg.typ {
			case proto.MsgInput:
				if p := sess.Pane(); p != nil {
					p.WriteInput(msg.payload)
				}
				// Schedule a deferred render to catch application output
				// that arrives after the notification coalesce window.
				go func() {
					time.Sleep(10 * time.Millisecond)
					sendRender()
				}()

			case proto.MsgResize:
				c, r, err := proto.DecodeResize(msg.payload)
				if err == nil {
					if c < 1 {
						c = 80
					}
					if r < 2 {
						r = 24
					}
					if c > 500 {
						c = 500
					}
					if r > 300 {
						r = 300
					}
					connMu.Lock()
					cols, rows = int(c), int(r)
					connMu.Unlock()
					sess.Resize(int(c), int(r))
					sendRender()
				}

			case proto.MsgDetach:
				connMu.Lock()
				proto.Encode(conn, proto.MsgDetached, nil)
				connMu.Unlock()
				w.Close()
				<-done
				return

			case proto.MsgNewWindow:
				sess.NewWindow()
				registerAllPanes()
				sendRender()

			case proto.MsgSelectWin:
				if len(msg.payload) > 0 {
					switch msg.payload[0] {
					case proto.WindowNext:
						sess.NextWindow()
					case proto.WindowPrev:
						sess.PrevWindow()
					default:
						sess.SelectWindow(int(msg.payload[0]))
					}
					registerAllPanes()
					sendRender()
				}

			case proto.MsgCloseWindow:
				empty := sess.CloseActiveWindow()
				if empty {
					connMu.Lock()
					proto.Encode(conn, proto.MsgSessionDead, nil)
					connMu.Unlock()
					w.Close()
					<-done
					return
				}
				registerAllPanes()
				sendRender()

			case proto.MsgHUD:
				if len(msg.payload) > 0 {
					hudVisible = msg.payload[0] != 0
					sendRender()
				}

			case proto.MsgPaste:
				if p := sess.Pane(); p != nil && len(msg.payload) > 0 {
					p.WriteInput(msg.payload)
				}

			case proto.MsgAdminPanel:
				if len(msg.payload) > 0 {
					adminVisible = msg.payload[0] != 0
					if adminVisible {
						sendAdminState()
					}
					sendRender()
				}

			case proto.MsgScrollMode:
				if len(msg.payload) > 0 {
					connMu.Lock()
					if msg.payload[0] != 0 {
						scrollActive = true
						scrollOffset = 0
					} else {
						scrollActive = false
						scrollOffset = 0
					}
					connMu.Unlock()
					sendRender()
				}

			case proto.MsgScrollAction:
				if len(msg.payload) > 0 && scrollActive {
					p := sess.Pane()
					if p == nil {
						break
					}
					connMu.Lock()
					sbLen := p.ScrollbackLen()
					switch msg.payload[0] {
					case mux.ScrollUp:
						scrollOffset++
					case mux.ScrollDown:
						scrollOffset--
					case mux.ScrollHalfUp:
						scrollOffset += rows / 2
					case mux.ScrollHalfDown:
						scrollOffset -= rows / 2
					case mux.ScrollTop:
						scrollOffset = sbLen
					case mux.ScrollBottom:
						scrollOffset = 0
						scrollActive = false
					}
					if scrollOffset < 0 {
						scrollOffset = 0
					}
					if scrollOffset > sbLen {
						scrollOffset = sbLen
					}
					connMu.Unlock()
					sendRender()
				}

			case proto.MsgAdminAction:
				if len(msg.payload) > 0 {
					action, cid := mux.DecodeAdminAction(msg.payload)
					switch action {
					case mux.AdminToggleSSH:
						if !s.access.SSH() {
							// Start the listener if not running.
							s.mu.Lock()
							hasLn := s.remoteLn != nil
							s.mu.Unlock()
							if !hasLn {
								s.ListenRemote(s.cfg.SSHAddr)
							}
						}
						s.access.SetSSH(!s.access.SSH())
					case mux.AdminToggleWeb:
						if !s.access.Web() {
							s.mu.Lock()
							hasLn := s.webLn != nil
							s.mu.Unlock()
							if !hasLn {
								s.ListenWeb(s.cfg.WebAddr, "", "")
							}
						}
						s.access.SetWeb(!s.access.Web())
					case mux.AdminToggleRelay:
						if !s.access.Relay() {
							// Start relay if configured but not connected.
							s.mu.Lock()
							hasRelay := s.relayCon != nil
							s.mu.Unlock()
							if !hasRelay && s.cfg.RelayUser != "" && s.cfg.RelayDevice != "" {
								node := s.cfg.RelayNode
								if node == "" {
									node = "relay.unixshells.com"
								}
								s.StartRelay(node+":443", s.cfg.RelayUser, s.cfg.RelayDevice, s.cfg.RelayCAFile)
							}
						} else {
							// Stop the relay connection.
							s.StopRelay()
						}
						s.access.SetRelay(!s.access.Relay())
					case mux.AdminSessionToggleSSH:
						sess.SetAllowSSH(!sess.AllowSSH())
					case mux.AdminSessionToggleWeb:
						sess.SetAllowWeb(!sess.AllowWeb())
					case mux.AdminSessionToggleRelay:
						sess.SetAllowRelay(!sess.AllowRelay())
					case mux.AdminKick:
						s.tracker.kick(cid)
					case mux.AdminNavUp:
						if adminSelected > 0 {
							adminSelected--
						}
					case mux.AdminNavDown:
						if n := len(s.tracker.list()); adminSelected < n-1 {
							adminSelected++
						}
					}
					sendAdminState()
					sendRender()
				}
			}

		case <-paneDied:
			if sess.ReapDead() {
				// If SSH/relay is active, respawn a window instead of dying.
				// The session stays alive for the next SSH connection.
				if s.remoteLn != nil || s.relayCon != nil || s.webLn != nil {
					sess.NewWindow()
					registerAllPanes()
					sendRender()
					continue
				}
				connMu.Lock()
				proto.Encode(conn, proto.MsgSessionDead, nil)
				connMu.Unlock()
				w.Close()
				<-done
				return
			}
			registerAllPanes()
			sendRender()
		}
	}
}

func (s *Server) handleList(conn net.Conn) {
	s.mu.Lock()
	s.reap()
	var list []byte
	for _, sess := range s.sessions {
		if len(list) > 0 {
			list = append(list, '\n')
		}
		status := "alive"
		if sess.Dead() {
			status = "dead"
		}
		list = append(list, fmt.Sprintf("%s\t%s\t%s", sess.Name, status, sess.Title())...)
	}
	s.mu.Unlock()
	proto.Encode(conn, proto.MsgSessionList, list)
}

func (s *Server) handleKill(conn net.Conn, name string) {
	s.mu.Lock()
	var killed bool
	for i, sess := range s.sessions {
		if sess.Name == name {
			sess.Close()
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			killed = true
			break
		}
	}
	s.mu.Unlock()
	if killed {
		proto.Encode(conn, proto.MsgSessionList, []byte("killed"))
		s.pushSessionsToRelay()
	} else {
		proto.Encode(conn, proto.MsgError, []byte(fmt.Sprintf("no session: %s", name)))
	}
}

func (s *Server) handleEnableSSH(conn net.Conn, addr string) {
	s.mu.Lock()
	already := s.remoteLn != nil
	s.mu.Unlock()
	if already {
		s.mu.Lock()
		a := s.sshAddr
		s.mu.Unlock()
		proto.Encode(conn, proto.MsgSessionList, []byte("ssh already listening on "+a))
		return
	}
	if addr == "" {
		addr = s.cfg.SSHAddr
	}
	if err := s.ListenRemote(addr); err != nil {
		proto.Encode(conn, proto.MsgError, []byte(err.Error()))
		return
	}
	s.mu.Lock()
	a := s.sshAddr
	s.mu.Unlock()
	proto.Encode(conn, proto.MsgSessionList, []byte("ssh listening on "+a))
}

func (s *Server) handleEnableWeb(conn net.Conn, addr string) {
	s.mu.Lock()
	already := s.webLn != nil
	s.mu.Unlock()
	if already {
		s.mu.Lock()
		a := s.webAddr
		s.mu.Unlock()
		proto.Encode(conn, proto.MsgSessionList, []byte("web already listening on "+a))
		return
	}
	if addr == "" {
		addr = s.cfg.WebAddr
	}
	if err := s.ListenWeb(addr, "", ""); err != nil {
		proto.Encode(conn, proto.MsgError, []byte(err.Error()))
		return
	}
	s.mu.Lock()
	a := s.webAddr
	s.mu.Unlock()
	proto.Encode(conn, proto.MsgSessionList, []byte("web listening on "+a))
}

func (s *Server) reap() {
	alive := s.sessions[:0]
	for _, sess := range s.sessions {
		if !sess.Dead() {
			alive = append(alive, sess)
		}
	}
	s.sessions = alive
}

// pushSessionsToRelay sends the current session list to the relay.
// Must be called without s.mu held (it acquires the lock).
func (s *Server) pushSessionsToRelay() {
	if s.relayCon == nil {
		return
	}

	s.mu.Lock()
	type sessionJSON struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Title  string `json:"title"`
	}
	list := make([]sessionJSON, 0, len(s.sessions))
	for _, sess := range s.sessions {
		status := "alive"
		if sess.Dead() {
			status = "dead"
		}
		list = append(list, sessionJSON{
			Name:   sess.Name,
			Status: status,
			Title:  sess.Title(),
		})
	}
	s.mu.Unlock()

	data, err := json.Marshal(list)
	if err != nil {
		return
	}
	go s.relayCon.PushSessions(data)
}

// shutdownIfEmpty closes the listener if no sessions or clients remain,
// causing Serve to return and the daemon to exit.
func (s *Server) shutdownIfEmpty() {
	s.mu.Lock()
	s.reap()
	empty := len(s.sessions) == 0 && len(s.clients) == 0
	s.mu.Unlock()
	s.pushSessionsToRelay()
	if empty {
		s.Close()
	}
}

// Running returns true if the server is already running.
func Running() bool {
	conn, err := net.Dial("unix", SocketPath())
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

const maxChunkSize = 60 * 1024 // max proto payload chunk for output frames

func sendOutput(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxChunkSize {
			chunk = chunk[:maxChunkSize]
		}
		if err := proto.Encode(conn, proto.MsgOutput, chunk); err != nil {
			return err
		}
		data = data[len(chunk):]
	}
	return nil
}

// notifyWriter triggers a notification when written to.
// The actual data is discarded — the render loop reads from VT emulators directly.
type notifyWriter struct {
	mu     sync.Mutex
	ch     chan struct{}
	closed bool
}

func newNotifyWriter() *notifyWriter {
	return &notifyWriter{ch: make(chan struct{}, 8)}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		select {
		case w.ch <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func (w *notifyWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
}

var _ io.Writer = (*notifyWriter)(nil)

// connLimiter limits concurrent connections per IP address.
type connLimiter struct {
	mu    sync.Mutex
	conns map[string]int
	max   int
}

func newConnLimiter(max int) *connLimiter {
	return &connLimiter{conns: make(map[string]int), max: max}
}

func (l *connLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns[ip] >= l.max {
		return false
	}
	l.conns[ip]++
	return true
}

func (l *connLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conns[ip]--
	if l.conns[ip] <= 0 {
		delete(l.conns, ip)
	}
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
