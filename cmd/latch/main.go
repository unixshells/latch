package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/unixshells/latch/internal/client"
	"github.com/unixshells/latch/internal/config"
	"github.com/unixshells/latch/internal/server"
)

var version = "dev"

func main() {
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("%v", err)
	}

	if len(os.Args) < 2 {
		ensureServer(cfg)
		if err := client.Attach(server.SocketPath(), "default", true, cfg.PrefixKey); err != nil {
			fatal("%v", err)
		}
		return
	}

	switch os.Args[1] {
	case "--help", "-h", "help":
		usage()

	case "--version":
		fmt.Println("latch", version)

	case "--server":
		var sshAddr, webAddr string
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--ssh":
				if i+1 < len(args) {
					i++
					sshAddr = args[i]
				}
			case "--web":
				if i+1 < len(args) {
					i++
					webAddr = args[i]
				}
			}
		}
		serve(cfg, sshAddr, webAddr)

	case "new":
		name := "default"
		var sshAddr, webAddr string
		detached := false
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--ssh":
				sshAddr = cfg.SSHAddr
				if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
					i++
					sshAddr = args[i]
				}
			case "--web":
				webAddr = cfg.WebAddr
				if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
					i++
					webAddr = args[i]
				}
			case "--detached", "-d":
				detached = true
			default:
				name = args[i]
			}
		}
		ensureServerWithRemote(cfg, sshAddr, webAddr)
		if detached {
			return
		}
		if err := client.Attach(server.SocketPath(), name, true, cfg.PrefixKey); err != nil {
			fatal("%v", err)
		}

	case "attach", "a":
		name := "default"
		if len(os.Args) > 2 {
			name = os.Args[2]
		}
		if !server.Running() {
			fatal("no server running")
		}
		if err := client.Attach(server.SocketPath(), name, false, cfg.PrefixKey); err != nil {
			fatal("%v", err)
		}

	case "ls", "list":
		if !server.Running() {
			fmt.Println("no sessions")
			return
		}
		if err := client.List(server.SocketPath()); err != nil {
			fatal("%v", err)
		}

	case "kill":
		if len(os.Args) < 3 {
			fatal("usage: latch kill <session>")
		}
		if !server.Running() {
			fatal("no server running")
		}
		if err := client.Kill(server.SocketPath(), os.Args[2]); err != nil {
			fatal("%v", err)
		}

	case "relay":
		if len(os.Args) < 3 {
			relayUsage()
		}
		switch os.Args[2] {
		case "register":
			if err := client.RelayRegister(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "add":
			if err := client.RelayAdd(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "keys":
			if err := client.RelayKeys(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "revoke":
			if err := client.RelayRevoke(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "sessions":
			if err := client.RelaySessions(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "status":
			if err := client.RelayStatus(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "enable":
			if err := client.RelayEnable(config.Path()); err != nil {
				fatal("%v", err)
			}
			fmt.Println("relay enabled in config")
			fmt.Println("relay connection will be established when the server starts.")
		case "disable":
			if err := client.RelayDisable(config.Path()); err != nil {
				fatal("%v", err)
			}
			fmt.Println("relay disabled in config")
		case "ssh-config":
			if err := client.RelaySSHConfig(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "rotate-key":
			if err := client.RelayRotateKey(config.Path()); err != nil {
				fatal("%v", err)
			}
		default:
			relayUsage()
		}

	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s [command] [options]

commands:
  (none)                   start or attach to default session
  new [name]               create a new session (default: "default")
      --ssh [addr]         also start SSH server (default :2222)
      --web [addr]         also start web terminal (default :7680)
      --detached, -d       start server without attaching
  attach [name]            attach to an existing session
  ls                       list sessions
  kill <name>              kill a session
  relay <cmd>              relay account management
  --version                print version

key bindings (prefix = Ctrl-]):
  c       new window           n/p     next/prev window
  0-9     select window        g<N>    goto window N
  x       close window         d       detach

remote access:
  latch new --ssh                    start with SSH on :2222
  latch new --web                    start with web on :7680
  latch new --ssh :3333 --web :8080  both, custom ports
  ssh -p 2222 user@host              connect via SSH
  mosh user@host --ssh="ssh -p 2222" connect via mosh

config: ~/.latch/config (see latch.conf(5))

`, os.Args[0])
	os.Exit(1)
}

func relayUsage() {
	fmt.Fprintf(os.Stderr, `usage: %s relay <command>

commands:
  register     create a new relay account
  add          add this device to an existing account
  keys         list devices and keys
  revoke       revoke a device's key
  sessions     list connected devices
  status       show local relay configuration
  enable       enable relay connection
  disable      disable relay connection
  ssh-config   print SSH config snippet
  rotate-key   rotate the relay key for this device

`, os.Args[0])
	os.Exit(1)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}

// ensureServer starts the daemon if it isn't running.
func ensureServer(cfg *config.Config) {
	ensureServerWithRemote(cfg, "", "")
}

// ensureServerWithRemote starts the daemon with optional SSH/web listeners.
// If the daemon is already running, it sends enable commands for any
// requested listeners that aren't already active.
func ensureServerWithRemote(cfg *config.Config, sshAddr, webAddr string) {
	if server.Running() {
		if sshAddr != "" {
			if err := client.EnableSSH(server.SocketPath(), sshAddr); err != nil {
				fmt.Fprintf(os.Stderr, "ssh: %v\n", err)
			}
		}
		if webAddr != "" {
			if err := client.EnableWeb(server.SocketPath(), webAddr); err != nil {
				fmt.Fprintf(os.Stderr, "web: %v\n", err)
			}
		}
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fatal("executable path: %v", err)
	}

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		fatal("open devnull: %v", err)
	}

	argv := []string{exe, "--server"}
	if sshAddr != "" {
		argv = append(argv, "--ssh", sshAddr)
	}
	if webAddr != "" {
		argv = append(argv, "--web", webAddr)
	}

	attr := &os.ProcAttr{
		Dir:   "/",
		Env:   os.Environ(),
		Files: []*os.File{devnull, devnull, os.Stderr},
	}

	proc, err := os.StartProcess(exe, argv, attr)
	if err != nil {
		fatal("start server: %v", err)
	}
	_ = proc.Release()
	devnull.Close()

	for i := 0; i < 150; i++ {
		if server.Running() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fatal("server did not start")
}

// serve starts the server with optional SSH and web listeners.
func serve(cfg *config.Config, sshAddr, webAddr string) {
	s := server.New(cfg)
	if err := s.Listen(); err != nil {
		fatal("listen: %v", err)
	}
	defer s.Close()

	if sshAddr != "" {
		if err := s.ListenRemote(sshAddr); err != nil {
			fatal("ssh: %v", err)
		}
	}
	if webAddr != "" {
		if err := s.ListenWeb(webAddr, "", ""); err != nil {
			fatal("web: %v", err)
		}
	}

	if cfg.RelayEnabled && cfg.RelayUser != "" && cfg.RelayDevice != "" {
		node := cfg.RelayNode
		if node == "" {
			node = "relay.unixshells.com"
		}
		if err := s.StartRelay(node+":443", cfg.RelayUser, cfg.RelayDevice, cfg.RelayCAFile); err != nil {
			fmt.Fprintf(os.Stderr, "relay: %v\n", err)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		s.Close()
	}()

	desc := server.SocketPath()
	if sshAddr != "" {
		desc += " + ssh " + sshAddr
	}
	if webAddr != "" {
		desc += " + web " + webAddr
	}
	fmt.Fprintf(os.Stderr, "latch server listening on %s\n", desc)

	if err := s.Serve(); err != nil {
		fatal("serve: %v", err)
	}
}
