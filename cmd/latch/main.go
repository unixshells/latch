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
		if os.Getenv("LATCH_SESSION") != "" {
			fatal("already inside a latch session")
		}
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
		if os.Getenv("LATCH_SESSION") != "" {
			fatal("already inside a latch session")
		}
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
			// Create the default session so it's ready for SSH/relay connections.
			client.Attach(server.SocketPath(), name, true, cfg.PrefixKey)
			return
		}
		if err := client.Attach(server.SocketPath(), name, true, cfg.PrefixKey); err != nil {
			fatal("%v", err)
		}

	case "attach", "a":
		if os.Getenv("LATCH_SESSION") != "" {
			fatal("already inside a latch session")
		}
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

	case "auth":
		if len(os.Args) < 3 {
			authUsage()
		}
		switch os.Args[2] {
		case "add":
			if len(os.Args) < 4 {
				fatal("usage: latch auth add <key-or-file>")
			}
			if err := client.AuthAdd(os.Args[3]); err != nil {
				fatal("%v", err)
			}
		case "list", "ls":
			if err := client.AuthList(); err != nil {
				fatal("%v", err)
			}
		case "remove", "rm":
			if len(os.Args) < 4 {
				fatal("usage: latch auth remove <fingerprint-or-comment>")
			}
			if err := client.AuthRemove(os.Args[3]); err != nil {
				fatal("%v", err)
			}
		default:
			authUsage()
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
		case "cancel":
			if err := client.RelayCancel(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "delete-account":
			if err := client.RelayDeleteAccount(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "change-email":
			if err := client.RelayChangeEmail(config.Path()); err != nil {
				fatal("%v", err)
			}
		default:
			relayUsage()
		}

	case "shells":
		if len(os.Args) < 3 {
			shellsUsage()
		}
		switch os.Args[2] {
		case "list", "ls":
			if err := client.ShellsList(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "create":
			if err := client.ShellsCreate(config.Path()); err != nil {
				fatal("%v", err)
			}
		case "destroy":
			if len(os.Args) < 4 {
				fatal("usage: latch shells destroy <shell-id>")
			}
			if err := client.ShellsDestroy(config.Path(), os.Args[3]); err != nil {
				fatal("%v", err)
			}
		case "restart":
			if len(os.Args) < 4 {
				fatal("usage: latch shells restart <shell-id>")
			}
			if err := client.ShellsRestart(config.Path(), os.Args[3]); err != nil {
				fatal("%v", err)
			}
		case "ssh":
			if len(os.Args) < 4 {
				fatal("usage: latch shells ssh <shell-id>")
			}
			if err := client.ShellsSSH(config.Path(), os.Args[3]); err != nil {
				fatal("%v", err)
			}
		case "key":
			if len(os.Args) < 4 {
				shellsKeyUsage()
			}
			switch os.Args[3] {
			case "add":
				if len(os.Args) < 5 {
					fatal("usage: latch shells key add <shell-id> [key-file]")
				}
				shellID := os.Args[4]
				keyFile := ""
				if len(os.Args) > 5 {
					keyFile = os.Args[5]
				}
				if err := client.ShellsKeyAdd(config.Path(), shellID, keyFile); err != nil {
					fatal("%v", err)
				}
			case "list", "ls":
				if len(os.Args) < 5 {
					fatal("usage: latch shells key list <shell-id>")
				}
				if err := client.ShellsKeyList(config.Path(), os.Args[4]); err != nil {
					fatal("%v", err)
				}
			default:
				shellsKeyUsage()
			}
		default:
			shellsUsage()
		}

	default:
		usage()
	}
}

func shellsUsage() {
	fmt.Fprintln(os.Stderr, "usage: latch shells <command>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  list             list your shells")
	fmt.Fprintln(os.Stderr, "  create           create a new shell")
	fmt.Fprintln(os.Stderr, "  destroy <id>     destroy a shell (requires email verification)")
	fmt.Fprintln(os.Stderr, "  restart <id>     restart a shell (requires email verification)")
	fmt.Fprintln(os.Stderr, "  ssh <id>         connect to a shell via SSH")
	fmt.Fprintln(os.Stderr, "  key <cmd>        manage SSH keys on a shell")
	os.Exit(1)
}

func shellsKeyUsage() {
	fmt.Fprintln(os.Stderr, "usage: latch shells key <command>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  add <id> [file]  add SSH key to shell (requires email verification)")
	fmt.Fprintln(os.Stderr, "  list <id>        list SSH keys on a shell")
	os.Exit(1)
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
  auth <cmd>              manage authorized SSH keys
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

func authUsage() {
	fmt.Fprintf(os.Stderr, `usage: %s auth <command>

commands:
  add <key-or-file>   add a public key (inline string or path to .pub file)
  list                list authorized keys
  remove <match>      remove a key by fingerprint or comment

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
  cancel       cancel subscription
  change-email change account email
  delete-account delete account

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
