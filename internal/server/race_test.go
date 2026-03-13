package server

import (
	"sync"
	"testing"
	"time"

	"github.com/unixshells/latch/pkg/proto"
)

func TestConcurrentAttachDetach(t *testing.T) {
	_, sock := testServer(t)

	// Create a session
	conn := dial(t, sock)
	proto.Encode(conn, proto.MsgNewSession, []byte("race"))
	time.Sleep(200 * time.Millisecond)
	proto.Encode(conn, proto.MsgDetach, nil)
	for {
		typ, _, err := proto.Decode(conn)
		if err != nil || typ == proto.MsgDetached {
			break
		}
	}
	conn.Close()

	// Concurrent attach/detach
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dial(t, sock)
			defer c.Close()
			proto.Encode(c, proto.MsgAttach, []byte("race"))
			time.Sleep(50 * time.Millisecond)
			proto.Encode(c, proto.MsgDetach, nil)
			for {
				typ, _, err := proto.Decode(c)
				if err != nil || typ == proto.MsgDetached {
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentAttachDetachStress(t *testing.T) {
	_, sock := testServer(t)

	// Create several sessions to work with.
	for _, name := range []string{"stress-a", "stress-b", "stress-c"} {
		c := dial(t, sock)
		proto.Encode(c, proto.MsgNewSession, []byte(name))
		time.Sleep(200 * time.Millisecond)
		proto.Encode(c, proto.MsgDetach, nil)
		for {
			typ, _, err := proto.Decode(c)
			if err != nil || typ == proto.MsgDetached {
				break
			}
		}
		c.Close()
	}

	sessions := []string{"stress-a", "stress-b", "stress-c"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := dial(t, sock)
			defer c.Close()

			switch idx % 5 {
			case 0, 1:
				// Attach to existing session then detach.
				name := sessions[idx%len(sessions)]
				proto.Encode(c, proto.MsgAttach, []byte(name))
				time.Sleep(time.Duration(10+idx%20) * time.Millisecond)
				proto.Encode(c, proto.MsgDetach, nil)
			case 2:
				// Create a new session then detach.
				proto.Encode(c, proto.MsgNewSession, []byte("default"))
				time.Sleep(time.Duration(10+idx%20) * time.Millisecond)
				proto.Encode(c, proto.MsgDetach, nil)
			case 3:
				// List sessions.
				proto.Encode(c, proto.MsgList, nil)
			case 4:
				// Kill a session (may fail if already killed, that's fine).
				proto.Encode(c, proto.MsgKillSession, []byte(sessions[idx%len(sessions)]))
			}

			// Drain responses to avoid blocking the server.
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			for {
				typ, _, err := proto.Decode(c)
				if err != nil || typ == proto.MsgDetached {
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestConcurrentNewSession(t *testing.T) {
	_, sock := testServer(t)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := dial(t, sock)
			defer c.Close()
			proto.Encode(c, proto.MsgNewSession, []byte("default"))
			time.Sleep(100 * time.Millisecond)
			proto.Encode(c, proto.MsgDetach, nil)
			for {
				typ, _, err := proto.Decode(c)
				if err != nil || typ == proto.MsgDetached {
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
