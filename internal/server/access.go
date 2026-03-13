package server

import "sync"

// accessState controls whether SSH, web, and relay connections are accepted.
type accessState struct {
	mu           sync.RWMutex
	sshEnabled   bool
	webEnabled   bool
	relayEnabled bool
}

func newAccessState() *accessState {
	return &accessState{sshEnabled: true, webEnabled: true, relayEnabled: true}
}

func (a *accessState) SSH() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sshEnabled
}

func (a *accessState) Web() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.webEnabled
}

func (a *accessState) Relay() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.relayEnabled
}

func (a *accessState) SetSSH(enabled bool) {
	a.mu.Lock()
	a.sshEnabled = enabled
	a.mu.Unlock()
}

func (a *accessState) SetWeb(enabled bool) {
	a.mu.Lock()
	a.webEnabled = enabled
	a.mu.Unlock()
}

func (a *accessState) SetRelay(enabled bool) {
	a.mu.Lock()
	a.relayEnabled = enabled
	a.mu.Unlock()
}
