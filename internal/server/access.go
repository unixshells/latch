package server

import "sync"

// accessState controls whether SSH, web, relay, and API connections are accepted.
type accessState struct {
	mu           sync.RWMutex
	sshEnabled   bool
	webEnabled   bool
	relayEnabled bool
	apiEnabled   bool
}

func newAccessState() *accessState {
	// All access starts disabled. Each service sets its flag when it starts.
	return &accessState{}
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

func (a *accessState) API() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.apiEnabled
}

func (a *accessState) SetAPI(enabled bool) {
	a.mu.Lock()
	a.apiEnabled = enabled
	a.mu.Unlock()
}
