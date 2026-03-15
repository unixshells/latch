package client

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/unixshells/latch/internal/config"
	"github.com/unixshells/latch/pkg/transport"
	"golang.org/x/crypto/ssh"
)

// signAuthToken creates a "timestamp:base64(signature)" token for API auth.
func signAuthToken(signer ssh.Signer) (string, error) {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig, err := signer.Sign(nil, []byte(ts))
	if err != nil {
		return "", err
	}
	return ts + ":" + base64.StdEncoding.EncodeToString(ssh.Marshal(sig)), nil
}

// RelayRegister creates a new relay account: generates a key, calls the API,
// and the server emails the payment link.
func RelayRegister(configPath string) error {
	keyPath := transport.RelayKeyPath()

	// Check if already registered.
	cfg, _ := config.Load(configPath)
	if cfg != nil && cfg.RelayUser != "" {
		return fmt.Errorf("already registered as %q on device %q\nto add another device, use 'latch relay add' on that device\nto re-register, first remove %s and the relay lines from %s",
			cfg.RelayUser, cfg.RelayDevice, keyPath, configPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("relay key already exists at %s\nif you already have an account, use 'latch relay add'\notherwise remove the key file and try again", keyPath)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	fmt.Print("username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	username = strings.ToLower(username)
	if err := validateUsername(username); err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	hostname = strings.TrimSuffix(hostname, ".local")
	fmt.Printf("device name [%s]: ", hostname)
	device, _ := reader.ReadString('\n')
	device = strings.TrimSpace(device)
	if device == "" {
		device = hostname
	}
	if err := validateDevice(device); err != nil {
		return err
	}

	// Terms of service acceptance.
	fmt.Println()
	fmt.Println("by continuing you agree to the terms of service:")
	fmt.Println("https://unixshells.com/terms.html")
	fmt.Print("accept? [y/N]: ")
	accept, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(accept)) != "y" {
		return fmt.Errorf("terms of service must be accepted")
	}

	// Generate relay key.
	_, pub, err := transport.LoadOrGenerateRelayKey(keyPath)
	if err != nil {
		return fmt.Errorf("generate relay key: %w", err)
	}
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	// Call signup API.
	host := relayHost(configPath)
	body := fmt.Sprintf(`{"username":%q,"email":%q,"pubkey":%q,"device":%q,"tos_accepted":true}`,
		username, email, pubStr, device)

	resp, err := http.Post("https://"+host+"/api/signup", "application/json", strings.NewReader(body))
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode != http.StatusCreated {
		os.Remove(keyPath)
		msg := result["error"]
		switch {
		case resp.StatusCode == http.StatusConflict && strings.Contains(msg, "username"):
			return fmt.Errorf("username %q is already taken — pick a different one", username)
		case resp.StatusCode == http.StatusConflict && strings.Contains(msg, "email"):
			return fmt.Errorf("email %q is already registered — use 'latch relay add' to add this device", email)
		case resp.StatusCode == http.StatusBadRequest && strings.Contains(msg, "reserved"):
			return fmt.Errorf("username %q is reserved — pick a different one", username)
		case resp.StatusCode == http.StatusTooManyRequests:
			return fmt.Errorf("too many requests — wait a minute and try again")
		default:
			return fmt.Errorf("signup failed: %s", msg)
		}
	}

	// Write relay config.
	if err := writeRelayConfig(configPath, username, device); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("account %q created\n", username)
	fmt.Printf("device:  %s\n", device)
	fmt.Printf("key:     %s\n", ssh.FingerprintSHA256(pub))
	fmt.Println()
	fmt.Println("check your email for the payment link.")
	fmt.Println("run 'latch relay enable' to activate the relay connection.")
	return nil
}

// RelayAdd adds this device to an existing relay account.
// Sends an approval email — the user clicks the link, and the CLI detects it automatically.
func RelayAdd(configPath string) error {
	keyPath := transport.RelayKeyPath()

	// Check if already configured.
	cfg, _ := config.Load(configPath)
	if cfg != nil && cfg.RelayUser != "" {
		return fmt.Errorf("this device is already registered as %q on account %q\nto start fresh, remove %s and the relay lines from %s",
			cfg.RelayDevice, cfg.RelayUser, keyPath, configPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("relay key already exists at %s\nremove it first if you want to re-add this device", keyPath)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	hostname, _ := os.Hostname()
	hostname = strings.TrimSuffix(hostname, ".local")
	fmt.Printf("device name [%s]: ", hostname)
	device, _ := reader.ReadString('\n')
	device = strings.TrimSpace(device)
	if device == "" {
		device = hostname
	}
	if err := validateDevice(device); err != nil {
		return err
	}

	// Generate relay key.
	_, pub, err := transport.LoadOrGenerateRelayKey(keyPath)
	if err != nil {
		return fmt.Errorf("generate relay key: %w", err)
	}
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	// Create device request (server emails approval link).
	host := relayHost(configPath)
	reqBody := fmt.Sprintf(`{"email":%q,"action":"add-key","pubkey":%q,"device":%q}`,
		email, pubStr, device)
	resp, err := http.Post("https://"+host+"/api/device-request", "application/json", strings.NewReader(reqBody))
	if err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		os.Remove(keyPath)
		return fmt.Errorf("request failed: %s", result["error"])
	}

	requestID := result["id"]
	fmt.Println()
	fmt.Println("check your email and click the approval link.")
	fmt.Print("waiting...")

	// Poll until approved or timeout.
	username, err := pollDeviceRequest(host, requestID, 15*time.Minute)
	if err != nil {
		os.Remove(keyPath)
		fmt.Println()
		return err
	}
	fmt.Println(" approved")

	if err := writeRelayConfig(configPath, username, device); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("device %q added to account %q\n", device, username)
	fmt.Printf("key: %s\n", ssh.FingerprintSHA256(pub))
	fmt.Println()
	fmt.Println("run 'latch relay enable' to activate the relay connection.")
	return nil
}

// pollDeviceRequest polls GET /api/device-request/{id} until status is "approved".
// Returns the username from the account on success.
func pollDeviceRequest(host, requestID string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	client := http.Client{Timeout: 5 * time.Second}

	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)

		resp, err := client.Get("https://" + host + "/api/device-request/" + requestID)
		if err != nil {
			continue // transient network error, keep trying
		}
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusNotFound:
			return "", fmt.Errorf("request expired — run 'latch relay add' again")
		case result["status"] == "approved":
			return result["username"], nil
		case result["status"] == "pending":
			fmt.Print(".")
			continue
		default:
			return "", fmt.Errorf("unexpected status: %s", result["status"])
		}
	}
	return "", fmt.Errorf("timed out waiting for approval — run 'latch relay add' again")
}

// RelayKeys lists devices and keys on the account.
func RelayKeys(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	resp, err := http.Get("https://" + host + "/api/status/" + cfg.RelayUser)
	if err != nil {
		return fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct{ Error string `json:"error"` }
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("failed: %s", errResp.Error)
	}

	var status struct {
		Username     string `json:"username"`
		Email        string `json:"email"`
		Subscription string `json:"subscription"`
		Devices      []struct {
			Device  string `json:"device"`
			AddedAt string `json:"added_at"`
		} `json:"devices"`
	}
	json.NewDecoder(resp.Body).Decode(&status)

	fmt.Printf("account: %s\n", status.Username)
	fmt.Printf("email:   %s\n", status.Email)
	sub := status.Subscription
	if sub == "" {
		sub = "none"
	}
	fmt.Printf("plan:    %s\n", sub)
	fmt.Println()

	if len(status.Devices) == 0 {
		fmt.Println("no devices")
		return nil
	}

	fmt.Println("devices:")
	for _, d := range status.Devices {
		added := d.AddedAt
		if t, err := time.Parse(time.RFC3339, d.AddedAt); err == nil {
			added = t.Format("2006-01-02")
		}
		marker := ""
		if d.Device == cfg.RelayDevice {
			marker = " (this device)"
		}
		fmt.Printf("  %-20s added %s%s\n", d.Device, added, marker)
	}
	return nil
}

// RelayRevoke revokes a device's key from the account.
func RelayRevoke(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("device to revoke: ")
	device, _ := reader.ReadString('\n')
	device = strings.TrimSpace(device)
	if device == "" {
		return fmt.Errorf("device name required")
	}

	if device == cfg.RelayDevice {
		fmt.Println("WARNING: you are revoking the key for this device.")
		fmt.Print("are you sure? [y/N]: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
			return fmt.Errorf("cancelled")
		}
	}

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	// Get email from account status.
	email := ""
	resp, err := http.Get("https://" + host + "/api/status/" + cfg.RelayUser)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	var statusResp struct{ Email string `json:"email"` }
	json.NewDecoder(resp.Body).Decode(&statusResp)
	resp.Body.Close()
	email = statusResp.Email

	if email == "" {
		fmt.Print("email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
	}

	// Create device request (server emails approval link).
	reqBody := fmt.Sprintf(`{"email":%q,"action":"remove-key","device":%q}`, email, device)
	resp, err = http.Post("https://"+host+"/api/device-request", "application/json", strings.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", result["error"])
	}

	requestID := result["id"]
	fmt.Println()
	fmt.Println("check your email and click the approval link.")
	fmt.Print("waiting...")

	if _, err := pollDeviceRequest(host, requestID, 15*time.Minute); err != nil {
		fmt.Println()
		return err
	}
	fmt.Println(" approved")

	fmt.Printf("device %q revoked from account %q\n", device, cfg.RelayUser)
	return nil
}

// RelaySessions lists currently connected devices.
func RelaySessions(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	signer, _, err := transport.LoadOrGenerateRelayKey(transport.RelayKeyPath())
	if err != nil {
		return fmt.Errorf("load relay key: %w", err)
	}
	token, err := signAuthToken(signer)
	if err != nil {
		return fmt.Errorf("sign auth token: %w", err)
	}

	req, err := http.NewRequest("GET", "https://"+host+"/api/sessions/"+cfg.RelayUser, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("API error: %s", resp.Status)
	}

	var result struct {
		Devices []struct {
			Device string `json:"device"`
			Status string `json:"status"`
		} `json:"devices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Devices) == 0 {
		fmt.Println("no devices connected")
		return nil
	}

	fmt.Println("connected devices:")
	for _, d := range result.Devices {
		marker := ""
		if d.Device == cfg.RelayDevice {
			marker = " (this device)"
		}
		fmt.Printf("  %-20s %s%s\n", d.Device, d.Status, marker)
	}
	return nil
}

// RelayStatus prints the current relay configuration.
func RelayStatus(configPath string) error {
	keyPath := transport.RelayKeyPath()

	fmt.Print("relay key: ")
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Println("not found")
	} else {
		_, pub, err := transport.LoadOrGenerateRelayKey(keyPath)
		if err != nil {
			fmt.Println("error:", err)
		} else {
			fmt.Println(ssh.FingerprintSHA256(pub))
		}
	}

	// Read config for relay settings.
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}

	host, node, user, device, enabled := "", "", "", "", "false"
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "relay-host":
			host = v
		case "relay-node":
			node = v
		case "relay-user":
			user = v
		case "relay-device":
			device = v
		case "relay-enabled":
			enabled = v
		}
	}

	if host == "" {
		host = "unixshells.com"
	}
	fmt.Printf("host:    %s\n", host)
	if node != "" {
		fmt.Printf("node:    %s\n", node)
	}
	fmt.Printf("user:    %s\n", user)
	fmt.Printf("device:  %s\n", device)
	fmt.Printf("enabled: %s\n", enabled)
	return nil
}

// RelaySSHConfig prints an SSH config snippet for connecting through the relay.
func RelaySSHConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}

	node, user, device := "", "", ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "relay-node":
			node = v
		case "relay-user":
			user = v
		case "relay-device":
			device = v
		}
	}

	if user == "" {
		return fmt.Errorf("relay-user not set in config (run 'latch relay register' first)")
	}

	// Use relay node for ProxyJump, defaulting to relay.unixshells.com (GeoDNS).
	jump := node
	if jump == "" {
		jump = "relay.unixshells.com"
	}

	// The HostName must match what parseDestination expects: device.user.unixshells.com.
	// The Host line is just a convenient alias.
	hostname := user + ".unixshells.com"
	alias := user
	if device != "" {
		hostname = device + "." + user + ".unixshells.com"
		alias = device
	}

	fmt.Printf("# Add to ~/.ssh/config\n")
	fmt.Printf("Host %s\n", alias)
	fmt.Printf("    HostName %s\n", hostname)
	fmt.Printf("    ProxyJump %s\n", jump)
	fmt.Printf("    User default\n")
	fmt.Println()
	fmt.Printf("# Then connect with:\n")
	fmt.Printf("#   ssh %s\n", alias)
	fmt.Println()
	fmt.Printf("# Connect to a specific session:\n")
	fmt.Printf("#   ssh -o User=work %s\n", alias)
	fmt.Println()
	fmt.Printf("# Or without config:\n")
	fmt.Printf("#   ssh -J %s default@%s\n", jump, hostname)
	return nil
}

// RelayRotateKey generates a new relay key and rotates it via the API.
func RelayRotateKey(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" || cfg.RelayDevice == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	// Load existing key.
	_, oldPub, err := transport.LoadOrGenerateRelayKey(transport.RelayKeyPath())
	if err != nil {
		return fmt.Errorf("load relay key: %w", err)
	}
	oldPubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(oldPub)))

	// Generate new key to a temp file.
	newKeyPath := transport.RelayKeyPath() + ".new"
	_, newPub, err := transport.GenerateRelayKey(newKeyPath)
	if err != nil {
		return fmt.Errorf("generate new key: %w", err)
	}
	newPubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newPub)))

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	// Get email from account status.
	email := ""
	resp, err := http.Get("https://" + host + "/api/status/" + cfg.RelayUser)
	if err != nil {
		os.Remove(newKeyPath)
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	var statusResp struct{ Email string `json:"email"` }
	json.NewDecoder(resp.Body).Decode(&statusResp)
	resp.Body.Close()
	email = statusResp.Email

	if email == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
	}

	// Create device request (server emails approval link).
	reqBody := fmt.Sprintf(`{"email":%q,"action":"rotate-key","device":%q,"old_pubkey":%q,"new_pubkey":%q}`,
		email, cfg.RelayDevice, oldPubStr, newPubStr)
	resp, err = http.Post("https://"+host+"/api/device-request", "application/json", strings.NewReader(reqBody))
	if err != nil {
		os.Remove(newKeyPath)
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		os.Remove(newKeyPath)
		return fmt.Errorf("request failed: %s", result["error"])
	}

	requestID := result["id"]
	fmt.Println()
	fmt.Printf("rotating key for device %q — check your email and click the approval link.\n", cfg.RelayDevice)
	fmt.Print("waiting...")

	if _, err := pollDeviceRequest(host, requestID, 15*time.Minute); err != nil {
		os.Remove(newKeyPath)
		fmt.Println()
		return err
	}
	fmt.Println(" approved")

	// Atomically replace old key with new key.
	if err := os.Rename(newKeyPath, transport.RelayKeyPath()); err != nil {
		return fmt.Errorf("replace key file: %w", err)
	}

	fmt.Println("key rotated successfully")
	fmt.Printf("new fingerprint: %s\n", ssh.FingerprintSHA256(newPub))
	return nil
}

// RelayCancel cancels the relay subscription.
func RelayCancel(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("cancel your relay subscription? [y/N]: ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		return fmt.Errorf("cancelled")
	}

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	// Get email from account status.
	email := ""
	resp, err := http.Get("https://" + host + "/api/status/" + cfg.RelayUser)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	var statusResp struct{ Email string `json:"email"` }
	json.NewDecoder(resp.Body).Decode(&statusResp)
	resp.Body.Close()
	email = statusResp.Email

	if email == "" {
		fmt.Print("email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
	}

	reqBody := fmt.Sprintf(`{"email":%q,"action":"cancel-subscription"}`, email)
	resp, err = http.Post("https://"+host+"/api/device-request", "application/json", strings.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", result["error"])
	}

	requestID := result["id"]
	fmt.Println()
	fmt.Println("check your email and click the approval link.")
	fmt.Print("waiting...")

	if _, err := pollDeviceRequest(host, requestID, 15*time.Minute); err != nil {
		fmt.Println()
		return err
	}
	fmt.Println(" approved")
	fmt.Println("subscription canceled")
	return nil
}

// RelayDeleteAccount permanently deletes the relay account.
func RelayDeleteAccount(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("permanently delete your account and all devices? this cannot be undone. [y/N]: ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		return fmt.Errorf("cancelled")
	}

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	// Get email from account status.
	email := ""
	resp, err := http.Get("https://" + host + "/api/status/" + cfg.RelayUser)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	var statusResp struct{ Email string `json:"email"` }
	json.NewDecoder(resp.Body).Decode(&statusResp)
	resp.Body.Close()
	email = statusResp.Email

	if email == "" {
		fmt.Print("email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
	}

	reqBody := fmt.Sprintf(`{"email":%q,"action":"delete-account"}`, email)
	resp, err = http.Post("https://"+host+"/api/device-request", "application/json", strings.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", result["error"])
	}

	requestID := result["id"]
	fmt.Println()
	fmt.Println("check your email and click the approval link.")
	fmt.Print("waiting...")

	if _, err := pollDeviceRequest(host, requestID, 15*time.Minute); err != nil {
		fmt.Println()
		return err
	}
	fmt.Println(" approved")

	// Clean up local state.
	keyPath := transport.RelayKeyPath()
	os.Remove(keyPath)
	config.RemoveKeys(configPath, "relay-host", "relay-node", "relay-user", "relay-device", "relay-enabled")

	fmt.Println("account deleted")
	return nil
}

// RelayChangeEmail changes the email on the relay account.
func RelayChangeEmail(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.RelayUser == "" {
		return fmt.Errorf("relay not configured — run 'latch relay register' first")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("new email: ")
	newEmail, _ := reader.ReadString('\n')
	newEmail = strings.TrimSpace(newEmail)
	if newEmail == "" || !strings.Contains(newEmail, "@") {
		return fmt.Errorf("valid email required")
	}

	host := cfg.RelayHost
	if host == "" {
		host = "unixshells.com"
	}

	// Get current email from account status.
	email := ""
	resp, err := http.Get("https://" + host + "/api/status/" + cfg.RelayUser)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	var statusResp struct{ Email string `json:"email"` }
	json.NewDecoder(resp.Body).Decode(&statusResp)
	resp.Body.Close()
	email = statusResp.Email

	if email == "" {
		fmt.Print("current email: ")
		email, _ = reader.ReadString('\n')
		email = strings.TrimSpace(email)
	}

	reqBody := fmt.Sprintf(`{"email":%q,"action":"change-email","new_email":%q}`, email, newEmail)
	resp, err = http.Post("https://"+host+"/api/device-request", "application/json", strings.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", host, err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", result["error"])
	}

	requestID := result["id"]
	fmt.Println()
	fmt.Println("check your email and click the approval links (both old and new email).")
	fmt.Print("waiting...")

	if _, err := pollDeviceRequest(host, requestID, 15*time.Minute); err != nil {
		fmt.Println()
		return err
	}
	fmt.Println(" approved")
	fmt.Println("email changed")
	return nil
}

func validateUsername(s string) error {
	if s == "" {
		return fmt.Errorf("username is required")
	}
	if len(s) < 2 || len(s) > 32 {
		return fmt.Errorf("username must be 2-32 characters")
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf("username may only contain lowercase letters, digits, and hyphens")
		}
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return fmt.Errorf("username may not start or end with a hyphen")
	}
	return nil
}

func validateDevice(s string) error {
	if s == "" {
		return fmt.Errorf("device name is required")
	}
	if len(s) > 63 {
		return fmt.Errorf("device name must be 63 characters or less")
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf("device name may only contain letters, digits, and hyphens")
		}
	}
	return nil
}

// RelayEnable sets relay-enabled = true in the config file.
func RelayEnable(configPath string) error {
	return config.SetKey(configPath, "relay-enabled", "true")
}

// RelayDisable sets relay-enabled = false in the config file.
func RelayDisable(configPath string) error {
	return config.SetKey(configPath, "relay-enabled", "false")
}

// relayHost reads the relay API host from config, defaulting to unixshells.com.
func relayHost(configPath string) string {
	data, _ := os.ReadFile(configPath)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok {
			if strings.TrimSpace(k) == "relay-host" {
				return strings.TrimSpace(v)
			}
		}
	}
	return "unixshells.com"
}

// writeRelayConfig appends relay settings to the config file.
func writeRelayConfig(path, username, device string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	lines := []string{
		"\n# relay",
		"relay-host = unixshells.com",
		"relay-node = relay.unixshells.com",
	}
	if username != "" {
		lines = append(lines, "relay-user = "+username)
	}
	lines = append(lines, "relay-device = "+device, "relay-enabled = false")

	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}
	return nil
}
