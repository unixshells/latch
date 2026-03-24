package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/unixshells/latch/internal/config"
)

const serverURL = "https://unixshells.com"

func loadRelayConfig(cfgPath string) (*config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if cfg.RelayUser == "" {
		return nil, fmt.Errorf("not logged in — run 'latch relay add' first")
	}
	return cfg, nil
}

func apiRequest(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, serverURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp map[string]string
		json.Unmarshal(respBody, &errResp)
		if msg, ok := errResp["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("server error (%d)", resp.StatusCode)
	}

	if result != nil {
		return json.Unmarshal(respBody, result)
	}
	return nil
}

// ShellsList lists the user's shells.
func ShellsList(cfgPath string) error {
	cfg, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	var result struct {
		Shells []struct {
			ID    string `json:"id"`
			Plan  string `json:"plan"`
			State string `json:"state"`
			MemMB int    `json:"mem_mb"`
			Vcpus int    `json:"vcpus"`
		} `json:"shells"`
	}

	if err := apiRequest("GET", "/api/shells?username="+cfg.RelayUser, nil, &result); err != nil {
		return err
	}

	if len(result.Shells) == 0 {
		fmt.Println("no shells")
		return nil
	}

	for _, s := range result.Shells {
		fmt.Printf("%-14s %-10s %-8s %dMB %dvCPU\n", s.ID, s.Plan, s.State, s.MemMB, s.Vcpus)
	}
	return nil
}

// ShellsCreate creates a new shell.
func ShellsCreate(cfgPath string) error {
	cfg, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	var result struct {
		Message string `json:"message"`
	}

	if err := apiRequest("POST", "/api/request-shell", map[string]string{
		"username": cfg.RelayUser,
	}, &result); err != nil {
		return err
	}

	fmt.Println(result.Message)
	fmt.Println("check your email and choose a plan to get started.")
	return nil
}

// ShellsDestroy initiates shell destruction (sends verification email).
func ShellsDestroy(cfgPath, shellID string) error {
	_, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	var result struct {
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}

	if err := apiRequest("POST", "/api/shells/"+shellID+"/destroy", nil, &result); err != nil {
		return err
	}

	fmt.Println(result.Message)
	fmt.Println("check your email to confirm.")
	return nil
}

// ShellsRestart initiates shell restart (sends verification email).
func ShellsRestart(cfgPath, shellID string) error {
	_, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	var result struct {
		Message string `json:"message"`
	}

	if err := apiRequest("POST", "/api/shells/"+shellID+"/restart", nil, &result); err != nil {
		return err
	}

	fmt.Println(result.Message)
	fmt.Println("check your email to confirm.")
	return nil
}

// ShellsSSH connects to a shell via SSH through the relay.
func ShellsSSH(cfgPath, shellID string) error {
	cfg, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	device := "shell-" + shellID
	host := device + "." + cfg.RelayUser + ".unixshells.com"

	cmd := exec.Command("ssh", "-J", "relay.unixshells.com", "default@"+host)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ShellsKeyAdd adds an SSH key to a shell (sends verification email).
func ShellsKeyAdd(cfgPath, shellID, keyFile string) error {
	_, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	// Read the key
	var pubKey string
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		pubKey = strings.TrimSpace(string(data))
	} else {
		// Default: try common key locations
		for _, path := range []string{
			os.ExpandEnv("$HOME/.ssh/id_ed25519.pub"),
			os.ExpandEnv("$HOME/.ssh/id_rsa.pub"),
		} {
			data, err := os.ReadFile(path)
			if err == nil {
				pubKey = strings.TrimSpace(string(data))
				fmt.Printf("using key: %s\n", path)
				break
			}
		}
	}

	if pubKey == "" {
		return fmt.Errorf("no SSH key found — specify a key file or generate one with ssh-keygen")
	}

	var result struct {
		Message string `json:"message"`
	}

	if err := apiRequest("POST", "/api/shells/"+shellID+"/keys", map[string]string{
		"pubkey": pubKey,
	}, &result); err != nil {
		return err
	}

	fmt.Println(result.Message)
	fmt.Println("check your email to confirm.")
	return nil
}

// ShellsKeyList lists SSH keys on a shell.
func ShellsKeyList(cfgPath, shellID string) error {
	_, err := loadRelayConfig(cfgPath)
	if err != nil {
		return err
	}

	var result struct {
		Keys []map[string]string `json:"keys"`
	}

	if err := apiRequest("GET", "/api/shells/"+shellID+"/keys", nil, &result); err != nil {
		return err
	}

	if len(result.Keys) == 0 {
		fmt.Println("no keys")
		return nil
	}

	for _, k := range result.Keys {
		fmt.Printf("%s %s %s\n", k["type"], k["key"], k["comment"])
	}
	return nil
}
