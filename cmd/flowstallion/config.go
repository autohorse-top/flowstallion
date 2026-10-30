// config.go: persistent CLI config at ~/.flowstallion/config.json.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type config struct {
	Server string `json:"server"`
	// User and Token are set by `flowstallion login <url> -u <user> -p <pass>` and sent
	// as `Authorization: Bearer` on every request (P6①). The token stays in
	// this owner-only file and is never printed by the CLI.
	User  string `json:"user,omitempty"`
	Token string `json:"token,omitempty"`
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".flowstallion", "config.json"), nil
}

// loadConfig reads the CLI config. Errors if it is missing or the server URL
// is empty — callers must tell the user to run `flowstallion login` first.
func loadConfig() (config, error) {
	p, err := configPath()
	if err != nil {
		return config{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return config{}, fmt.Errorf("no server configured (%s not found). Run `flowstallion login <url>` first", p)
	}
	var c config
	if err := json.Unmarshal(data, &c); err != nil {
		return config{}, fmt.Errorf("corrupt config %s: %w", p, err)
	}
	if c.Server == "" {
		return config{}, fmt.Errorf("config %s has no server URL. Run `flowstallion login <url>`", p)
	}
	return c, nil
}

// saveConfig writes the config with owner-only permissions.
func saveConfig(c config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return nil
}
