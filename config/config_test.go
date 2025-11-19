package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadValidConfig tests loading a valid YAML config
func TestLoadValidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `server:
  bind: "127.0.0.1:5300"
  timeout: 10

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /data/blocklist.txt

metrics:
  prometheus_endpoint: "0.0.0.0:9090"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Server.Bind != "127.0.0.1:5300" {
		t.Errorf("expected bind 127.0.0.1:5300, got %s", cfg.Server.Bind)
	}

	if cfg.Server.Timeout != 10 {
		t.Errorf("expected timeout 10, got %d", cfg.Server.Timeout)
	}

	if len(cfg.Zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(cfg.Zones))
	}

	t.Log("Valid config loaded successfully")
}

// TestLoadInvalidYAML tests loading config with invalid YAML syntax
func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "bad.yaml")
	badYAML := `server:
  bind: "unclosed string
zones: [this is bad
`
	if err := os.WriteFile(configPath, []byte(badYAML), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("should have rejected invalid YAML")
	}

	t.Log("Invalid YAML correctly rejected")
}

// TestLoadMissingConfigFile tests loading nonexistent config file
func TestLoadMissingConfigFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("should have failed to load missing config")
	}

	t.Log("Missing config file correctly rejected")
}

// TestDefaultConfigValues tests that default values are applied
func TestDefaultConfigValues(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "minimal.yaml")
	minimal := `server:
  bind: "0.0.0.0:53"
`
	if err := os.WriteFile(configPath, []byte(minimal), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Check defaults
	if cfg.Server.Timeout != 5 {
		t.Errorf("expected default timeout 5, got %d", cfg.Server.Timeout)
	}

	if !cfg.Server.AutoReload {
		t.Error("expected auto_reload default to be true")
	}

	if cfg.Server.ReloadDebounce != 2 {
		t.Errorf("expected default debounce 2, got %d", cfg.Server.ReloadDebounce)
	}

	t.Log("Default config values applied correctly")
}

// TestLoadConfigWithMultipleZones tests config with multiple zones
func TestLoadConfigWithMultipleZones(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "multi.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones:
  - name: bl1.example.com
    type: ip4trie
    files:
      - /data/bl1.txt

  - name: bl2.example.com
    type: ip4set
    files:
      - /data/bl2.txt

  - name: wl.example.com
    type: generic
    files:
      - /data/wl.txt
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if len(cfg.Zones) != 3 {
		t.Errorf("expected 3 zones, got %d", len(cfg.Zones))
	}

	t.Log("Multiple zones loaded successfully")
}

// TestLoadConfigWithACLRules tests config with inline ACL rules
func TestLoadConfigWithACLRules(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "acl.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /data/blocklist.txt
    acl_rules:
      allow:
        - 192.168.0.0/16
        - 10.0.0.0/8
      deny:
        - 203.0.113.0/24
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	zone := cfg.Zones[0]
	if len(zone.ACLRule.Allow) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(zone.ACLRule.Allow))
	}

	if len(zone.ACLRule.Deny) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(zone.ACLRule.Deny))
	}

	t.Log("ACL rules loaded successfully")
}

// TestLoadConfigWithACLFile tests config with ACL file reference
func TestLoadConfigWithACLFile(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /data/blocklist.txt
    acl: /etc/rbldnsd/acl.txt
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	zone := cfg.Zones[0]
	if zone.ACL != "/etc/rbldnsd/acl.txt" {
		t.Errorf("expected ACL path /etc/rbldnsd/acl.txt, got %s", zone.ACL)
	}

	t.Log("ACL file reference loaded successfully")
}

// TestLoadConfigWithSOA tests config with SOA records
func TestLoadConfigWithSOA(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "soa.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /data/blocklist.txt
    ns:
      - ns1.example.com
      - ns2.example.com
    soa:
      mname: ns1.example.com
      rname: hostmaster.example.com
      serial: 2024010101
      refresh: 3600
      retry: 600
      expire: 86400
      minimum: 3600
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	zone := cfg.Zones[0]
	if zone.SOA.MName != "ns1.example.com" {
		t.Errorf("expected mname ns1.example.com, got %s", zone.SOA.MName)
	}

	if zone.SOA.Serial != 2024010101 {
		t.Errorf("expected serial 2024010101, got %d", zone.SOA.Serial)
	}

	t.Log("SOA records loaded successfully")
}

// TestLoadConfigWithMetrics tests config with metrics settings
func TestLoadConfigWithMetrics(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "metrics.yaml")
	content := `server:
  bind: "0.0.0.0:53"

metrics:
  prometheus_endpoint: "0.0.0.0:9090"
  otel_endpoint: "http://localhost:4318"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Metrics.PrometheusEndpoint != "0.0.0.0:9090" {
		t.Errorf("expected prometheus endpoint 0.0.0.0:9090, got %s", cfg.Metrics.PrometheusEndpoint)
	}

	t.Log("Metrics config loaded successfully")
}

// TestLoadConfigAutoReloadSettings tests auto_reload configuration
func TestLoadConfigAutoReloadSettings(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "autoreload.yaml")
	content := `server:
  bind: "0.0.0.0:53"
  auto_reload: true
  reload_debounce: 5
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if !cfg.Server.AutoReload {
		t.Error("expected auto_reload to be true")
	}

	if cfg.Server.ReloadDebounce != 5 {
		t.Errorf("expected reload_debounce 5, got %d", cfg.Server.ReloadDebounce)
	}

	t.Log("Auto-reload settings loaded successfully")
}

// TestLoadConfigWithMultipleFiles tests zone with multiple files
func TestLoadConfigWithMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "multifile.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /data/bl1.txt
      - /data/bl2.txt
      - /data/bl3.txt
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	zone := cfg.Zones[0]
	if len(zone.Files) != 3 {
		t.Errorf("expected 3 files, got %d", len(zone.Files))
	}

	t.Log("Zone with multiple files loaded successfully")
}

// TestLoadConfigEmptyZones tests config with empty zones list
func TestLoadConfigEmptyZones(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "nozones.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones: []
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if len(cfg.Zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(cfg.Zones))
	}

	t.Log("Config with empty zones list loaded successfully")
}

// TestConfigManagerInitialization tests ConfigManager creation
func TestConfigManagerInitialization(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `server:
  bind: "0.0.0.0:53"

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /data/blocklist.txt
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cm, err := NewConfigManager(configPath, nil)
	if err != nil {
		t.Fatalf("failed to create config manager: %v", err)
	}

	// Verify initial config is loaded
	if cm.Get() == nil {
		t.Fatal("config manager should load initial config")
	}

	if cm.Get().Server.Bind != "0.0.0.0:53" {
		t.Errorf("expected bind 0.0.0.0:53, got %s", cm.Get().Server.Bind)
	}

	t.Log("ConfigManager initialized successfully")
}
