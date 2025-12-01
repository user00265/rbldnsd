// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package config handles YAML configuration file parsing and validation.
// It defines zone configurations, server settings, and metrics options.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Zones   []ZoneConfig  `yaml:"zones"`
	Metrics MetricsConfig `yaml:"metrics"`
	Logging LoggingConfig `yaml:"logging"`
}

type ServerConfig struct {
	Bind           string `yaml:"bind"`
	Timeout        int    `yaml:"timeout"`
	AutoReload     bool   `yaml:"auto_reload"`     // Enable automatic zone file monitoring
	ReloadDebounce int    `yaml:"reload_debounce"` // Debounce time in seconds (default: 2)
}

type ZoneConfig struct {
	Name    string     `yaml:"name"`
	Type    string     `yaml:"type"`
	Files   []string   `yaml:"files"`
	ACL     string     `yaml:"acl"`       // Path to ACL file
	ACLRule ACLRuleSet `yaml:"acl_rules"` // Inline ACL rules
	NS      []string   `yaml:"ns"`        // Nameservers
	SOA     SOAConfig  `yaml:"soa"`       // SOA record
}

// SOAConfig defines SOA record parameters
type SOAConfig struct {
	MName   string `yaml:"mname"`   // Primary nameserver
	RName   string `yaml:"rname"`   // Responsible email
	Serial  uint32 `yaml:"serial"`  // Serial number
	Refresh uint32 `yaml:"refresh"` // Refresh interval (default 3600)
	Retry   uint32 `yaml:"retry"`   // Retry interval (default 600)
	Expire  uint32 `yaml:"expire"`  // Expire time (default 86400)
	Minimum uint32 `yaml:"minimum"` // Minimum TTL (default 3600)
}

// ACLRuleSet defines allow/deny rules inline in config
type ACLRuleSet struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type MetricsConfig struct {
	PrometheusEndpoint string `yaml:"prometheus_endpoint"`
	OTELEndpoint       string `yaml:"otel_endpoint"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

// LoadConfig loads and parses a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{
		Server: ServerConfig{
			Bind:           "0.0.0.0:53",
			Timeout:        5,
			AutoReload:     true, // Enable by default
			ReloadDebounce: 2,    // 2 second debounce
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// ZoneSpecs converts zone config to CLI format for backward compatibility
func (c *Config) ZoneSpecs() string {
	var specs []string
	for _, z := range c.Zones {
		files := strings.Join(z.Files, ",")
		specs = append(specs, fmt.Sprintf("%s:%s:%s", z.Name, z.Type, files))
	}
	return strings.Join(specs, " ")
}

// Example returns a YAML example config
func Example() string {
	return `# rbldnsd Configuration

server:
  bind: "0.0.0.0:53"
  timeout: 5
  auto_reload: true        # Automatically reload zones when files change
  reload_debounce: 2       # Wait 2 seconds before reloading (prevents rapid reloads)

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /etc/rbldnsd/blocklist.txt
    # Option 1: ACL from file
    acl: /etc/rbldnsd/acl-bl.txt
    # NS and SOA records for the zone
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

  - name: restricted.example.com
    type: generic
    files:
      - /etc/rbldnsd/whitelist.txt
    # Option 2: Inline ACL rules
    acl_rules:
      allow:
        - 192.168.0.0/16
        - 10.0.0.0/8
        - 127.0.0.1
      deny:
        - 203.0.113.0/24

  - name: public.example.com
    type: ip4trie
    files:
      - /etc/rbldnsd/public-list.txt
    # No ACL - public access

metrics:
  prometheus_endpoint: "localhost:9090"
  otel_endpoint: "localhost:4318"

logging:
  level: "info"
`
}
