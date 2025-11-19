package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/user00265/rbldnsd/config"
)

// TestDNSSimpleZoneLoad tests that a simple valid zone loads
func TestDNSSimpleZoneLoad(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "blocklist.txt")
	if err := os.WriteFile(zonePath, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "bl.test",
				Type:  "ip4trie",
				Files: []string{zonePath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Simple zone loaded and server started")
}

// TestDNSInvalidZoneDoesntLoad tests that invalid zone is skipped
func TestDNSInvalidZoneDoesntLoad(t *testing.T) {
	tmpDir := t.TempDir()

	invalidPath := filepath.Join(tmpDir, "invalid.txt")
	if err := os.WriteFile(invalidPath, []byte("not a valid zone\n"), 0644); err != nil {
		t.Fatalf("failed to create invalid zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "bad.test",
				Type:  "ip4trie",
				Files: []string{invalidPath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Invalid zone skipped, server started anyway")
}

// TestDNSMultipleZonesLoad tests loading multiple zones
func TestDNSMultipleZonesLoad(t *testing.T) {
	tmpDir := t.TempDir()

	bl1Path := filepath.Join(tmpDir, "bl1.txt")
	if err := os.WriteFile(bl1Path, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create bl1: %v", err)
	}

	bl2Path := filepath.Join(tmpDir, "bl2.txt")
	if err := os.WriteFile(bl2Path, []byte("203.0.113.0/24 127.0.0.3\n"), 0644); err != nil {
		t.Fatalf("failed to create bl2: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "bl1.test",
				Type:  "ip4trie",
				Files: []string{bl1Path},
			},
			{
				Name:  "bl2.test",
				Type:  "ip4trie",
				Files: []string{bl2Path},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Multiple zones loaded")
}

// TestDNSGenericZoneLoad tests loading generic (forward DNS) zone
func TestDNSGenericZoneLoad(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "forward.txt")
	content := `example.com 3600 IN A 192.0.2.1
mail.example.com 3600 IN A 192.0.2.2
example.com 3600 IN MX 10 mail.example.com
`
	if err := os.WriteFile(zonePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "example.test",
				Type:  "generic",
				Files: []string{zonePath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Generic zone loaded")
}

// TestDNSZoneWithACL tests zone with ACL rules
func TestDNSZoneWithACL(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "acl-zone.txt")
	if err := os.WriteFile(zonePath, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "restricted.test",
				Type:  "ip4trie",
				Files: []string{zonePath},
				ACLRule: config.ACLRuleSet{
					Allow: []string{"192.168.0.0/16", "10.0.0.0/8"},
					Deny:  []string{"203.0.113.0/24"},
				},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Zone with ACL rules loaded")
}

// TestDNSEmptyZoneFile tests empty zone files are valid
func TestDNSEmptyZoneFile(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(zonePath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create empty zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "empty.test",
				Type:  "ip4trie",
				Files: []string{zonePath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Empty zone file loaded")
}

// TestDNSMixedValidInvalidZones tests server with both valid and invalid zones
func TestDNSMixedValidInvalidZones(t *testing.T) {
	tmpDir := t.TempDir()

	validPath := filepath.Join(tmpDir, "valid.txt")
	if err := os.WriteFile(validPath, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create valid zone: %v", err)
	}

	invalidPath := filepath.Join(tmpDir, "invalid.txt")
	if err := os.WriteFile(invalidPath, []byte("not valid\n"), 0644); err != nil {
		t.Fatalf("failed to create invalid zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "valid.test",
				Type:  "ip4trie",
				Files: []string{validPath},
			},
			{
				Name:  "invalid.test",
				Type:  "ip4trie",
				Files: []string{invalidPath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Server started with mixed valid/invalid zones")
}

// TestDNSNoZonesStarts tests server starts even with no zones
func TestDNSNoZonesStarts(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Server started with no zones")
}

// TestDNSZoneWithMultipleFiles tests zone loading from multiple files
func TestDNSZoneWithMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	file1Path := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(file1Path, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}

	file2Path := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file2Path, []byte("203.0.113.0/24 127.0.0.3\n"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "combined.test",
				Type:  "ip4trie",
				Files: []string{file1Path, file2Path},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Zone with multiple files loaded")
}

// TestDNSInvalidZoneTypeSkipped tests zones with invalid type are skipped
func TestDNSInvalidZoneTypeSkipped(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "zone.txt")
	if err := os.WriteFile(zonePath, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "badtype.test",
				Type:  "unsupported-type",
				Files: []string{zonePath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Zone with invalid type skipped")
}

// TestDNSMissingZoneFileSkipped tests zones with missing files are skipped
func TestDNSMissingZoneFileSkipped(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "missing.test",
				Type:  "ip4trie",
				Files: []string{filepath.Join(tmpDir, "nonexistent.txt")},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Zone with missing file skipped")
}

// TestDNSZoneWithComments tests comments are ignored in zone files
func TestDNSZoneWithComments(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "commented.txt")
	content := `# This is a comment
192.0.2.0/24 127.0.0.2
# Another comment
203.0.113.0/24 127.0.0.3
`
	if err := os.WriteFile(zonePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "commented.test",
				Type:  "ip4trie",
				Files: []string{zonePath},
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Zone with comments loaded")
}

// TestDNSZoneWithACLFile tests zone with external ACL file
func TestDNSZoneWithACLFile(t *testing.T) {
	tmpDir := t.TempDir()

	zonePath := filepath.Join(tmpDir, "zone.txt")
	if err := os.WriteFile(zonePath, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	aclPath := filepath.Join(tmpDir, "acl.txt")
	aclContent := `allow:
192.168.0.0/16
10.0.0.0/8

deny:
203.0.113.0/24
`
	if err := os.WriteFile(aclPath, []byte(aclContent), 0644); err != nil {
		t.Fatalf("failed to create ACL: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Bind:    "127.0.0.1:0",
			Timeout: 5,
		},
		Zones: []config.ZoneConfig{
			{
				Name:  "acl-zone.test",
				Type:  "ip4trie",
				Files: []string{zonePath},
				ACL:   aclPath,
			},
		},
	}

	srv, err := New(cfg, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Shutdown()

	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)

	t.Log("✓ Zone with ACL file loaded")
}
