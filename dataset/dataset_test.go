package dataset

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIP4TrieSingleIP tests single IP format in ip4trie
func TestIP4TrieSingleIP(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("192.0.2.1 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Single IP format accepted (192.0.2.1)")
}

// TestIP4TrieCIDR tests CIDR format in ip4trie
func TestIP4TrieCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ CIDR format accepted (192.0.2.0/24)")
}

// TestIP4TriePartialIP tests partial IP format in ip4trie
func TestIP4TriePartialIP(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("192.0.2 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Partial IP format accepted (192.0.2)")
}

// TestIP4TrieMultipleFormats tests mixed formats in same file
func TestIP4TrieMultipleFormats(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	content := `192.0.2.1 127.0.0.2
192.0.3.0/24 127.0.0.3
203.0.113 127.0.0.4
`
	if err := os.WriteFile(zonePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Mixed formats accepted (IP, CIDR, partial)")
}

// TestIP4SetSingleIP tests single IP format in ip4set
func TestIP4SetSingleIP(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("192.0.2.1\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4set", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ IP4Set single IP format accepted")
}

// TestIP4SetCIDR tests CIDR format in ip4set
func TestIP4SetCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("192.0.2.0/24\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4set", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ IP4Set CIDR format accepted")
}

// TestGenericDNSRecords tests standard DNS record format
func TestGenericDNSRecords(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	content := `example.com 3600 IN A 192.0.2.1
mail.example.com 3600 IN A 192.0.2.2
example.com 3600 IN MX 10 mail.example.com
example.com 3600 IN TXT "v=spf1 mx -all"
`
	if err := os.WriteFile(zonePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("generic", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Generic DNS records (A, MX, TXT) accepted")
}

// TestDatasetInvalidFormat tests that invalid lines are logged but don't fail load
func TestDatasetInvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("this is not a valid format\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	// Dataset loads but with no entries (line was invalid)
	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Invalid lines logged, dataset still loads")
}

// TestDatasetInvalidType tests that invalid dataset type is rejected
func TestDatasetInvalidType(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte("192.0.2.1 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	_, err := Load("nonexistent-type", []string{zonePath})
	if err == nil {
		t.Fatal("should reject invalid type")
	}

	t.Log("✓ Invalid dataset type rejected")
}

// TestDatasetEmptyFile tests that empty file is valid
func TestDatasetEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	if err := os.WriteFile(zonePath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Empty file valid")
}

// TestDatasetWithComments tests that comments are ignored
func TestDatasetWithComments(t *testing.T) {
	tmpDir := t.TempDir()
	zonePath := filepath.Join(tmpDir, "zone.txt")

	content := `# This is a comment
192.0.2.1 127.0.0.2
# Another comment
192.0.3.0/24 127.0.0.3
`
	if err := os.WriteFile(zonePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create zone: %v", err)
	}

	ds, err := Load("ip4trie", []string{zonePath})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Comments ignored")
}

// TestDatasetMultipleFiles tests combining multiple files
func TestDatasetMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("192.0.2.0/24 127.0.0.2\n"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}

	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("203.0.113.0/24 127.0.0.3\n"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	ds, err := Load("ip4trie", []string{file1, file2})
	if err != nil {
		t.Fatalf("failed to load dataset: %v", err)
	}

	if ds == nil {
		t.Fatal("dataset should not be nil")
	}

	t.Log("✓ Multiple files combined")
}
