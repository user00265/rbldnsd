// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package dataset implements all dataset types for rbldnsd.
// It includes generic, ip4set, ip4trie, ip4tset, ip6trie, ip6tset, and dnset datasets.
// Each dataset type handles zone file parsing and query lookups.
package dataset

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// QueryResult represents the result of a dataset query.
// Matches Spamhaus rbldnsd behavior: stores both A and TXT records.
type QueryResult struct {
	TTL         uint32
	ARecord     string // A record value (e.g., "127.0.0.2")
	TXTTemplate string // TXT template with $ for substitution
}

// Dataset is the interface that all dataset types must implement.
type Dataset interface {
	Query(name string, qtype uint16) (*QueryResult, error)
	Count() int
}

// GenericEntry represents an A, TXT, MX, or AAAA record.
type GenericEntry struct {
	Name  string
	Type  uint16
	TTL   uint32
	Value string // Store as string, not bytes
}

// GenericDataset stores generic DNS records
type GenericDataset struct {
	entries map[string][]*GenericEntry
}

func (ds *GenericDataset) Count() int {
	count := 0
	for _, entries := range ds.entries {
		count += len(entries)
	}
	return count
}

// IP4SetEntry represents an IPv4 address/range with optional return value
type IP4SetEntry struct {
	IP       net.IP
	Mask     net.IPMask
	Value    string
	TTL      uint32
	Excluded bool
}

// IP4SetDataset stores IPv4 entries sorted for efficient lookup
type IP4SetDataset struct {
	entries   []*IP4SetEntry
	def       string
	defTTL    uint32
	maxRange  int   // Maximum CIDR prefix length (for $MAXRANGE4)
	timestamp int64 // Zone file modification time (for $TIMESTAMP)
}

func (ds *IP4SetDataset) Count() int {
	return len(ds.entries)
}

// IP4TrieNode is a node in the IP4 trie
type IP4TrieNode struct {
	Value    string
	TTL      uint32
	Children [2]*IP4TrieNode
	Excluded bool
	IsEntry  bool // true if this node represents an actual entry (not just intermediate)
}

// IP4TrieDataset uses a trie for efficient IP matching
type IP4TrieDataset struct {
	root      *IP4TrieNode
	defVal    string
	defTTL    uint32
	maxRange  int   // Maximum CIDR prefix length (for $MAXRANGE4)
	timestamp int64 // Zone file modification time (for $TIMESTAMP)
}

func (ds *IP4TrieDataset) Count() int {
	return ds.countNodes(ds.root)
}

func (ds *IP4TrieDataset) countNodes(node *IP4TrieNode) int {
	if node == nil {
		return 0
	}
	count := 0
	if node.IsEntry {
		count = 1
	}
	return count + ds.countNodes(node.Children[0]) + ds.countNodes(node.Children[1])
}

// CombinedDataset holds multiple datasets and queries them in order
type CombinedDataset struct {
	datasets []Dataset
}

func (ds *CombinedDataset) Count() int {
	count := 0
	for _, d := range ds.datasets {
		count += d.Count()
	}
	return count
}

func (ds *CombinedDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	// Query each dataset in order until one returns a result
	for _, d := range ds.datasets {
		result, err := d.Query(name, qtype)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
	}
	return nil, nil
}

func Load(dataType string, files []string, defaultTTL uint32) (Dataset, error) {
	switch dataType {
	case "generic":
		return loadGeneric(files, defaultTTL)
	case "ip4set":
		return loadIP4Set(files, defaultTTL)
	case "ip4trie":
		return loadIP4Trie(files, defaultTTL)
	case "ip4tset":
		return loadIP4TSet(files, defaultTTL)
	case "ip6trie":
		return loadIP6Trie(files, defaultTTL)
	case "ip6tset":
		return loadIP6TSet(files, defaultTTL)
	case "dnset":
		return loadDNSet(files, defaultTTL)
	case "combined":
		return loadCombined(files, defaultTTL)
	default:
		return nil, ErrUnknownDataType
	}
}

func loadIP6Trie(files []string, defaultTTL uint32) (Dataset, error) {
	ds := &IP6TrieDataset{
		root:   &IP6TrieNode{Children: make(map[string]*IP6TrieNode)},
		defTTL: defaultTTL,
	}

	for _, file := range files {
		if err := parseIP6TrieFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func loadGeneric(files []string, defaultTTL uint32) (Dataset, error) {
	ds := &GenericDataset{
		entries: make(map[string][]*GenericEntry),
	}

	for _, file := range files {
		if err := parseGenericFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func loadIP4Set(files []string, defaultTTL uint32) (Dataset, error) {
	ds := &IP4SetDataset{
		entries: make([]*IP4SetEntry, 0),
		defTTL:  defaultTTL,
	}

	for _, file := range files {
		if err := parseIP4SetFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func loadIP4Trie(files []string, defaultTTL uint32) (Dataset, error) {
	ds := &IP4TrieDataset{
		root:   &IP4TrieNode{},
		defTTL: defaultTTL,
	}

	for _, file := range files {
		if err := parseIP4TrieFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func loadCombined(files []string, defaultTTL uint32) (Dataset, error) {
	combined := &CombinedDataset{
		datasets: make([]Dataset, 0),
	}

	// For combined datasets, each file spec can be "type:filename"
	// If no type prefix, attempt auto-detection
	for _, fileSpec := range files {
		parts := strings.SplitN(fileSpec, ":", 2)
		var dsType string
		var filename string

		if len(parts) == 2 {
			// Explicit type specified
			dsType = parts[0]
			filename = parts[1]
		} else {
			// Auto-detect based on file content
			filename = fileSpec
			detectedType, err := detectDatasetType(filename)
			if err != nil {
				return nil, fmt.Errorf("failed to detect dataset type for %s: %w", filename, err)
			}
			dsType = detectedType
		}

		// Load the individual dataset
		ds, err := Load(dsType, []string{filename}, defaultTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s as %s: %w", filename, dsType, err)
		}

		combined.datasets = append(combined.datasets, ds)
	}

	return combined, nil
}

// detectDatasetType attempts to auto-detect the dataset type from file content
func detectDatasetType(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip directives
		if strings.HasPrefix(line, "$") || strings.HasPrefix(line, ":") || strings.HasPrefix(line, "!") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Check first field to determine type
		firstField := fields[0]

		// Check if it's an IPv6 address (contains colons, not a port)
		if strings.Contains(firstField, ":") && strings.Count(firstField, ":") > 1 {
			return "ip6trie", nil
		}

		// Check if it's an IPv4 address or CIDR
		if ip := net.ParseIP(firstField); ip != nil {
			return "ip4trie", nil
		}
		if _, _, err := net.ParseCIDR(firstField); err == nil {
			return "ip4trie", nil
		}

		// Check for DNS record format (has record type like A, TXT, MX)
		if len(fields) >= 3 {
			for i := 1; i < len(fields); i++ {
				recordType := strings.ToUpper(fields[i])
				if recordType == "A" || recordType == "TXT" || recordType == "MX" || recordType == "AAAA" {
					return "generic", nil
				}
			}
		}

		// Assume domain name = dnset
		return "dnset", nil
	}

	// Default to generic if can't determine
	return "generic", scanner.Err()
}

// GenericDataset.Query looks up a record in the generic dataset
func (ds *GenericDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	entries, ok := ds.entries[name]
	if !ok || len(entries) == 0 {
		return nil, nil
	}

	// Generic dataset returns actual record values, not A|TXT format
	// For A records, return IP; for TXT, return text
	var aRecord string
	var txtTemplate string
	var ttl uint32

	for _, entry := range entries {
		if entry.Type == qtype || qtype == 255 { // 255 = ANY
			if entry.Type == 1 { // A record
				aRecord = entry.Value
			} else if entry.Type == 16 { // TXT record
				txtTemplate = entry.Value
			}
			if ttl == 0 || entry.TTL < ttl {
				ttl = entry.TTL
			}
		}
	}

	if aRecord == "" && txtTemplate == "" {
		return nil, nil
	}

	return &QueryResult{TTL: ttl, ARecord: aRecord, TXTTemplate: txtTemplate}, nil
}

// IP4SetDataset.Query looks up an IP in the IP4 set
func (ds *IP4SetDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	ip := parseReverseIP(name)
	if ip == nil {
		return nil, nil
	}

	for _, entry := range ds.entries {
		ipnet := &net.IPNet{IP: entry.IP, Mask: entry.Mask}
		if ipnet.Contains(ip) {
			if entry.Excluded {
				continue
			}
			value := entry.Value
			if value == "" {
				value = ds.def
			}
			if value == "" {
				value = "127.0.0.2|"
			}
			// Split A|TXT format
			parts := strings.SplitN(value, "|", 2)
			aRecord := parts[0]
			txtTemplate := ""
			if len(parts) > 1 {
				txtTemplate = parts[1]
			}
			return &QueryResult{TTL: entry.TTL, ARecord: aRecord, TXTTemplate: txtTemplate}, nil
		}
	}

	if ds.def != "" {
		parts := strings.SplitN(ds.def, "|", 2)
		aRecord := parts[0]
		txtTemplate := ""
		if len(parts) > 1 {
			txtTemplate = parts[1]
		}
		return &QueryResult{TTL: ds.defTTL, ARecord: aRecord, TXTTemplate: txtTemplate}, nil
	}

	return nil, nil
}

// IP4TrieDataset.Query looks up an IP in the trie
func (ds *IP4TrieDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	ip := parseReverseIP(name)
	if ip == nil {
		return nil, nil
	}

	node := ds.findNode(ip)
	if node == nil || !node.IsEntry || node.Excluded {
		return nil, nil
	}

	value := node.Value
	if value == "" {
		value = ds.defVal
	}
	if value == "" {
		value = "127.0.0.2|"
	}

	// Split A|TXT format
	parts := strings.SplitN(value, "|", 2)
	aRecord := parts[0]
	txtTemplate := ""
	if len(parts) > 1 {
		txtTemplate = parts[1]
	}
	// Substitute variables in TXT template
	txtTemplate = substituteTXTWithMetadata(txtTemplate, ip.String(), ds.timestamp, ds.maxRange, false)

	ttl := node.TTL
	if ttl == 0 {
		ttl = ds.defTTL
	}

	return &QueryResult{TTL: ttl, ARecord: aRecord, TXTTemplate: txtTemplate}, nil
}

// findNode traverses the trie for an IP address
func (ds *IP4TrieDataset) findNode(ip net.IP) *IP4TrieNode {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	node := ds.root
	var best *IP4TrieNode

	for _, octet := range ip4 {
		for bit := 7; bit >= 0; bit-- {
			if node == nil {
				break
			}

			// Check if current node has a value
			if node.Value != "" {
				best = node
			}

			// Traverse based on bit
			idx := (octet >> uint(bit)) & 1
			node = node.Children[idx]
		}
	}

	if node != nil && node.Value != "" {
		best = node
	}

	return best
}

// parseReverseIP converts a reverse DNS name to an IP address
func parseReverseIP(name string) net.IP {
	// Remove trailing dot
	name = strings.TrimSuffix(name, ".")

	parts := strings.Split(name, ".")
	if len(parts) < 4 {
		return nil
	}

	// Reverse the first 4 parts
	ip := net.IP{0, 0, 0, 0}
	for i := 0; i < 4; i++ {
		var val int
		if _, err := fmt.Sscanf(parts[i], "%d", &val); err != nil {
			return nil
		}
		if val < 0 || val > 255 {
			return nil
		}
		ip[3-i] = byte(val)
	}

	return ip
}

// parseReverseIPv6 converts a reverse DNS IPv6 name to an IP address
// Format: x.x.x.x....x.x.ip6.arpa (32 nibbles reversed)
func parseReverseIPv6(name string) net.IP {
	// Remove trailing dot
	name = strings.TrimSuffix(name, ".")

	// Remove .ip6.arpa suffix if present
	name = strings.TrimSuffix(name, ".ip6.arpa")

	parts := strings.Split(name, ".")
	if len(parts) != 32 {
		return nil
	}

	// Each part is a hex nibble, reversed
	ip := make(net.IP, 16)
	for i := 0; i < 32; i++ {
		var val int
		if _, err := fmt.Sscanf(parts[i], "%x", &val); err != nil {
			return nil
		}
		if val < 0 || val > 15 {
			return nil
		}
		// Reverse order: parts[0] is the last nibble
		byteIdx := 15 - (i / 2)
		if i%2 == 0 {
			ip[byteIdx] |= byte(val)
		} else {
			ip[byteIdx] |= byte(val << 4)
		}
	}

	return ip
}

// ipv6Equal compares two IPv6 addresses for equality
func ipv6Equal(a, b net.IP) bool {
	a16 := a.To16()
	b16 := b.To16()
	if a16 == nil || b16 == nil {
		return false
	}
	return a16.Equal(b16)
}
