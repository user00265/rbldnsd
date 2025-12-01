// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package dataset implements all dataset types for rbldnsd.
// It includes generic, ip4set, ip4trie, ip4tset, ip6trie, ip6tset, and dnset datasets.
// Each dataset type handles zone file parsing and query lookups.
package dataset

import (
	"fmt"
	"net"
	"strings"
)

// QueryResult represents the result of a dataset query.
type QueryResult struct {
	TTL    uint32
	Values []string // Can be IP addresses or text
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
	entries []*IP4SetEntry
	def     string
	defTTL  uint32
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
}

// IP4TrieDataset uses a trie for efficient IP matching
type IP4TrieDataset struct {
	root   *IP4TrieNode
	defVal string
	defTTL uint32
}

func (ds *IP4TrieDataset) Count() int {
	return ds.countNodes(ds.root)
}

func (ds *IP4TrieDataset) countNodes(node *IP4TrieNode) int {
	if node == nil {
		return 0
	}
	count := 0
	if node.Value != "" || node.Excluded {
		count = 1
	}
	return count + ds.countNodes(node.Children[0]) + ds.countNodes(node.Children[1])
}

func Load(dataType string, files []string) (Dataset, error) {
	switch dataType {
	case "generic":
		return loadGeneric(files)
	case "ip4set":
		return loadIP4Set(files)
	case "ip4trie":
		return loadIP4Trie(files)
	case "ip4tset":
		return loadIP4TSet(files)
	case "ip6trie":
		return loadIP6Trie(files)
	case "ip6tset":
		return loadIP6TSet(files)
	case "dnset":
		return loadDNSet(files)
	default:
		return nil, ErrUnknownDataType
	}
}

func loadIP6Trie(files []string) (Dataset, error) {
	ds := &IP6TrieDataset{
		root:   &IP6TrieNode{Children: make(map[string]*IP6TrieNode)},
		defTTL: 3600,
	}

	for _, file := range files {
		if err := parseIP6TrieFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func loadGeneric(files []string) (Dataset, error) {
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

func loadIP4Set(files []string) (Dataset, error) {
	ds := &IP4SetDataset{
		entries: make([]*IP4SetEntry, 0),
		defTTL:  3600,
	}

	for _, file := range files {
		if err := parseIP4SetFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func loadIP4Trie(files []string) (Dataset, error) {
	ds := &IP4TrieDataset{
		root:   &IP4TrieNode{},
		defTTL: 3600,
	}

	for _, file := range files {
		if err := parseIP4TrieFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

// GenericDataset.Query looks up a record in the generic dataset
func (ds *GenericDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	entries, exists := ds.entries[strings.ToLower(name)]
	if !exists {
		return nil, nil
	}

	var values []string
	var ttl uint32

	for _, entry := range entries {
		if entry.Type == qtype {
			if ttl == 0 {
				ttl = entry.TTL
			}
			values = append(values, entry.Value)
		}
	}

	if len(values) == 0 {
		return nil, nil
	}

	return &QueryResult{TTL: ttl, Values: values}, nil
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
			if entry.Value == "" {
				entry.Value = ds.def
			}
			if entry.Value == "" {
				return nil, nil
			}
			return &QueryResult{TTL: entry.TTL, Values: []string{entry.Value}}, nil
		}
	}

	if ds.def != "" {
		return &QueryResult{TTL: ds.defTTL, Values: []string{ds.def}}, nil
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
	if node == nil || node.Excluded {
		return nil, nil
	}

	value := node.Value
	if value == "" {
		value = ds.defVal
	}
	if value == "" {
		return nil, nil
	}

	ttl := node.TTL
	if ttl == 0 {
		ttl = ds.defTTL
	}

	return &QueryResult{TTL: ttl, Values: []string{value}}, nil
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
