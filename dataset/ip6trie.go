// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package dataset

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"strings"
)

// IP6TrieNode is a node in the IPv6 trie (simplified for /64 blocks)
type IP6TrieNode struct {
	Value    string
	TTL      uint32
	Children map[string]*IP6TrieNode
	Excluded bool
}

// IP6TrieDataset uses a trie for efficient IPv6 matching
type IP6TrieDataset struct {
	root   *IP6TrieNode
	defVal string
	defTTL uint32
}

// Query looks up an IPv6 address in the trie
func (ds *IP6TrieDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	ip := parseReverseIP6(name)
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

// findNode traverses the trie for an IPv6 address
func (ds *IP6TrieDataset) findNode(ip net.IP) *IP6TrieNode {
	ip6 := ip.To16()
	if ip6 == nil {
		return nil
	}

	node := ds.root
	var best *IP6TrieNode

	// For IPv6, we use hex nibbles (4 bits at a time)
	for _, byte_ := range ip6 {
		for shift := 4; shift >= 0; shift -= 4 {
			if node == nil {
				break
			}

			if node.Value != "" {
				best = node
			}

			// Extract 4-bit nibble
			nibble := (byte_ >> uint(shift)) & 0x0F
			key := []byte{byte((nibble >> 3) & 1)}
			for i := 2; i >= 0; i-- {
				key[0] = key[0]<<1 | byte((nibble>>uint(i))&1)
			}

			keyStr := string(key)
			if next, exists := node.Children[keyStr]; exists {
				node = next
			} else {
				node = nil
			}
		}
	}

	if node != nil && node.Value != "" {
		best = node
	}

	return best
}

// parseReverseIP6 converts a reverse IPv6 DNS name to an IPv6 address
func parseReverseIP6(name string) net.IP {
	// Remove trailing dot
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}

	parts := strings.Split(name, ".")
	// IPv6 reverse DNS format: individual hex digits separated by dots
	// 2001:db8::1 -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
	// We expect at least 32 parts for a full IPv6 address
	if len(parts) < 32 {
		return nil
	}

	// Reconstruct the IPv6 address from reversed hex digits
	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		// Each byte is represented by 2 hex digits (reversed order)
		high := parts[31-i*2]
		low := parts[31-i*2-1]

		// Parse hex digits
		var val byte
		for _, ch := range []byte(high) {
			if ch >= '0' && ch <= '9' {
				val = (val << 4) | (ch - '0')
			} else if ch >= 'a' && ch <= 'f' {
				val = (val << 4) | (ch - 'a' + 10)
			} else {
				return nil
			}
		}
		for _, ch := range []byte(low) {
			if ch >= '0' && ch <= '9' {
				val = (val << 4) | (ch - '0')
			} else if ch >= 'a' && ch <= 'f' {
				val = (val << 4) | (ch - 'a' + 10)
			} else {
				return nil
			}
		}
		ip[i] = val
	}

	return ip
}

// parseIP6TrieFile parses an ip6trie zone file
func parseIP6TrieFile(filename string, ds *IP6TrieDataset) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip directives
		if strings.HasPrefix(line, "$") {
			continue
		}

		// Handle exclusion
		excluded := false
		if strings.HasPrefix(line, "!") {
			excluded = true
			line = line[1:]
		}

		// Handle default value
		if strings.HasPrefix(line, ":") {
			parts := strings.SplitN(line[1:], ":", 2)
			if len(parts) > 0 {
				ds.defVal = parts[0]
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}

		ipStr := fields[0]
		value := ""
		if len(fields) > 1 {
			value = fields[1]
		}

		// Parse IP/CIDR
		var ipnet *net.IPNet
		var ip net.IP

		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try single IP
			ip = net.ParseIP(ipStr)
			if ip == nil {
				slog.Warn("invalid IPv6", "line", lineNum, "value", ipStr)
				continue
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}

		// Insert into trie
		ds.insertTrie(ipnet.IP, ipnet.Mask, value, excluded, ds.defTTL)
	}

	return scanner.Err()
}

// insertTrie inserts a CIDR block into the IPv6 trie
func (ds *IP6TrieDataset) insertTrie(ip net.IP, mask net.IPMask, value string, excluded bool, ttl uint32) {
	ip6 := ip.To16()
	if ip6 == nil {
		return
	}

	node := ds.root
	ones, _ := mask.Size()

	// For IPv6, work with 4-bit nibbles
	for i := 0; i < ones; i += 4 {
		octetIdx := i / 8
		nibbleIdx := (i % 8) / 4

		octet := ip6[octetIdx]
		var nibble byte
		if nibbleIdx == 0 {
			nibble = (octet >> 4) & 0x0F
		} else {
			nibble = octet & 0x0F
		}

		// Convert nibble to binary string key
		keyStr := ""
		for j := 3; j >= 0; j-- {
			if (nibble>>uint(j))&1 == 1 {
				keyStr += "1"
			} else {
				keyStr += "0"
			}
		}

		if node.Children == nil {
			node.Children = make(map[string]*IP6TrieNode)
		}

		if node.Children[keyStr] == nil {
			node.Children[keyStr] = &IP6TrieNode{
				Children: make(map[string]*IP6TrieNode),
			}
		}
		node = node.Children[keyStr]
	}

	node.Value = value
	node.TTL = ttl
	node.Excluded = excluded
}
