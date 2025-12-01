// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package dataset

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

// parseGenericFile parses a generic (BIND-like) zone file
func parseGenericFile(filename string, ds *GenericDataset) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	defaultTTL := uint32(3600)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle directives
		if strings.HasPrefix(line, "$") {
			parts := strings.Fields(line)
			if len(parts) > 0 && parts[0] == "$TTL" && len(parts) > 1 {
				if ttl, err := parseTTL(parts[1]); err == nil {
					defaultTTL = ttl
				}
			}
			continue
		}

		// Parse entry
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		if name == "@" {
			name = ""
		}

		idx := 1
		ttl := defaultTTL

		// Try to parse TTL
		if ttlVal, err := parseTTL(fields[idx]); err == nil {
			ttl = ttlVal
			idx++
		}

		// Skip IN class if present
		if idx < len(fields) && (fields[idx] == "IN" || fields[idx] == "in") {
			idx++
		}

		if idx >= len(fields) {
			continue
		}

		recordType := strings.ToUpper(fields[idx])
		idx++

		if idx >= len(fields) {
			continue
		}

		var qtype uint16
		var value string

		switch recordType {
		case "A":
			qtype = 1
			value = fields[idx]

		case "TXT":
			qtype = 16
			text := strings.Join(fields[idx:], " ")
			if strings.HasPrefix(text, "\"") && strings.HasSuffix(text, "\"") {
				text = text[1 : len(text)-1]
			}
			if len(text) > 255 {
				text = text[:255]
			}
			value = text

		case "MX":
			qtype = 15
			if idx+1 >= len(fields) {
				slog.Warn("MX record requires preference and exchange", "line", lineNum)
				continue
			}
			pref := fields[idx]
			exchange := fields[idx+1]
			value = pref + " " + exchange

		default:
			continue
		}

		// Normalize name (remove trailing dot if present, add it back)
		if !strings.HasSuffix(name, ".") {
			name = name + "."
		}

		key := strings.ToLower(name)
		ds.entries[key] = append(ds.entries[key], &GenericEntry{
			Name:  name,
			Type:  qtype,
			TTL:   ttl,
			Value: value,
		})
		slog.Debug("generic entry added", "name", name, "type", recordType, "value", value)
	}

	return scanner.Err()
}

// parseIP4SetFile parses an ip4set zone file
func parseIP4SetFile(filename string, ds *IP4SetDataset) error {
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
				ds.def = parts[0]
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
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try single IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				slog.Warn("invalid IP", "line", lineNum, "value", ipStr)
				continue
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}

		entry := &IP4SetEntry{
			IP:       ipnet.IP,
			Mask:     ipnet.Mask,
			Value:    value,
			TTL:      ds.defTTL,
			Excluded: excluded,
		}

		ds.entries = append(ds.entries, entry)
		slog.Debug("ip4set entry added", "ip", ipnet.String(), "value", value, "excluded", excluded)
	}

	return scanner.Err()
}

// parseIP4TrieFile parses an ip4trie zone file
func parseIP4TrieFile(filename string, ds *IP4TrieDataset) error {
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
				slog.Warn("invalid IP", "line", lineNum, "value", ipStr)
				continue
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}

		// Insert into trie
		ds.insertTrie(ipnet.IP, ipnet.Mask, value, excluded, ds.defTTL)
		slog.Debug("ip4trie entry added", "ip", ipnet.String(), "value", value, "excluded", excluded)
	}

	return scanner.Err()
}

// insertTrie inserts a CIDR block into the trie
func (ds *IP4TrieDataset) insertTrie(ip net.IP, mask net.IPMask, value string, excluded bool, ttl uint32) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}

	node := ds.root
	ones, _ := mask.Size()

	for i := 0; i < ones; i++ {
		octetIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ip4[octetIdx] >> uint(bitIdx)) & 1

		if node.Children[bit] == nil {
			node.Children[bit] = &IP4TrieNode{}
		}
		node = node.Children[bit]
	}

	node.Value = value
	node.TTL = ttl
	node.Excluded = excluded
	node.IsEntry = true
}

// parseTTL parses a TTL value with optional suffixes
func parseTTL(s string) (uint32, error) {
	multiplier := uint32(1)

	// Check for suffix
	if len(s) > 0 {
		switch s[len(s)-1] {
		case 's':
			multiplier = 1
			s = s[:len(s)-1]
		case 'm':
			multiplier = 60
			s = s[:len(s)-1]
		case 'h':
			multiplier = 3600
			s = s[:len(s)-1]
		case 'd':
			multiplier = 86400
			s = s[:len(s)-1]
		case 'w':
			multiplier = 604800
			s = s[:len(s)-1]
		}
	}

	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(val) * multiplier, nil
}

// parseValue parses a value string which may contain value and/or TTL
// Format: "value" or "value:ttl" or ":ttl"
func parseValue(s string) (string, uint32) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}

	// Check for TTL suffix (e.g., "value:3600" or ":3600")
	parts := strings.SplitN(s, ":", 2)
	value := parts[0]
	var ttl uint32

	if len(parts) > 1 && parts[1] != "" {
		if t, err := parseTTL(parts[1]); err == nil {
			ttl = t
		}
	}

	// Default value if empty
	if value == "" {
		value = "127.0.0.2"
	}

	return value, ttl
}
