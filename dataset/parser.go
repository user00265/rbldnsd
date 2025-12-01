// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package dataset

import (
	"bufio"
	"fmt"
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
	return parseIP4SetFileWithSilent(filename, ds, false)
}

func parseIP4SetFileWithSilent(filename string, ds *IP4SetDataset, silent bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file modification time for $TIMESTAMP
	if fileInfo, err := os.Stat(filename); err == nil {
		ds.timestamp = fileInfo.ModTime().Unix()
	}

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

		// Handle default value line (:A:TXT format)
		if strings.HasPrefix(line, ":") {
			aRecord, txtTemplate, _ := parseATxt(line)
			if aRecord != "" {
				ds.def = aRecord + "|" + txtTemplate
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

		// If no value set, use 127.0.0.2
		if value == "" {
			value = "127.0.0.2|"
		}

		// Parse IP/CIDR
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try single IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				if !silent {
					slog.Warn("invalid IP", "line", lineNum, "value", ipStr)
				}
				continue
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}

		// Track maximum CIDR prefix length for $MAXRANGE4
		ones, _ := ipnet.Mask.Size()
		if ones < ds.maxRange || ds.maxRange == 0 {
			ds.maxRange = ones
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
	return parseIP4TrieFileWithSilent(filename, ds, false)
}

func parseIP4TrieFileWithSilent(filename string, ds *IP4TrieDataset, silent bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file modification time for $TIMESTAMP
	if fileInfo, err := os.Stat(filename); err == nil {
		ds.timestamp = fileInfo.ModTime().Unix()
	}

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

		// Handle default value line (:A:TXT format)
		if strings.HasPrefix(line, ":") {
			aRecord, txtTemplate, _ := parseATxt(line)
			if aRecord != "" {
				ds.defVal = aRecord + "|" + txtTemplate
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}

		ipStr := fields[0]
		value := ds.defVal
		if len(fields) > 1 {
			// Parse A:TXT format for this entry
			aRecord, txtTemplate, _ := parseATxt(strings.Join(fields[1:], " "))
			value = aRecord + "|" + txtTemplate
		}

		// If no value set (no default and no per-entry value), use 127.0.0.2
		if value == "" {
			value = "127.0.0.2|"
		}

		// Parse IP/CIDR
		var ipnet *net.IPNet
		var ip net.IP

		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			// Try single IP
			ip = net.ParseIP(ipStr)
			if ip == nil {
				if !silent {
					slog.Warn("invalid IP", "line", lineNum, "value", ipStr)
				}
				continue
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}

		// Track maximum CIDR prefix length for $MAXRANGE4
		ones, _ := ipnet.Mask.Size()
		if ones < ds.maxRange || ds.maxRange == 0 {
			ds.maxRange = ones
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

// parseATxt parses A and TXT records in Spamhaus format: ":A:TXT"
// Returns: aRecord, txtTemplate, ttl
// Examples:
//
//	":127.0.0.2:Listed"          -> "127.0.0.2", "Listed", 0
//	":2:Spam source"             -> "127.0.0.2", "Spam source", 0
//	":127.0.0.5:"                -> "127.0.0.5", "", 0
//	"Listed: see http://x.com/$" -> "127.0.0.2", "Listed: see http://x.com/$", 0
func parseATxt(s string) (string, string, uint32) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "127.0.0.2", "", 0
	}

	// Check if starts with colon (A record specified)
	if strings.HasPrefix(s, ":") {
		// Format: :A:TXT or :A:
		parts := strings.SplitN(s[1:], ":", 2)
		aRecord := strings.TrimSpace(parts[0])
		txtTemplate := ""

		if len(parts) > 1 {
			txtTemplate = parts[1]
		}

		// Handle shorthand: :2: means 127.0.0.2
		if aRecord != "" {
			// Check if it's a single digit or two digits (127.0.0.x shorthand)
			if len(aRecord) <= 3 && !strings.Contains(aRecord, ".") {
				aRecord = "127.0.0." + aRecord
			}
		} else {
			aRecord = "127.0.0.2"
		}

		return aRecord, txtTemplate, 0
	}

	// No colon prefix - this is just TXT template, use default A
	return "127.0.0.2", s, 0
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

// substituteTXT performs $ substitution in TXT template
// Replaces $ with the provided substitution string (IP or domain)
// substituteTXT replaces variables in TXT templates
// Supports: $, $TIMESTAMP, $MAXRANGE4, $MAXRANGE6
func substituteTXT(template, subst string) string {
	if template == "" {
		return template
	}
	return strings.ReplaceAll(template, "$", subst)
}

// substituteTXTWithMetadata replaces all variables in TXT templates
// including $TIMESTAMP, $MAXRANGE4, $MAXRANGE6
func substituteTXTWithMetadata(template, subst string, timestamp int64, maxRange int, isIPv6 bool) string {
	if template == "" {
		return template
	}

	result := template

	// Replace specific variables FIRST before generic $
	// Replace $TIMESTAMP with Unix timestamp
	if timestamp > 0 {
		result = strings.ReplaceAll(result, "$TIMESTAMP", fmt.Sprintf("%d", timestamp))
	}

	// Replace $MAXRANGE4 or $MAXRANGE6 with maximum CIDR prefix
	if maxRange > 0 {
		if isIPv6 {
			result = strings.ReplaceAll(result, "$MAXRANGE6", fmt.Sprintf("%d", maxRange))
		} else {
			result = strings.ReplaceAll(result, "$MAXRANGE4", fmt.Sprintf("%d", maxRange))
		}
	}

	// Replace $ with the primary substitution (IP or domain) LAST
	result = strings.ReplaceAll(result, "$", subst)

	return result
}
