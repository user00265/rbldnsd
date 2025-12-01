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

// IP4TSetEntry represents an IPv4 address with per-entry value
type IP4TSetEntry struct {
	IP    net.IP
	Value string
	TTL   uint32
}

// IP4TSetDataset stores IPv4 addresses with individual values
type IP4TSetDataset struct {
	entries   []*IP4TSetEntry
	defVal    string
	defTTL    uint32
	maxRange  int   // Maximum CIDR prefix length (for $MAXRANGE4)
	timestamp int64 // Zone file modification time (for $TIMESTAMP)
}

func (ds *IP4TSetDataset) Count() int {
	return len(ds.entries)
}

func loadIP4TSet(files []string, defaultTTL uint32) (Dataset, error) {
	ds := &IP4TSetDataset{
		entries: make([]*IP4TSetEntry, 0),
		defTTL:  defaultTTL,
	}

	for _, file := range files {
		if err := parseIP4TSetFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func parseIP4TSetFile(filename string, ds *IP4TSetDataset) error {
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

		// Handle default value line (:A:TXT format)
		if strings.HasPrefix(line, ":") {
			aRecord, txtTemplate, ttl := parseATxt(line)
			if aRecord != "" {
				ds.defVal = aRecord + "|" + txtTemplate
			}
			if ttl > 0 {
				ds.defTTL = ttl
			}
			continue
		}

		// Parse IP address
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		ip := net.ParseIP(parts[0])
		if ip == nil {
			slog.Warn("invalid IP address", "line", lineNum, "value", parts[0])
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}

		// Get value (if any)
		value := ds.defVal
		ttl := ds.defTTL
		if len(parts) > 1 {
			aRecord, txtTemplate, t := parseATxt(strings.Join(parts[1:], " "))
			value = aRecord + "|" + txtTemplate
			if t > 0 {
				ttl = t
			}
		}

		// If no value set, use 127.0.0.2
		if value == "" {
			value = "127.0.0.2|"
		}

		ds.entries = append(ds.entries, &IP4TSetEntry{
			IP:    ip,
			Value: value,
			TTL:   ttl,
		})
		slog.Debug("ip4tset entry added", "ip", ip.String(), "value", value)
	}

	return scanner.Err()
}

// Query looks up an IP in the IP4TSet
func (ds *IP4TSetDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	ip := parseReverseIP(name)
	if ip == nil {
		return nil, nil
	}

	// Linear search for exact match
	for _, entry := range ds.entries {
		if entry.IP.Equal(ip) {
			// Split A|TXT format
			parts := strings.SplitN(entry.Value, "|", 2)
			aRecord := parts[0]
			txtTemplate := ""
			if len(parts) > 1 {
				txtTemplate = parts[1]
			}
			// Substitute variables in TXT template
			txtTemplate = substituteTXTWithMetadata(txtTemplate, ip.String(), ds.timestamp, ds.maxRange, false)
			return &QueryResult{
				TTL:         entry.TTL,
				ARecord:     aRecord,
				TXTTemplate: txtTemplate,
			}, nil
		}
	}

	return nil, nil
}
