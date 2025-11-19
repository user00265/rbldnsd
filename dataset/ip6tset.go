// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package dataset

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"
)

// IP6TSetEntry represents an IPv6 address with per-entry value
type IP6TSetEntry struct {
	IP    net.IP
	Value string
	TTL   uint32
}

// IP6TSetDataset stores IPv6 addresses with individual values
type IP6TSetDataset struct {
	entries []*IP6TSetEntry
	defVal  string
	defTTL  uint32
}

func loadIP6TSet(files []string) (Dataset, error) {
	ds := &IP6TSetDataset{
		entries: make([]*IP6TSetEntry, 0),
		defTTL:  3600,
	}

	for _, file := range files {
		if err := parseIP6TSetFile(file, ds); err != nil {
			return nil, err
		}
	}

	return ds, nil
}

func parseIP6TSetFile(filename string, ds *IP6TSetDataset) error {
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

		// Handle default value line (:value)
		if strings.HasPrefix(line, ":") {
			val, ttl := parseValue(line[1:])
			if val != "" {
				ds.defVal = val
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
			log.Printf("warning: invalid IP address at line %d: %s", lineNum, parts[0])
			continue
		}
		ip = ip.To16()
		if ip == nil {
			continue
		}

		// Get value (if any)
		value := ds.defVal
		ttl := ds.defTTL
		if len(parts) > 1 {
			val, t := parseValue(strings.Join(parts[1:], " "))
			if val != "" {
				value = val
			}
			if t > 0 {
				ttl = t
			}
		}

		ds.entries = append(ds.entries, &IP6TSetEntry{
			IP:    ip,
			Value: value,
			TTL:   ttl,
		})
	}

	return scanner.Err()
}

// Query looks up an IPv6 address in the IP6TSet
func (ds *IP6TSetDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	ip := parseReverseIP6(name)
	if ip == nil {
		return nil, nil
	}

	// Linear search for exact match
	for _, entry := range ds.entries {
		if entry.IP.Equal(ip) {
			return &QueryResult{
				TTL:    entry.TTL,
				Values: []string{entry.Value},
			}, nil
		}
	}

	return nil, nil
}
