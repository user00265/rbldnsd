// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package dataset

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
)

// DNSetEntry represents a domain name with associated value
type DNSetEntry struct {
	Name     string
	Value    string
	TTL      uint32
	Wildcard bool
	Negated  bool
}

// DNSetDataset stores domain names with values (supports wildcards)
type DNSetDataset struct {
	entries []*DNSetEntry
	defVal  string
	defTTL  uint32
}

func (ds *DNSetDataset) Count() int {
	return len(ds.entries)
}

func loadDNSet(files []string, defaultTTL uint32) (Dataset, error) {
	ds := &DNSetDataset{
		entries: make([]*DNSetEntry, 0),
		defTTL:  defaultTTL,
	}

	for _, file := range files {
		if err := parseDNSetFile(file, ds); err != nil {
			return nil, err
		}
	}

	// Sort entries: plain before wildcards, longer before shorter
	sort.Slice(ds.entries, func(i, j int) bool {
		ei, ej := ds.entries[i], ds.entries[j]
		if ei.Wildcard != ej.Wildcard {
			return !ei.Wildcard // plain entries first
		}
		return len(ei.Name) > len(ej.Name) // longer first
	})

	return ds, nil
}

func parseDNSetFile(filename string, ds *DNSetDataset) error {
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

		// Handle default value line (:A:TXT format)
		if strings.HasPrefix(line, ":") {
			aRecord, txtTemplate, _ := parseATxt(line)
			if aRecord != "" {
				ds.defVal = aRecord + "|" + txtTemplate
			}
			continue
		}

		// Parse domain name entry
		negated := false
		if strings.HasPrefix(line, "!") {
			negated = true
			line = strings.TrimSpace(line[1:])
		}

		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		name := strings.ToLower(parts[0])

		// Skip entries that look like IP addresses or CIDR blocks
		// This allows dnset to be used in combined datasets alongside ip4trie/ip6trie
		if net.ParseIP(name) != nil {
			continue // It's a plain IP address
		}
		if _, _, err := net.ParseCIDR(name); err == nil {
			continue // It's a CIDR block
		}
		if strings.Contains(name, "/") {
			continue // Contains / but not valid CIDR - skip it anyway
		}

		wildcard := strings.HasPrefix(name, "*.")
		if wildcard {
			name = name[2:]
		}

		// Normalize domain name
		if !strings.HasSuffix(name, ".") {
			name += "."
		}

		value := ds.defVal
		ttl := ds.defTTL
		if len(parts) > 1 && !negated {
			// Parse A:TXT format for this entry
			aRecord, txtTemplate, t := parseATxt(strings.Join(parts[1:], " "))
			value = aRecord + "|" + txtTemplate
			if t > 0 {
				ttl = t
			}
		}

		// If no value set (no default and no per-entry value), use 127.0.0.2
		if value == "" {
			value = "127.0.0.2|"
		}

		ds.entries = append(ds.entries, &DNSetEntry{
			Name:     name,
			Value:    value,
			TTL:      ttl,
			Wildcard: wildcard,
			Negated:  negated,
		})
		slog.Debug("dnset entry added", "name", name, "value", value, "wildcard", wildcard, "negated", negated)
	}

	return scanner.Err()
}

// Query looks up a domain name in the DNSet
func (ds *DNSetDataset) Query(name string, qtype uint16) (*QueryResult, error) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// Check exact matches and negations first
	for _, entry := range ds.entries {
		if entry.Wildcard {
			continue
		}
		if entry.Name == name {
			if entry.Negated {
				return nil, nil
			}
			// Split A|TXT format
			parts := strings.SplitN(entry.Value, "|", 2)
			aRecord := parts[0]
			txtTemplate := ""
			if len(parts) > 1 {
				txtTemplate = parts[1]
			}
			// Substitute $ with domain name (without trailing dot)
			domainForSubst := strings.TrimSuffix(name, ".")
			txtTemplate = substituteTXT(txtTemplate, domainForSubst)
			return &QueryResult{
				TTL:         entry.TTL,
				ARecord:     aRecord,
				TXTTemplate: txtTemplate,
			}, nil
		}
	}

	// Check wildcard matches
	for _, entry := range ds.entries {
		if !entry.Wildcard {
			continue
		}
		if strings.HasSuffix(name, "."+entry.Name) || name == entry.Name {
			if entry.Negated {
				return nil, nil
			}
			// Split A|TXT format
			parts := strings.SplitN(entry.Value, "|", 2)
			aRecord := parts[0]
			txtTemplate := ""
			if len(parts) > 1 {
				txtTemplate = parts[1]
			}
			// Substitute $ with domain name (without trailing dot)
			domainForSubst := strings.TrimSuffix(name, ".")
			txtTemplate = substituteTXT(txtTemplate, domainForSubst)
			return &QueryResult{
				TTL:         entry.TTL,
				ARecord:     aRecord,
				TXTTemplate: txtTemplate,
			}, nil
		}
	}

	return nil, nil
}
