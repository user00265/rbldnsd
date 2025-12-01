// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package acl implements access control lists for zone queries.
// It supports both file-based and inline ACL rules with allow/deny semantics.
package acl

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"strings"
)

// ACL represents an access control list with allow and deny rules.
type ACL struct {
	Allow []net.IPNet
	Deny  []net.IPNet
}

// LoadACL loads an ACL from a file.
func LoadACL(filename string) (*ACL, error) {
	acl := &ACL{
		Allow: make([]net.IPNet, 0),
		Deny:  make([]net.IPNet, 0),
	}

	if filename == "" {
		return acl, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	mode := "allow" // default

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Directives
		if strings.HasPrefix(line, "allow:") {
			mode = "allow"
			continue
		}
		if strings.HasPrefix(line, "deny:") {
			mode = "deny"
			continue
		}

		// Parse CIDR or IP
		ip, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			// Try single IP
			ip = net.ParseIP(line)
			if ip == nil {
				slog.Warn("acl: invalid IP/CIDR", "line", lineNum, "value", line)
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}

		if mode == "allow" {
			acl.Allow = append(acl.Allow, *ipnet)
		} else {
			acl.Deny = append(acl.Deny, *ipnet)
		}
	}

	return acl, scanner.Err()
}

// FromRules creates an ACL from inline rules (allow/deny string lists)
func FromRules(allow, deny []string) (*ACL, error) {
	acl := &ACL{
		Allow: make([]net.IPNet, 0),
		Deny:  make([]net.IPNet, 0),
	}

	// Process allow rules
	for i, rule := range allow {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		_, ipnet, err := net.ParseCIDR(rule)
		if err != nil {
			// Try single IP
			ip := net.ParseIP(rule)
			if ip == nil {
				if err != nil {
					slog.Warn("allow rule: invalid IP/CIDR", "index", i, "value", rule)
					continue
				}
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		acl.Allow = append(acl.Allow, *ipnet)
	}

	// Process deny rules
	for i, rule := range deny {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		_, ipnet, err := net.ParseCIDR(rule)
		if err != nil {
			// Try single IP
			ip := net.ParseIP(rule)
			if ip == nil {
				if err != nil {
					slog.Warn("deny rule: invalid IP/CIDR", "index", i, "value", rule)
					continue
				}
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		acl.Deny = append(acl.Deny, *ipnet)
	}

	return acl, nil
}

// AllowQuery checks if the query from the given IP should be allowed
func (a *ACL) AllowQuery(ip net.IP) bool {
	if len(a.Allow) == 0 && len(a.Deny) == 0 {
		return true
	}

	// Check deny list first
	for _, deny := range a.Deny {
		if deny.Contains(ip) {
			return false
		}
	}

	// If allow list exists, check it
	if len(a.Allow) > 0 {
		for _, allow := range a.Allow {
			if allow.Contains(ip) {
				return true
			}
		}
		return false
	}

	return true
}
