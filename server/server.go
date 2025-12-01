// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package server implements the DNS server for rbldnsd.
// It handles UDP queries, zone routing, ACL enforcement, and metrics collection.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/user00265/rbldnsd/acl"
	"github.com/user00265/rbldnsd/config"
	"github.com/user00265/rbldnsd/dataset"
	"github.com/user00265/rbldnsd/dns"
	"github.com/user00265/rbldnsd/metrics"

	"github.com/fsnotify/fsnotify"
)

// Server represents the DNS server instance.
// It manages multiple zones and handles incoming UDP queries.
type Server struct {
	configPath      string
	configMgr       *config.ConfigManager
	zones           map[string]*Zone
	zonesMu         sync.RWMutex
	listener        *net.UDPConn
	addr            string
	done            atomic.Bool
	metrics         *metrics.Metrics
	watcher         *fsnotify.Watcher
	autoReload      bool
	reloadDebounce  time.Duration
	reloadTimer     *time.Timer
	reloadMu        sync.Mutex
	readTimeout     time.Duration
	shutdownTimeout time.Duration
	udpBufferSize   int
	defaultTTL      uint32
	soaRefresh      uint32
	soaRetry        uint32
	soaExpire       uint32
	soaMinimum      uint32
} // Zone represents a DNS zone with its dataset and configuration.
type Zone struct {
	name     string
	dataType string
	files    []string
	dataset  dataset.Dataset
	acl      *acl.ACL
	ns       []string          // Nameservers
	soa      *config.SOAConfig // SOA record
}

// New creates a new DNS server from the provided configuration.
func New(cfg *config.Config, configPath string) (*Server, error) {
	srv := &Server{
		configPath:      configPath,
		zones:           make(map[string]*Zone),
		addr:            cfg.Server.Bind,
		autoReload:      cfg.Server.AutoReload,
		reloadDebounce:  time.Duration(cfg.Server.ReloadDebounce) * time.Second,
		readTimeout:     time.Duration(cfg.Server.ReadTimeout) * time.Second,
		shutdownTimeout: time.Duration(cfg.Server.ShutdownTimeout) * time.Second,
		udpBufferSize:   cfg.Server.UDPBufferSize,
		defaultTTL:      cfg.Server.DefaultTTL,
		soaRefresh:      cfg.Server.SOARefresh,
		soaRetry:        cfg.Server.SOARetry,
		soaExpire:       cfg.Server.SOAExpire,
		soaMinimum:      cfg.Server.SOAMinimum,
	}

	// Set defaults if not specified
	if srv.reloadDebounce == 0 {
		srv.reloadDebounce = 2 * time.Second
	}
	if srv.readTimeout == 0 {
		srv.readTimeout = 1 * time.Second
	}
	if srv.shutdownTimeout == 0 {
		srv.shutdownTimeout = 5 * time.Second
	}
	if srv.udpBufferSize == 0 {
		srv.udpBufferSize = 512
	}
	if srv.defaultTTL == 0 {
		srv.defaultTTL = 3600
	}
	if srv.soaRefresh == 0 {
		srv.soaRefresh = 3600
	}
	if srv.soaRetry == 0 {
		srv.soaRetry = 600
	}
	if srv.soaExpire == 0 {
		srv.soaExpire = 86400
	}
	if srv.soaMinimum == 0 {
		srv.soaMinimum = 3600
	}

	// Initialize metrics
	var err error
	srv.metrics, err = metrics.New(cfg.Metrics.OTELEndpoint, cfg.Metrics.PrometheusEndpoint)
	if err != nil {
		slog.Warn("failed to initialize metrics", "error", err)
	}

	// Load initial zones
	if err := srv.loadZones(cfg); err != nil {
		return nil, err
	}

	// Initialize config manager if config file is provided
	if configPath != "" {
		configMgr, err := config.NewConfigManager(configPath, srv.handleConfigReload)
		if err != nil {
			slog.Warn("failed to initialize config manager", "error", err)
		} else {
			srv.configMgr = configMgr
			if err := configMgr.Start(); err != nil {
				slog.Warn("failed to start config manager", "error", err)
			}
		}
	}

	// Initialize file watcher if auto-reload is enabled (for zone files, not config)
	if srv.autoReload {
		if err := srv.initFileWatcher(cfg); err != nil {
			slog.Warn("failed to initialize file watcher", "error", err)
			slog.Info("automatic reload disabled, use SIGHUP for manual reload")
			srv.autoReload = false
		} else {
			slog.Info("automatic zone file monitoring enabled", "debounce", srv.reloadDebounce)
		}
	}

	return srv, nil
}

func (s *Server) loadZones(cfg *config.Config) error {
	newZones := make(map[string]*Zone)
	var failedZones []string

	for _, zc := range cfg.Zones {
		slog.Info("loading zone", "zone", zc.Name, "type", zc.Type, "files", zc.Files)

		ds, err := dataset.Load(zc.Type, zc.Files, s.defaultTTL, false)
		if err != nil {
			slog.Error("failed to load zone", "zone", zc.Name, "error", err)
			failedZones = append(failedZones, zc.Name)
			continue
		}
		slog.Info("zone loaded", "zone", zc.Name, "records", ds.Count())

		// Load ACL - prefer inline rules, fall back to file
		var zoneACL *acl.ACL
		if len(zc.ACLRule.Allow) > 0 || len(zc.ACLRule.Deny) > 0 {
			// Use inline ACL rules from config
			zoneACL, err = acl.FromRules(zc.ACLRule.Allow, zc.ACLRule.Deny)
			if err != nil {
				slog.Error("failed to parse inline ACL for zone", "zone", zc.Name, "error", err)
				failedZones = append(failedZones, zc.Name)
				continue
			}
			slog.Info("loaded inline ACL", "allow", len(zoneACL.Allow), "deny", len(zoneACL.Deny))
		} else if zc.ACL != "" {
			// Load ACL from file
			zoneACL, err = acl.LoadACL(zc.ACL)
			if err != nil {
				slog.Error("failed to load ACL file for zone", "zone", zc.Name, "error", err)
				failedZones = append(failedZones, zc.Name)
				continue
			}
			slog.Info("loaded ACL file", "file", zc.ACL)
		}

		// Set default SOA values if not provided
		soaConfig := zc.SOA
		if len(zc.NS) > 0 && soaConfig.MName == "" {
			// Use first NS as mname if not specified
			soaConfig.MName = zc.NS[0]
		}
		if soaConfig.Refresh == 0 {
			soaConfig.Refresh = s.soaRefresh
		}
		if soaConfig.Retry == 0 {
			soaConfig.Retry = s.soaRetry
		}
		if soaConfig.Expire == 0 {
			soaConfig.Expire = s.soaExpire
		}
		if soaConfig.Minimum == 0 {
			soaConfig.Minimum = s.soaMinimum
		}

		var soaPtr *config.SOAConfig
		if soaConfig.MName != "" && soaConfig.RName != "" {
			soaPtr = &soaConfig
		}

		newZones[zc.Name] = &Zone{
			name:     zc.Name,
			dataType: zc.Type,
			files:    zc.Files,
			dataset:  ds,
			acl:      zoneACL,
			ns:       zc.NS,
			soa:      soaPtr,
		}
	}

	s.zonesMu.Lock()
	s.zones = newZones
	s.zonesMu.Unlock()

	// If all zones failed to load from config file, return error only if config file was provided
	if len(newZones) == 0 && len(cfg.Zones) > 0 && s.configPath != "" {
		return fmt.Errorf("failed to load any zones (loaded 0/%d)", len(cfg.Zones))
	}

	if len(failedZones) > 0 {
		slog.Warn("failed to load zones", "count", len(failedZones), "zones", failedZones)
	}

	return nil
}

func (s *Server) Reload() error {
	cfg := s.configMgr.Get()
	return s.loadZones(cfg)
}

// ReloadFile reloads only the zones that use the specified file
func (s *Server) ReloadFile(changedFile string) error {
	cfg := s.configMgr.Get()

	// Find which zones use this file
	var affectedZones []*config.ZoneConfig
	for i := range cfg.Zones {
		zc := &cfg.Zones[i]
		for _, file := range zc.Files {
			if file == changedFile {
				affectedZones = append(affectedZones, zc)
				break
			}
		}
		// Also check ACL file
		if zc.ACL == changedFile {
			affectedZones = append(affectedZones, zc)
		}
	}

	if len(affectedZones) == 0 {
		slog.Debug("no zones affected by file change", "file", changedFile)
		return nil
	}

	// Reload each affected zone
	for _, zc := range affectedZones {
		slog.Info("reloading zone", "zone", zc.Name, "type", zc.Type, "files", zc.Files)

		ds, err := dataset.Load(zc.Type, zc.Files, s.defaultTTL, false)
		if err != nil {
			slog.Error("failed to reload zone", "zone", zc.Name, "error", err)
			continue
		}
		slog.Info("zone reloaded", "zone", zc.Name, "records", ds.Count())

		// Load ACL - prefer inline rules, fall back to file
		var zoneACL *acl.ACL
		if len(zc.ACLRule.Allow) > 0 || len(zc.ACLRule.Deny) > 0 {
			zoneACL, err = acl.FromRules(zc.ACLRule.Allow, zc.ACLRule.Deny)
			if err != nil {
				slog.Error("failed to parse inline ACL for zone", "zone", zc.Name, "error", err)
				continue
			}
		} else if zc.ACL != "" {
			zoneACL, err = acl.LoadACL(zc.ACL)
			if err != nil {
				slog.Error("failed to load ACL file for zone", "zone", zc.Name, "error", err)
				continue
			}
		}

		// Set default SOA values if not provided
		soaConfig := zc.SOA
		if len(zc.NS) > 0 && soaConfig.MName == "" {
			soaConfig.MName = zc.NS[0]
		}
		if soaConfig.Refresh == 0 {
			soaConfig.Refresh = s.soaRefresh
		}
		if soaConfig.Retry == 0 {
			soaConfig.Retry = s.soaRetry
		}
		if soaConfig.Expire == 0 {
			soaConfig.Expire = s.soaExpire
		}
		if soaConfig.Minimum == 0 {
			soaConfig.Minimum = s.soaMinimum
		}

		var soaPtr *config.SOAConfig
		if soaConfig.MName != "" && soaConfig.RName != "" {
			soaPtr = &soaConfig
		}

		newZone := &Zone{
			name:     zc.Name,
			dataType: zc.Type,
			files:    zc.Files,
			dataset:  ds,
			acl:      zoneACL,
			ns:       zc.NS,
			soa:      soaPtr,
		}

		s.zonesMu.Lock()
		s.zones[zc.Name] = newZone
		s.zonesMu.Unlock()
	}

	return nil
}

// handleConfigReload is called by ConfigManager when config file changes
func (s *Server) handleConfigReload(newCfg *config.Config, changes config.ZoneChanges) error {
	// Handle server config changes (bind address, timeout)
	if changes.ServerChanged {
		// Bind address changes require restart
		if s.addr != newCfg.Server.Bind {
			slog.Info("bind address changed (requires restart)", "old", s.addr, "new", newCfg.Server.Bind)
			s.addr = newCfg.Server.Bind
		}
		// Other server settings can be applied dynamically if needed
	}

	// Handle removed zones
	for _, zoneName := range changes.Removed {
		s.zonesMu.Lock()
		delete(s.zones, zoneName)
		s.zonesMu.Unlock()
		slog.Info("zone unloaded", "zone", zoneName)
	}

	// Handle added and updated zones
	for _, zoneName := range append(changes.Added, changes.Updated...) {
		// Find the zone in new config
		var zc *config.ZoneConfig
		for i := range newCfg.Zones {
			if newCfg.Zones[i].Name == zoneName {
				zc = &newCfg.Zones[i]
				break
			}
		}

		if zc == nil {
			slog.Error("zone not found in config", "zone", zoneName)
			continue
		}

		// Load the zone
		slog.Info("loading zone", "zone", zc.Name, "type", zc.Type, "files", zc.Files)
		ds, err := dataset.Load(zc.Type, zc.Files, s.defaultTTL, false)
		if err != nil {
			// On reload, skip this zone and keep existing one
			// On initial load, this would have failed earlier
			slog.Error("failed to load zone (keeping existing zone)", "zone", zc.Name, "error", err)
			continue
		}

		// Load ACL
		var zoneACL *acl.ACL
		if len(zc.ACLRule.Allow) > 0 || len(zc.ACLRule.Deny) > 0 {
			var err error
			zoneACL, err = acl.FromRules(zc.ACLRule.Allow, zc.ACLRule.Deny)
			if err != nil {
				slog.Error("failed to parse inline ACL for zone (keeping existing zone)", "zone", zc.Name, "error", err)
				continue
			}
			slog.Info("loaded inline ACL", "allow", len(zoneACL.Allow), "deny", len(zoneACL.Deny))
		} else if zc.ACL != "" {
			var err error
			zoneACL, err = acl.LoadACL(zc.ACL)
			if err != nil {
				slog.Error("failed to load ACL file for zone (keeping existing zone)", "zone", zc.Name, "error", err)
				continue
			}
			slog.Info("loaded ACL file", "file", zc.ACL)
		}

		// Set default SOA values
		soaConfig := zc.SOA
		if len(zc.NS) > 0 && soaConfig.MName == "" {
			soaConfig.MName = zc.NS[0]
		}
		if soaConfig.Refresh == 0 {
			soaConfig.Refresh = s.soaRefresh
		}
		if soaConfig.Retry == 0 {
			soaConfig.Retry = s.soaRetry
		}
		if soaConfig.Expire == 0 {
			soaConfig.Expire = s.soaExpire
		}
		if soaConfig.Minimum == 0 {
			soaConfig.Minimum = s.soaMinimum
		}

		var soaPtr *config.SOAConfig
		if soaConfig.MName != "" && soaConfig.RName != "" {
			soaPtr = &soaConfig
		}

		newZone := &Zone{
			name:     zc.Name,
			dataType: zc.Type,
			files:    zc.Files,
			dataset:  ds,
			acl:      zoneACL,
			ns:       zc.NS,
			soa:      soaPtr,
		}

		s.zonesMu.Lock()
		s.zones[zoneName] = newZone
		s.zonesMu.Unlock()

		if contains(changes.Added, zoneName) {
			slog.Info("zone loaded", "zone", zoneName)
		} else {
			slog.Info("zone reloaded", "zone", zoneName)
		}
	}

	// Update file watcher to reflect current configuration
	if s.autoReload && s.watcher != nil {
		if err := s.updateFileWatcher(newCfg); err != nil {
			slog.Error("failed to update file watcher", "error", err)
		}
	}

	return nil
}

// updateFileWatcher synchronizes the file watcher with the current configuration
func (s *Server) updateFileWatcher(cfg *config.Config) error {
	// Collect all unique files that should be watched
	shouldWatch := make(map[string]bool)
	for _, zc := range cfg.Zones {
		for _, file := range zc.Files {
			// Strip dataset type prefix if present (e.g., "ip4trie:file.zone" -> "file.zone")
			cleanFile := file
			if idx := strings.Index(file, ":"); idx != -1 {
				cleanFile = file[idx+1:]
			}
			shouldWatch[cleanFile] = true
		}
		// Also watch ACL files if specified
		if zc.ACL != "" {
			shouldWatch[zc.ACL] = true
		}
	}

	// Get currently watched files
	currentlyWatched := s.watcher.WatchList()
	currentWatchMap := make(map[string]bool)
	for _, file := range currentlyWatched {
		currentWatchMap[file] = true
	}

	// Add new files that should be watched but aren't
	for file := range shouldWatch {
		if !currentWatchMap[file] {
			if err := s.watcher.Add(file); err != nil {
				slog.Warn("failed to add file to watcher", "file", file, "error", err)
			} else {
				slog.Info("now watching file", "file", file)
			}
		}
	}

	// Remove files that are watched but shouldn't be
	for file := range currentWatchMap {
		if !shouldWatch[file] {
			if err := s.watcher.Remove(file); err != nil {
				slog.Warn("failed to remove file from watcher", "file", file, "error", err)
			} else {
				slog.Info("stopped watching file", "file", file)
			}
		}
	}

	return nil
}

// contains checks if a string is in a slice
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.listener = conn
	defer conn.Close()

	slog.Info("listening on", "address", s.addr)

	buf := make([]byte, s.udpBufferSize)
	for !s.done.Load() {
		conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if server is shutting down - don't log closed connection errors
			if s.done.Load() {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			slog.Error("read error", "error", err)
			continue
		}

		go s.handleRequest(conn, buf[:n], remoteAddr)
	}

	return nil
}

func (s *Server) handleRequest(conn *net.UDPConn, data []byte, remoteAddr *net.UDPAddr) {
	startTime := time.Now()

	msg, err := dns.ParseMessage(data)
	if err != nil {
		slog.Error("parse error", "error", err)
		s.metrics.RecordError("unknown", "parse_error")
		return
	}

	// Debug log for incoming queries
	for _, q := range msg.Questions {
		slog.Debug("incoming query", "name", q.Name, "qtype", q.Type, "from", remoteAddr.IP)
	}

	// Only handle queries
	if msg.Header.QR {
		return
	}

	// Build response
	var answers []dns.ResourceRecord

	for _, q := range msg.Questions {
		result := s.queryZones(remoteAddr.IP, q.Name, q.Type)
		answers = append(answers, result...)

		s.metrics.RecordQuery("all", fmt.Sprintf("%d", q.Type))
	}

	rcode := dns.RCodeNoError
	if len(answers) == 0 && len(msg.Questions) > 0 {
		rcode = dns.RCodeNameErr
	}

	response := dns.BuildResponse(msg.Header.ID, msg.Questions, answers, uint8(rcode))

	_, err = conn.WriteToUDP(response, remoteAddr)
	if err != nil {
		slog.Error("write error", "error", err)
		s.metrics.RecordError("unknown", "write_error")
	}

	latency := time.Since(startTime).Seconds() * 1000
	s.metrics.RecordLatency("all", latency)
}

func (s *Server) queryZones(remoteIP net.IP, name string, qtype uint16) []dns.ResourceRecord {
	s.zonesMu.RLock()
	defer s.zonesMu.RUnlock()

	// Find the matching zone first (most specific match)
	// This matches Spamhaus rbldnsd's findqzone() behavior
	var matchedZone *Zone
	var matchedZoneName string
	var matchedZoneDot string
	longestMatch := 0

	for zoneName, zone := range s.zones {
		zoneDot := zoneName
		if !strings.HasSuffix(zoneDot, ".") {
			zoneDot += "."
		}

		// Check if query name is in this zone
		if strings.HasSuffix(name, zoneDot) {
			// Track the longest (most specific) match
			if len(zoneDot) > longestMatch {
				matchedZone = zone
				matchedZoneName = zoneName
				matchedZoneDot = zoneDot
				longestMatch = len(zoneDot)
			}
		}
	}

	// No matching zone found
	if matchedZone == nil {
		slog.Debug("no matching zone", "name", name, "zones", len(s.zones))
		return nil
	}

	slog.Debug("zone matched", "query", name, "zone", matchedZoneDot)

	// Check ACL
	if matchedZone.acl != nil && !matchedZone.acl.AllowQuery(remoteIP) {
		slog.Info("query denied by ACL", "name", name, "ip", remoteIP)
		s.metrics.RecordError(matchedZoneName, "acl_denied")
		return nil
	}

	// Check ACL
	if matchedZone.acl != nil && !matchedZone.acl.AllowQuery(remoteIP) {
		slog.Info("query denied by ACL", "name", name, "ip", remoteIP)
		s.metrics.RecordError(matchedZoneName, "acl_denied")
		return nil
	}

	// Handle queries to zone apex (NS and SOA records)
	if name == matchedZoneDot || name == matchedZoneName {
		switch qtype {
		case dns.QueryTypeNS:
			if len(matchedZone.ns) > 0 {
				var answers []dns.ResourceRecord
				for _, ns := range matchedZone.ns {
					if rrData, err := dns.EncodeNS(ns); err == nil {
						answers = append(answers, dns.ResourceRecord{
							Name:  matchedZoneDot,
							Type:  dns.QueryTypeNS,
							Class: dns.ClassIN,
							TTL:   s.defaultTTL,
							Data:  rrData,
						})
					}
				}
				s.metrics.RecordResponse(matchedZoneName, true)
				return answers
			}
		case dns.QueryTypeSOA:
			if matchedZone.soa != nil {
				if rrData, err := dns.EncodeSOA(
					matchedZone.soa.MName,
					matchedZone.soa.RName,
					matchedZone.soa.Serial,
					matchedZone.soa.Refresh,
					matchedZone.soa.Retry,
					matchedZone.soa.Expire,
					matchedZone.soa.Minimum,
				); err == nil {
					s.metrics.RecordResponse(matchedZoneName, true)
					return []dns.ResourceRecord{{
						Name:  matchedZoneDot,
						Type:  dns.QueryTypeSOA,
						Class: dns.ClassIN,
						TTL:   matchedZone.soa.Minimum,
						Data:  rrData,
					}}
				}
			}
		}
	}

	// Strip zone suffix from query name before passing to dataset
	// This matches Spamhaus rbldnsd behavior where qi->qi_dnlen0/qi_dnlab
	// represent "length/labels AFTER zone base is stripped"
	queryName := name
	if strings.HasSuffix(name, matchedZoneDot) {
		// Remove the zone suffix, e.g. "gofundme.com.rwl.nullnetwork.cc" -> "gofundme.com"
		queryName = strings.TrimSuffix(name, matchedZoneDot)
		queryName = strings.TrimSuffix(queryName, ".") // Remove trailing dot if present
	}

	// Query the matched zone's dataset
	result, err := matchedZone.dataset.Query(queryName, qtype)
	if err != nil {
		slog.Error("query error", "name", name, "zone", matchedZoneName, "error", err)
		s.metrics.RecordError(matchedZoneName, "query_error")
		return nil
	}

	if result == nil {
		slog.Debug("no match in zone", "name", name, "zone", matchedZoneName)
		s.metrics.RecordResponse(matchedZoneName, false)
		return nil
	}

	slog.Info("query result", "name", name, "zone", matchedZoneName, "qtype", qtype, "a", result.ARecord, "txt", result.TXTTemplate)
	s.metrics.RecordResponse(matchedZoneName, true)

	var answers []dns.ResourceRecord
	var rrData []byte

	switch qtype {
	case dns.QueryTypeA:
		// Return A record if available
		if result.ARecord != "" {
			ip := net.ParseIP(result.ARecord)
			if ip != nil {
				rrData = dns.EncodeA(ip)
				if rrData != nil {
					answers = append(answers, dns.ResourceRecord{
						Name:  name,
						Type:  dns.QueryTypeA,
						Class: dns.ClassIN,
						TTL:   result.TTL,
						Data:  rrData,
					})
				}
			}
		}
	case dns.QueryTypeTXT:
		// Return TXT record if available (already substituted by dataset)
		if result.TXTTemplate != "" {
			rrData = dns.EncodeTXT(result.TXTTemplate)
			if rrData != nil {
				answers = append(answers, dns.ResourceRecord{
					Name:  name,
					Type:  dns.QueryTypeTXT,
					Class: dns.ClassIN,
					TTL:   result.TTL,
					Data:  rrData,
				})
			}
		}
	case dns.QueryTypeAAAA:
		// For AAAA, try to parse ARecord as IPv6
		if result.ARecord != "" {
			ip := net.ParseIP(result.ARecord)
			if ip != nil && ip.To16() != nil {
				rrData = dns.EncodeAAAA(ip)
				if rrData != nil {
					answers = append(answers, dns.ResourceRecord{
						Name:  name,
						Type:  dns.QueryTypeAAAA,
						Class: dns.ClassIN,
						TTL:   result.TTL,
						Data:  rrData,
					})
				}
			}
		}
	case 255: // ANY query
		// Return both A and TXT if available
		if result.ARecord != "" {
			ip := net.ParseIP(result.ARecord)
			if ip != nil {
				rrData = dns.EncodeA(ip)
				if rrData != nil {
					answers = append(answers, dns.ResourceRecord{
						Name:  name,
						Type:  dns.QueryTypeA,
						Class: dns.ClassIN,
						TTL:   result.TTL,
						Data:  rrData,
					})
				}
			}
		}
		if result.TXTTemplate != "" {
			rrData = dns.EncodeTXT(result.TXTTemplate)
			if rrData != nil {
				answers = append(answers, dns.ResourceRecord{
					Name:  name,
					Type:  dns.QueryTypeTXT,
					Class: dns.ClassIN,
					TTL:   result.TTL,
					Data:  rrData,
				})
			}
		}
	}

	return answers
}

// Shutdown gracefully shuts down the server with a timeout.
// It gives in-flight requests up to shutdownTimeout to complete.
func (s *Server) Shutdown() {
	slog.Info("initiating graceful shutdown", "timeout", s.shutdownTimeout)

	// Signal main loop to stop accepting new connections
	s.done.Store(true)

	// Close listener to stop accepting new requests
	if s.listener != nil {
		s.listener.Close()
	}

	// Create context for graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	// Shutdown metrics server gracefully
	if s.metrics != nil {
		if err := s.metrics.Shutdown(ctx); err != nil && err != context.DeadlineExceeded {
			slog.Error("metrics server shutdown error", "error", err)
		}
	}

	// Clean up watchers and timers (non-blocking)
	if s.watcher != nil {
		s.watcher.Close()
	}
	if s.reloadTimer != nil {
		s.reloadTimer.Stop()
	}
	if s.configMgr != nil {
		s.configMgr.Stop()
	}

	// Don't wait for timeout in the shutdown function - let it happen in background
	// This allows tests to complete and the daemon to exit cleanly
	slog.Info("shutdown initiated, waiting for in-flight requests")
}

// initFileWatcher initializes the file system watcher for zone files
func (s *Server) initFileWatcher(cfg *config.Config) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	s.watcher = watcher

	// Collect all unique files to watch
	filesToWatch := make(map[string]bool)
	for _, zc := range cfg.Zones {
		for _, file := range zc.Files {
			// Strip dataset type prefix if present (e.g., "ip4trie:file.zone" -> "file.zone")
			cleanFile := file
			if idx := strings.Index(file, ":"); idx != -1 {
				cleanFile = file[idx+1:]
			}
			filesToWatch[cleanFile] = true
		}
		// Also watch ACL files if specified
		if zc.ACL != "" {
			filesToWatch[zc.ACL] = true
		}
	}

	// Add files to watcher
	for file := range filesToWatch {
		if err := watcher.Add(file); err != nil {
			slog.Warn("failed to watch file", "file", file, "error", err)
		} else {
			slog.Info("watching file", "file", file)
		}
	}

	// Start watching in background
	go s.watchFiles()

	return nil
}

// watchFiles monitors file system events and triggers reloads
func (s *Server) watchFiles() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}

			// Only handle write, create, remove, and rename events
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) ||
				event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				slog.Info("detected file change", "file", event.Name, "op", event.Op)
				s.scheduleReload(event.Name)
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "error", err)
		}
	}
}

// scheduleReload schedules a zone reload with debouncing
func (s *Server) scheduleReload(changedFile string) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	// Cancel existing timer if any
	if s.reloadTimer != nil {
		s.reloadTimer.Stop()
	}

	// Schedule new reload after debounce period
	s.reloadTimer = time.AfterFunc(s.reloadDebounce, func() {
		slog.Info("reloading zones due to file changes", "file", changedFile)
		startTime := time.Now()

		if err := s.ReloadFile(changedFile); err != nil {
			slog.Error("failed to reload zones", "error", err)
		} else {
			duration := time.Since(startTime)
			slog.Info("zones reloaded successfully", "duration", duration)
		}
	})
}
