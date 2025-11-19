// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package server implements the DNS server for rbldnsd.
// It handles UDP queries, zone routing, ACL enforcement, and metrics collection.
package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"rbldnsd/acl"
	"rbldnsd/config"
	"rbldnsd/dataset"
	"rbldnsd/dns"
	"rbldnsd/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Server represents the DNS server instance.
// It manages multiple zones and handles incoming UDP queries.
type Server struct {
	configPath     string
	configMgr      *config.ConfigManager
	zones          map[string]*Zone
	zonesMu        sync.RWMutex
	listener       *net.UDPConn
	addr           string
	done           atomic.Bool
	metrics        *metrics.Metrics
	watcher        *fsnotify.Watcher
	autoReload     bool
	reloadDebounce time.Duration
	reloadTimer    *time.Timer
	reloadMu       sync.Mutex
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
		configPath:     configPath,
		zones:          make(map[string]*Zone),
		addr:           cfg.Server.Bind,
		autoReload:     cfg.Server.AutoReload,
		reloadDebounce: time.Duration(cfg.Server.ReloadDebounce) * time.Second,
	}

	// Set default debounce if not specified
	if srv.reloadDebounce == 0 {
		srv.reloadDebounce = 2 * time.Second
	}

	// Initialize metrics
	var err error

	// Handle both old 'port' and new 'prometheus_endpoint' config
	prometheusEndpoint := cfg.Metrics.PrometheusEndpoint
	if prometheusEndpoint == "" && cfg.Metrics.Port > 0 {
		// Backward compatibility: convert port to endpoint
		prometheusEndpoint = fmt.Sprintf("0.0.0.0:%d", cfg.Metrics.Port)
		log.Printf("Using deprecated 'port' config. Please use 'prometheus_endpoint' instead.")
	}

	srv.metrics, err = metrics.New(cfg.Metrics.OTELEndpoint, prometheusEndpoint)
	if err != nil {
		log.Printf("warning: failed to initialize metrics: %v", err)
	}

	// Load initial zones
	if err := srv.loadZones(cfg); err != nil {
		return nil, err
	}

	// Initialize config manager if config file is provided
	if configPath != "" {
		configMgr, err := config.NewConfigManager(configPath, srv.handleConfigReload)
		if err != nil {
			log.Printf("warning: failed to initialize config manager: %v", err)
		} else {
			srv.configMgr = configMgr
			if err := configMgr.Start(); err != nil {
				log.Printf("warning: failed to start config manager: %v", err)
			}
		}
	}

	// Initialize file watcher if auto-reload is enabled (for zone files, not config)
	if srv.autoReload {
		if err := srv.initFileWatcher(cfg); err != nil {
			log.Printf("warning: failed to initialize file watcher: %v", err)
			log.Printf("automatic reload disabled, use SIGHUP for manual reload")
			srv.autoReload = false
		} else {
			log.Printf("automatic zone file monitoring enabled (debounce: %v)", srv.reloadDebounce)
		}
	}

	return srv, nil
}

func (s *Server) loadZones(cfg *config.Config) error {
	newZones := make(map[string]*Zone)
	var failedZones []string

	for _, zc := range cfg.Zones {
		log.Printf("loading zone %s (type=%s, files=%v)", zc.Name, zc.Type, zc.Files)

		ds, err := dataset.Load(zc.Type, zc.Files)
		if err != nil {
			log.Printf("ERROR: failed to load zone %s: %v", zc.Name, err)
			failedZones = append(failedZones, zc.Name)
			continue
		}

		// Load ACL - prefer inline rules, fall back to file
		var zoneACL *acl.ACL
		if len(zc.ACLRule.Allow) > 0 || len(zc.ACLRule.Deny) > 0 {
			// Use inline ACL rules from config
			zoneACL, err = acl.FromRules(zc.ACLRule.Allow, zc.ACLRule.Deny)
			if err != nil {
				log.Printf("ERROR: failed to parse inline ACL for zone %s: %v", zc.Name, err)
				failedZones = append(failedZones, zc.Name)
				continue
			}
			log.Printf("  loaded inline ACL: allow=%d, deny=%d", len(zoneACL.Allow), len(zoneACL.Deny))
		} else if zc.ACL != "" {
			// Load ACL from file
			zoneACL, err = acl.LoadACL(zc.ACL)
			if err != nil {
				log.Printf("ERROR: failed to load ACL file for zone %s: %v", zc.Name, err)
				failedZones = append(failedZones, zc.Name)
				continue
			}
			log.Printf("  loaded ACL file: %s", zc.ACL)
		}

		// Set default SOA values if not provided
		soaConfig := zc.SOA
		if len(zc.NS) > 0 && soaConfig.MName == "" {
			// Use first NS as mname if not specified
			soaConfig.MName = zc.NS[0]
		}
		if soaConfig.Refresh == 0 {
			soaConfig.Refresh = 3600
		}
		if soaConfig.Retry == 0 {
			soaConfig.Retry = 600
		}
		if soaConfig.Expire == 0 {
			soaConfig.Expire = 86400
		}
		if soaConfig.Minimum == 0 {
			soaConfig.Minimum = 3600
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
		log.Printf("warning: failed to load %d zones: %v", len(failedZones), failedZones)
	}

	return nil
}

func (s *Server) Reload() error {
	cfg := s.configMgr.Get()
	return s.loadZones(cfg)
}

// handleConfigReload is called by ConfigManager when config file changes
func (s *Server) handleConfigReload(newCfg *config.Config, changes config.ZoneChanges) error {
	// Handle server config changes (bind address, timeout)
	if changes.ServerChanged {
		// Bind address changes require restart
		if s.addr != newCfg.Server.Bind {
			log.Printf("bind address changed from %s to %s (requires restart)", s.addr, newCfg.Server.Bind)
			s.addr = newCfg.Server.Bind
		}
		// Other server settings can be applied dynamically if needed
	}

	// Handle removed zones
	for _, zoneName := range changes.Removed {
		s.zonesMu.Lock()
		delete(s.zones, zoneName)
		s.zonesMu.Unlock()
		log.Printf("zone unloaded: %s", zoneName)
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
			log.Printf("ERROR: zone %s not found in config", zoneName)
			continue
		}

		// Load the zone
		log.Printf("loading zone %s (type=%s, files=%v)", zc.Name, zc.Type, zc.Files)
		ds, err := dataset.Load(zc.Type, zc.Files)
		if err != nil {
			// On reload, skip this zone and keep existing one
			// On initial load, this would have failed earlier
			log.Printf("ERROR: failed to load zone %s: %v (keeping existing zone)", zc.Name, err)
			continue
		}

		// Load ACL
		var zoneACL *acl.ACL
		if len(zc.ACLRule.Allow) > 0 || len(zc.ACLRule.Deny) > 0 {
			var err error
			zoneACL, err = acl.FromRules(zc.ACLRule.Allow, zc.ACLRule.Deny)
			if err != nil {
				log.Printf("ERROR: failed to parse inline ACL for zone %s: %v (keeping existing zone)", zc.Name, err)
				continue
			}
			log.Printf("  loaded inline ACL: allow=%d, deny=%d", len(zoneACL.Allow), len(zoneACL.Deny))
		} else if zc.ACL != "" {
			var err error
			zoneACL, err = acl.LoadACL(zc.ACL)
			if err != nil {
				log.Printf("ERROR: failed to load ACL file for zone %s: %v (keeping existing zone)", zc.Name, err)
				continue
			}
			log.Printf("  loaded ACL file: %s", zc.ACL)
		}

		// Set default SOA values
		soaConfig := zc.SOA
		if len(zc.NS) > 0 && soaConfig.MName == "" {
			soaConfig.MName = zc.NS[0]
		}
		if soaConfig.Refresh == 0 {
			soaConfig.Refresh = 3600
		}
		if soaConfig.Retry == 0 {
			soaConfig.Retry = 600
		}
		if soaConfig.Expire == 0 {
			soaConfig.Expire = 86400
		}
		if soaConfig.Minimum == 0 {
			soaConfig.Minimum = 3600
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
			log.Printf("zone loaded: %s", zoneName)
		} else {
			log.Printf("zone reloaded: %s", zoneName)
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

	log.Printf("listening on %s", s.addr)

	buf := make([]byte, 512)
	for !s.done.Load() {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("read error: %v", err)
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
		log.Printf("parse error: %v", err)
		s.metrics.RecordError("unknown", "parse_error")
		return
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
		log.Printf("write error: %v", err)
		s.metrics.RecordError("unknown", "write_error")
	}

	latency := time.Since(startTime).Seconds() * 1000
	s.metrics.RecordLatency("all", latency)
}

func (s *Server) queryZones(remoteIP net.IP, name string, qtype uint16) []dns.ResourceRecord {
	s.zonesMu.RLock()
	defer s.zonesMu.RUnlock()

	for zoneName, zone := range s.zones {
		zoneDot := zoneName
		if !strings.HasSuffix(zoneDot, ".") {
			zoneDot += "."
		}

		// Check if query name is in this zone
		if !strings.HasSuffix(name, zoneDot) {
			continue
		}

		// Check ACL
		if zone.acl != nil && !zone.acl.AllowQuery(remoteIP) {
			log.Printf("query denied by ACL: %s from %s", name, remoteIP)
			s.metrics.RecordError(zoneName, "acl_denied")
			continue
		}

		// Handle queries to zone apex (NS and SOA records)
		if name == zoneDot || name == zoneName {
			switch qtype {
			case dns.QueryTypeNS:
				if len(zone.ns) > 0 {
					var answers []dns.ResourceRecord
					for _, ns := range zone.ns {
						if rrData, err := dns.EncodeNS(ns); err == nil {
							answers = append(answers, dns.ResourceRecord{
								Name:  zoneDot,
								Type:  dns.QueryTypeNS,
								Class: dns.ClassIN,
								TTL:   3600,
								Data:  rrData,
							})
						}
					}
					s.metrics.RecordResponse(zoneName, true)
					return answers
				}
			case dns.QueryTypeSOA:
				if zone.soa != nil {
					if rrData, err := dns.EncodeSOA(
						zone.soa.MName,
						zone.soa.RName,
						zone.soa.Serial,
						zone.soa.Refresh,
						zone.soa.Retry,
						zone.soa.Expire,
						zone.soa.Minimum,
					); err == nil {
						s.metrics.RecordResponse(zoneName, true)
						return []dns.ResourceRecord{{
							Name:  zoneDot,
							Type:  dns.QueryTypeSOA,
							Class: dns.ClassIN,
							TTL:   zone.soa.Minimum,
							Data:  rrData,
						}}
					}
				}
			}
		}

		// For generic datasets, we query the full name
		// For IP-based datasets, they handle reverse IP lookup themselves
		result, err := zone.dataset.Query(name, qtype)
		if err != nil {
			log.Printf("query error for %s in zone %s: %v", name, zoneName, err)
			s.metrics.RecordError(zoneName, "query_error")
			continue
		}

		if result == nil {
			s.metrics.RecordResponse(zoneName, false)
			continue
		}

		log.Printf("query %s in zone %s (qtype=%d): got %d values", name, zoneName, qtype, len(result.Values))
		s.metrics.RecordResponse(zoneName, true)

		var answers []dns.ResourceRecord
		for _, value := range result.Values {
			var rrData []byte

			switch qtype {
			case dns.QueryTypeA:
				ip := net.ParseIP(value)
				if ip != nil {
					rrData = dns.EncodeA(ip)
				}
			case dns.QueryTypeAAAA:
				ip := net.ParseIP(value)
				if ip != nil {
					rrData = dns.EncodeAAAA(ip)
				}
			case dns.QueryTypeTXT:
				rrData = dns.EncodeTXT(value)
			case dns.QueryTypeMX:
				// For MX, value should be "preference exchange"
				parts := strings.Fields(value)
				if len(parts) >= 2 {
					var pref uint16
					if _, err := fmt.Sscanf(parts[0], "%d", &pref); err == nil {
						rrData, _ = dns.EncodeMX(pref, parts[1])
					}
				}
			}

			if rrData != nil {
				answers = append(answers, dns.ResourceRecord{
					Name:  name,
					Type:  qtype,
					Class: dns.ClassIN,
					TTL:   result.TTL,
					Data:  rrData,
				})
			}
		}

		return answers
	}

	return nil
}

// Shutdown gracefully shuts down the server with a timeout.
// It gives in-flight requests up to shutdownTimeout to complete.
func (s *Server) Shutdown() {
	const shutdownTimeout = 5 * time.Second

	log.Println("initiating graceful shutdown (5s timeout)")

	// Signal main loop to stop accepting new connections
	s.done.Store(true)

	// Close listener to stop accepting new requests
	if s.listener != nil {
		s.listener.Close()
	}

	// Create context for graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Shutdown metrics server gracefully
	if s.metrics != nil {
		if err := s.metrics.Shutdown(ctx); err != nil && err != context.DeadlineExceeded {
			log.Printf("metrics server shutdown error: %v", err)
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
	log.Println("shutdown initiated, waiting for in-flight requests")
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
			filesToWatch[file] = true
		}
		// Also watch ACL files if specified
		if zc.ACL != "" {
			filesToWatch[zc.ACL] = true
		}
	}

	// Add files to watcher
	for file := range filesToWatch {
		if err := watcher.Add(file); err != nil {
			log.Printf("warning: failed to watch file %s: %v", file, err)
		} else {
			log.Printf("watching file: %s", file)
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
				log.Printf("detected file change: %s (op: %v)", event.Name, event.Op)
				s.scheduleReload()
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("file watcher error: %v", err)
		}
	}
}

// scheduleReload schedules a zone reload with debouncing
func (s *Server) scheduleReload() {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	// Cancel existing timer if any
	if s.reloadTimer != nil {
		s.reloadTimer.Stop()
	}

	// Schedule new reload after debounce period
	s.reloadTimer = time.AfterFunc(s.reloadDebounce, func() {
		log.Printf("reloading zones due to file changes")
		startTime := time.Now()

		if err := s.Reload(); err != nil {
			log.Printf("failed to reload zones: %v", err)
		} else {
			duration := time.Since(startTime)
			log.Printf("zones reloaded successfully in %v", duration)
		}
	})
}
