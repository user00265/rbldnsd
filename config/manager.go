// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package config implements dynamic config file monitoring and reloading.
package config

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ConfigManager watches config file for changes and intelligently reloads zones.
type ConfigManager struct {
	configPath string
	cfg        *Config
	mu         sync.RWMutex
	watcher    *fsnotify.Watcher
	done       chan bool
	onReload   func(*Config, ZoneChanges) error
}

// ZoneChanges describes what zones were added, removed, or updated.
type ZoneChanges struct {
	Added         []string // Zone names that were added
	Removed       []string // Zone names that were removed
	Updated       []string // Zone names that had config changes
	ServerChanged bool     // Server config (bind, timeout) changed
}

// NewConfigManager creates a new config manager.
func NewConfigManager(configPath string, onReload func(*Config, ZoneChanges) error) (*ConfigManager, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	cm := &ConfigManager{
		configPath: configPath,
		cfg:        cfg,
		done:       make(chan bool),
		onReload:   onReload,
	}

	return cm, nil
}

// Start begins watching the config file for changes.
func (cm *ConfigManager) Start() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	cm.watcher = watcher

	// Watch the config file
	if err := watcher.Add(cm.configPath); err != nil {
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	slog.Info("watching config file", "path", cm.configPath)

	go cm.watchLoop()
	return nil
}

// Stop stops watching the config file.
func (cm *ConfigManager) Stop() {
	if cm.watcher != nil {
		cm.watcher.Close()
	}
	cm.done <- true
}

// Get returns current config (thread-safe).
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cfg
}

// watchLoop monitors config file changes with debouncing.
func (cm *ConfigManager) watchLoop() {
	var timer *time.Timer

	for {
		select {
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			// Only handle write and create events
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				slog.Info("config file changed", "path", event.Name)

				// Cancel pending reload
				if timer != nil {
					timer.Stop()
				}

				// Schedule reload with debounce
				timer = time.AfterFunc(time.Duration(cm.cfg.Server.ReloadDebounce)*time.Second, func() {
					cm.reloadConfig()
				})
			}

		case err := <-cm.watcher.Errors:
			slog.Error("config watcher error", "error", err)

		case <-cm.done:
			return
		}
	}
}

// reloadConfig reloads the config file and applies changes.
func (cm *ConfigManager) reloadConfig() {
	newCfg, err := LoadConfig(cm.configPath)
	if err != nil {
		slog.Error("failed to reload config", "error", err)
		return
	}

	cm.mu.Lock()
	oldCfg := cm.cfg
	cm.cfg = newCfg
	cm.mu.Unlock()

	// Calculate what changed
	changes := cm.detectChanges(oldCfg, newCfg)

	// Call callback with changes
	if cm.onReload != nil {
		startTime := time.Now()
		if err := cm.onReload(newCfg, changes); err != nil {
			slog.Error("failed to apply config changes", "error", err)
			// Revert to old config
			cm.mu.Lock()
			cm.cfg = oldCfg
			cm.mu.Unlock()
			return
		}
		duration := time.Since(startTime)
		slog.Info("config reloaded successfully", "duration", duration)
	}
}

// detectChanges compares old and new configs to determine what changed.
func (cm *ConfigManager) detectChanges(oldCfg, newCfg *Config) ZoneChanges {
	changes := ZoneChanges{}

	// Check if server config changed
	if cm.cfg.Server.Bind != newCfg.Server.Bind || cm.cfg.Server.Timeout != newCfg.Server.Timeout {
		changes.ServerChanged = true
		slog.Info("server config changed", "bind", newCfg.Server.Bind, "timeout", newCfg.Server.Timeout)
	}

	// Build maps of zones by name
	oldZones := make(map[string]ZoneConfig)
	for _, z := range oldCfg.Zones {
		oldZones[z.Name] = z
	}

	newZones := make(map[string]ZoneConfig)
	for _, z := range newCfg.Zones {
		newZones[z.Name] = z
	}

	// Find added zones
	for name := range newZones {
		if _, exists := oldZones[name]; !exists {
			changes.Added = append(changes.Added, name)
			slog.Info("zone added", "zone", name)
		}
	}

	// Find removed zones
	for name := range oldZones {
		if _, exists := newZones[name]; !exists {
			changes.Removed = append(changes.Removed, name)
			slog.Info("zone removed", "zone", name)
		}
	}

	// Find updated zones (same name, different config)
	for name, newZone := range newZones {
		if oldZone, exists := oldZones[name]; exists {
			if zoneConfigChanged(oldZone, newZone) {
				changes.Updated = append(changes.Updated, name)
				slog.Info("zone updated", "zone", name)
			}
		}
	}

	return changes
}

// zoneConfigChanged checks if a zone's configuration changed.
func zoneConfigChanged(old, new ZoneConfig) bool {
	// Check basic fields
	if old.Type != new.Type {
		return true
	}

	// Check files
	if len(old.Files) != len(new.Files) {
		return true
	}
	for i, f := range old.Files {
		if i >= len(new.Files) || f != new.Files[i] {
			return true
		}
	}

	// Check ACL config
	if old.ACL != new.ACL {
		return true
	}

	// Check NS records
	if len(old.NS) != len(new.NS) {
		return true
	}
	for i, ns := range old.NS {
		if i >= len(new.NS) || ns != new.NS[i] {
			return true
		}
	}

	// Check SOA config
	if soaConfigChanged(old.SOA, new.SOA) {
		return true
	}

	return false
}

// soaConfigChanged checks if SOA config changed.
func soaConfigChanged(old, new SOAConfig) bool {
	return old.MName != new.MName ||
		old.RName != new.RName ||
		old.Serial != new.Serial ||
		old.Refresh != new.Refresh ||
		old.Retry != new.Retry ||
		old.Expire != new.Expire ||
		old.Minimum != new.Minimum
}
