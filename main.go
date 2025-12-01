// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/user00265/rbldnsd/config"
	"github.com/user00265/rbldnsd/server"
)

// levelWriter routes log records to stdout or stderr based on level
type levelWriter struct{}

func (lw levelWriter) Write(p []byte) (n int, err error) {
	// This is called by the handler, but we'll use a custom handler instead
	return os.Stdout.Write(p)
}

// multiLevelHandler routes ERROR logs to stderr, everything else to stdout
type multiLevelHandler struct {
	infoHandler  slog.Handler
	errorHandler slog.Handler
}

func (h *multiLevelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *multiLevelHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		return h.errorHandler.Handle(ctx, r)
	}
	return h.infoHandler.Handle(ctx, r)
}

func (h *multiLevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiLevelHandler{
		infoHandler:  h.infoHandler.WithAttrs(attrs),
		errorHandler: h.errorHandler.WithAttrs(attrs),
	}
}

func (h *multiLevelHandler) WithGroup(name string) slog.Handler {
	return &multiLevelHandler{
		infoHandler:  h.infoHandler.WithGroup(name),
		errorHandler: h.errorHandler.WithGroup(name),
	}
}

const Version = "1.0.0"

var (
	GitHash = ""
	Branch  = ""
)

func main() {
	// Configure structured logging with INFO/WARN to stdout, ERROR to stderr
	handler := &multiLevelHandler{
		infoHandler:  slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		errorHandler: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}),
	}
	slog.SetDefault(slog.New(handler))

	var (
		bind       = flag.String("b", "", "bind address and port (host:port)")
		zones      = flag.String("z", "", "zone specifications (zone:type:file,...)")
		configFile = flag.String("c", "", "config file (YAML)")
		version    = flag.Bool("v", false, "show version")
	)
	flag.Bool("n", false, "run in foreground (no fork)")
	flag.Parse()

	if *version {
		var versionStr string
		if Version != "" {
			versionStr = fmt.Sprintf("rbldnsd %s", Version)
			if GitHash != "" {
				versionStr += fmt.Sprintf("+%s", GitHash)
			}
		} else if Branch == "master" {
			versionStr = "rbldnsd next"
			if GitHash != "" {
				versionStr += fmt.Sprintf("+%s", GitHash)
			}
		} else if GitHash != "" {
			versionStr = fmt.Sprintf("rbldnsd %s", GitHash)
		} else {
			versionStr = "rbldnsd"
		}
		fmt.Println(versionStr)
		fmt.Println("GitHub: https://github.com/user00265/rbldnsd")
		os.Exit(0)
	}

	var cfg *config.Config
	var err error

	// Load config from file if provided
	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			slog.Error("failed to load config", "error", err)
			os.Exit(1)
		}
	} else {
		// Build config from CLI flags
		cfg = &config.Config{
			Server: config.ServerConfig{
				Bind:    "0.0.0.0:53",
				Timeout: 5,
			},
			Logging: config.LoggingConfig{
				Level: "info",
			},
		}

		if *bind != "" {
			cfg.Server.Bind = *bind
		}

		if *zones == "" && len(cfg.Zones) == 0 {
			fmt.Fprintf(os.Stderr, "usage: rbldnsd [options]\n")
			fmt.Fprintf(os.Stderr, "  -b address:port  bind address and port (default: 0.0.0.0:53)\n")
			fmt.Fprintf(os.Stderr, "  -z specs         zone specifications (zone:type:file,...)\n")
			fmt.Fprintf(os.Stderr, "  -c config.yaml   config file (YAML)\n")
			fmt.Fprintf(os.Stderr, "  -n               run in foreground\n")
			fmt.Fprintf(os.Stderr, "  -v               show version\n")
			os.Exit(1)
		}

		if *zones != "" {
			// Parse CLI zones into config
			zoneSpecs := strings.Split(*zones, " ")
			for _, spec := range zoneSpecs {
				parts := strings.SplitN(spec, ":", 3)
				if len(parts) == 3 {
					cfg.Zones = append(cfg.Zones, config.ZoneConfig{
						Name:  parts[0],
						Type:  parts[1],
						Files: strings.Split(parts[2], ","),
					})
				}
			}
		}
	}

	srv, err := server.New(cfg, *configFile)
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				slog.Info("received SIGHUP, reloading zones")
				if err := srv.Reload(); err != nil {
					slog.Error("failed to reload zones", "error", err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				srv.Shutdown()
				os.Exit(0) // Exit after graceful shutdown completes
			}
		}
	}()

	slog.Info("rbldnsd starting", "version", Version, "bind", cfg.Server.Bind)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
