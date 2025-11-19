// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"rbldnsd/config"
	"rbldnsd/server"
	"strings"
	"syscall"
)

const Version = "1.0.0"

var (
	GitHash = ""
	Branch  = ""
)

func main() {
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
		if Branch == "master" {
			versionStr = "rbldnsd next"
		} else if Version != "" {
			versionStr = fmt.Sprintf("rbldnsd %s", Version)
		} else if GitHash != "" {
			versionStr = fmt.Sprintf("rbldnsd %s", GitHash)
		} else {
			versionStr = "rbldnsd"
		}
		if GitHash != "" && !(Version == "" && Branch != "master") {
			versionStr += fmt.Sprintf("+%s", GitHash)
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
			log.Fatalf("failed to load config: %v", err)
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
		log.Fatalf("failed to create server: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				log.Println("received SIGHUP, reloading zones")
				if err := srv.Reload(); err != nil {
					log.Printf("failed to reload zones: %v", err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				srv.Shutdown()
				os.Exit(0) // Exit after graceful shutdown completes
			}
		}
	}()

	log.Printf("rbldnsd %s starting on %s", Version, cfg.Server.Bind)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
