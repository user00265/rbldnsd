# rbldnsd

[![Build](https://github.com/user00265/rbldnsd/workflows/Build/badge.svg)](https://github.com/user00265/rbldnsd/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.23+](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org/)

DNS server for blocklists. Answers DNS queries for IP ranges and domain names. Good for spam filtering and network access control.

## Features

- All 7 dataset types (ip4trie, ip4set, ip4tset, ip6trie, ip6tset, dnset, generic)
- IPv6 with AAAA records
- Per-zone access control (ACLs)
- Prometheus/OpenTelemetry metrics
- Config file (YAML) or CLI mode
- Dynamic config reloading (add/remove/update zones without restart)
- Single binary, no external dependencies

## Install

```bash
go build
```

## Usage

### Config File (Recommended)

```bash
./rbldnsd -c rbldnsd.yaml
```

Example `rbldnsd.yaml`:
```yaml
server:
  bind: "0.0.0.0:53"
  auto_reload: true          # Watch config for changes

zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /etc/rbldnsd/blocklist.txt
    ns:
      - ns1.example.com
    soa:
      mname: ns1.example.com
      rname: hostmaster.example.com
      serial: 2024010101

  - name: wl.example.com
    type: generic
    files:
      - /etc/rbldnsd/whitelist.txt
    acl_rules:
      allow:
        - 192.168.0.0/16
      deny:
        - 203.0.113.0/24

metrics:
  prometheus_endpoint: "0.0.0.0:9090"
```

### CLI Mode (Testing)

```bash
# Single zone
./rbldnsd -z "bl.local:ip4trie:blocklist.txt"

# Multiple zones
./rbldnsd -z "bl.local:ip4trie:blocklist.txt wl.local:generic:whitelist.txt"

# Custom port
./rbldnsd -b 127.0.0.1:5300 -z "bl.local:ip4trie:blocklist.txt"

# Foreground (for debugging)
./rbldnsd -n -b 127.0.0.1:5300 -z "bl.local:ip4trie:blocklist.txt"
```

## Zone Files

### IP4 Blocklist Format (ip4trie)
```
# CIDR blocks with optional return values
192.0.2.0/24 127.0.0.2
203.0.113.0/24 127.0.0.3:Listed

# Exclusions
!192.0.2.50

# Default
0.0.0.0/0 127.0.0.2
```

### Generic DNS Records (generic)
```
example.com 3600 IN A 192.0.2.1
example.com 3600 IN TXT "v=spf1 mx -all"
mail.example.com 3600 IN A 192.0.2.2
example.com 3600 IN MX 10 mail.example.com
```

### Domain Blocklist (dnset)
```
spam.example.com 127.0.0.2
*.badactor.org 127.0.0.3
!trusted.badactor.org
```

## Query Examples

```bash
# Check if IP is listed (reverse DNS)
dig @localhost 4.3.2.192.bl.local A

# Forward DNS query
dig @localhost wl.local A
dig @localhost wl.local MX
```

## Flags

| Flag | Default | Use |
|------|---------|-----|
| `-c file.yaml` | - | Load config from file |
| `-z "zone:type:file"` | - | Define zone via CLI (spaces separate multiple zones) |
| `-b addr:port` | 0.0.0.0:53 | Bind address |
| `-n` | - | Run in foreground |
| `-v` | - | Show version |

**Config file mode** (`-c`) is recommended for production. Use when you need multiple zones, ACLs, or metrics.

**CLI mode** (`-z`) is for testing or simple one-zone setups. Limitations: no ACLs, no NS/SOA records, no metrics.

Examples:
```bash
# Config file (recommended)
./rbldnsd -c rbldnsd.yaml

# CLI - single zone
./rbldnsd -z "bl.local:ip4trie:blocklist.txt"

# CLI - multiple zones (spaces separate)
./rbldnsd -z "bl.local:ip4trie:blocklist.txt wl.local:generic:whitelist.txt"

# CLI - custom port
./rbldnsd -b 127.0.0.1:5300 -z "bl.local:ip4trie:blocklist.txt"

# Foreground for debugging
./rbldnsd -n -b 127.0.0.1:5300 -z "bl.local:ip4trie:blocklist.txt"
```

## Signals

- `SIGHUP` - Reload zones
- `SIGTERM/SIGINT` - Graceful shutdown

## Docker

### Build and Run

```bash
docker build -t rbldnsd .
docker-compose up -d
```

### Standalone Container

Default (uses `/config/rbldnsd.yaml`):
```bash
docker run -d \
  --name rbldnsd \
  -p 53:53/udp \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/data:/data:ro \
  rbldnsd:latest
```

Custom config path:
```bash
docker run -d \
  --name rbldnsd \
  -p 53:53/udp \
  -v $(pwd)/config:/my-config:ro \
  -v $(pwd)/data:/data:ro \
  -e CONFIG_PATH=/my-config/rbldnsd.yaml \
  rbldnsd:latest
```

CLI flags (no config file):
```bash
docker run -d \
  --name rbldnsd \
  -p 53:53/udp \
  -v $(pwd)/data:/data:ro \
  rbldnsd:latest -z "bl.local:ip4trie:/data/blocklist.txt"
```

### Config File with Auto-Reload

rbldnsd watches the config file for changes:
- **Add zone** → Loaded automatically
- **Remove zone** → Unloaded automatically  
- **Update zone files** → Reloaded automatically

Requires `auto_reload: true` in config (default).

To manually reload (SIGHUP signal):
```bash
docker kill -s HUP rbldnsd
```

## Configuration

### Server Settings

```yaml
server:
  bind: "0.0.0.0:53"         # Listen address
  timeout: 5                  # Query timeout in seconds
  auto_reload: true           # Watch config for changes
  reload_debounce: 2          # Debounce delay in seconds
```

### Zone Configuration

```yaml
zones:
  - name: bl.example.com
    type: ip4trie              # Dataset type
    files:
      - /data/blocklist.txt
    
    # ACL options (choose one):
    # Option 1: Inline rules
    acl_rules:
      allow:
        - 192.168.0.0/16
      deny:
        - 203.0.113.0/24
    
    # Option 2: External file
    # acl: /etc/rbldnsd/acl.txt
    
    # NS records (optional)
    ns:
      - ns1.example.com
      - ns2.example.com
    
    # SOA record (optional)
    soa:
      mname: ns1.example.com
      rname: hostmaster.example.com
      serial: 2024010101
      refresh: 3600
      retry: 600
      expire: 86400
      minimum: 3600
```

### ACL File Format

```
allow:
192.168.0.0/16
10.0.0.0/8
127.0.0.1

deny:
203.0.113.0/24
```

### Metrics

```yaml
metrics:
  prometheus_endpoint: "0.0.0.0:9090"
  otel_endpoint: "http://localhost:4318"
```

## Dataset Types

| Type | Use |
|------|-----|
| ip4trie | IPv4 blocklists (efficient trie-based) |
| ip4set | IPv4 simple ranges |
| ip4tset | IPv4 with per-entry values |
| ip6trie | IPv6 blocklists |
| ip6tset | IPv6 with per-entry values |
| dnset | Domain blocklists with wildcards |
| generic | Standard DNS records (A, MX, TXT, AAAA) |

## Dynamic Configuration

When using `-c`, rbldnsd watches the config file for changes (requires `auto_reload: true`, which is default).

No restart needed:
- Add a zone → Loaded automatically
- Remove a zone → Unloaded automatically
- Update zone files → Reloaded automatically
- Change settings → Applied to new queries

## Systemd

```ini
[Unit]
Description=rbldnsd
After=network.target

[Service]
Type=simple
User=rbldnsd
ExecStart=/usr/local/bin/rbldnsd -c /etc/rbldnsd/rbldnsd.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable rbldnsd
sudo systemctl start rbldnsd
sudo systemctl reload rbldnsd  # Reload zones
```

## Performance

- Memory: All zones loaded at startup
- CPU: Concurrent queries handled with goroutines
- Network: UDP only (no TCP)
- Speed: O(1) ACL matching, efficient trie lookups

## Differences from Original rbldnsd

Same:
- Zone file format (100% compatible)
- All 7 dataset types
- DNS query responses

Different:
- Config is YAML (not `$SOA`/`$NS` directives in zone files)
- Dynamic config reloading (watches file)
- IPv6 AAAA record support
- Metrics (Prometheus/OpenTelemetry)

## Limitations

- UDP only (no TCP DNS)
- No DNSSEC
- No rate limiting (use firewall/load balancer)
- Bind address change requires restart

## Error Handling

### Invalid Config File on Startup
- **With `-c`**: Logs error and exits. No zones loaded.
- **Without `-c` (CLI mode)**: Not applicable.

### Invalid Config File During Reload
- Logs error, keeps running with previous config. Next change to file will be retried.
- Partial updates are applied: removed zones are removed, valid new zones are loaded, invalid zones are skipped.

### Invalid Zone File on Startup
- **With `-c`**: Zone is skipped, logs warning, other zones continue loading. Server starts even if all zones fail.
- **Without `-c` (CLI mode)**: Logs error and exits. Server will not start without valid zones.

### Invalid Zone File During Reload
- Zone is skipped, old copy stays in memory. Next file change will be retried automatically.
- Other zones reload normally. No impact on running queries.

### Invalid ACL File
- Same behavior as zone files: skip on error, keep running.

## License

MIT - See LICENSE file

## Security

For security issues, see [SECURITY.md](SECURITY.md)
