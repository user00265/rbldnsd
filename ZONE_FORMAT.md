# rbldnsd Zone File Format

## Important: Differences from Original rbldnsd

**This Go implementation differs from the original C rbldnsd:**

| Aspect | Original C rbldnsd | This Go Implementation |
|--------|-------------------|----------------------|
| Configuration | Command-line zone specs | YAML configuration file |
| NS/SOA records | `$NS` and `$SOA` directives in zone files | Defined in YAML config per zone |
| Default values | `:` prefix in zone files (`:127.0.0.2:`) | Same format supported |
| `$TTL` directive | Supported in zone files | Not needed (use TTL in records) |

**Zone file compatibility:** Data files (IP addresses, domains) use the same format as original rbldnsd. Only the configuration method differs.

## Overview
rbldnsd is a minimal authoritative-only DNS server designed to serve DNS-based blocklists (DNSBLs). 

**Note:** This Go implementation differs from the original C rbldnsd in how configuration is handled:
- **Configuration:** YAML-based config file (not command-line zone specs)
- **NS/SOA Records:** Defined in YAML config (not `$SOA`/`$NS` directives in zone files)
- **Zone Files:** Data only (IP addresses, domain names, etc.) without special directives

## Configuration vs Zone Files

### YAML Configuration (rbldnsd.yaml)
Zones, NS records, and SOA records are defined in the configuration file:

```yaml
zones:
  - name: bl.example.com
    type: ip4trie
    files:
      - /etc/rbldnsd/blocklist.txt
    ns:
      - ns1.example.com
      - ns2.example.com
    soa:
      mname: ns1.example.com
      rname: hostmaster.example.com
      serial: 2024010101
      refresh: 3600
      retry: 600
      expire: 86400
      minimum: 3600
```

### Zone Data Files
Zone data files contain **only the actual data** (IP addresses, domains, etc.), not NS/SOA directives.

## File Structure
- Lines starting with `#` are comments and are ignored
- Blank lines are ignored
- No special `$SOA` or `$NS` directives needed (use YAML config instead)
- Each line represents a data entry

## Dataset Types

1. **generic** - Standard DNS records (A, TXT, MX, AAAA)
2. **ip4set** - IPv4 CIDR ranges
3. **ip4trie** - IPv4 hierarchical trie (most efficient)
4. **ip4tset** - IPv4 with per-entry values
5. **ip6trie** - IPv6 hierarchical trie
6. **ip6tset** - IPv6 with per-entry values
7. **dnset** - Domain names with wildcards
The generic dataset follows a simplified BIND format:

```
domain [ttl] [IN] record_type record_data
```

#### Supported Record Types in Generic Dataset:

**A Records:**
```
example.com 3600 IN A 192.0.2.1
```

**TXT Records:**
```
example.com 3600 IN TXT "This is a text record"
example.com 3600 TXT Listed
```

**MX Records:**
```
example.com 3600 IN MX 10 mail.example.com
```

**Special Cases:**
- `@` can be used as shorthand for the zone apex
- If TTL is omitted, a default TTL is used
- If `IN` class is omitted, it's assumed
- Forward lookups use standard domain names

### IP4Set Dataset Format
IP4SET is the most common format for DNSBL/RBL usage:

```
IP_ADDRESS[:port] [RETURN_VALUE]
IP_RANGE [RETURN_VALUE]
```

#### Entry Formats:

**Single IP address:**
```
192.0.2.1
192.0.2.1 127.0.0.2
```

**IP range (CIDR notation):**
```
192.0.2.0/24
192.0.2.0/24 127.0.0.2
```

**IP range (dot notation, /32, /24, /16, /8 only):**
```
192.0.2.* 127.0.0.2
192.0.*.* 127.0.0.3
```

**Exclusions (prefix with `!`):**
```
192.0.2.0/24 127.0.0.2
!192.0.2.1
```

**Default return value (starts with `:`)**:
```
:127.0.0.2
```

#### Return Values:
Return values can be:
- IPv4 address (e.g., `127.0.0.2`) - becomes A record
- Text with `:` separator (e.g., `:127.0.0.2:listed`) - A and TXT records
- Text only (e.g., `listed`) - TXT record only

**Return Value Format:**
```
:IPv4_ADDRESS:TXT_DATA
```

Example:
```
:127.0.0.2:Server is blocked
```

### IP4Trie Dataset Format
IP4TRIE is similar to IP4SET but uses a more efficient trie-based implementation:

```
IP_ADDRESS [TEXT_VALUE]
IP_RANGE [TEXT_VALUE]
IP_PATTERN [TEXT_VALUE]
!EXCLUSION
```

#### Entry Formats:

**CIDR notation:**
```
1.2.3.0/24 listed
1.2.3.0/24 127.0.0.2
```

**Wildcard pattern:**
```
0/0 default_value
127.0.0.1 localhost
1.2.3.* value
```

**Exclusions:**
```
1.2.3.0/24 listed
!1.2.3.4
```

**Default value:**
```
0/0 wild
```

### Parsing Rules

#### Domain Name Parsing
- Domain names are parsed from the zone file and converted to wire format
- Case-insensitive (converted to lowercase internally)
- Must be fully qualified (end with `.` optional, assumed if missing in certain contexts)

#### TTL Parsing
- Numeric values are treated as seconds
- Suffixes supported: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks)
- Examples: `3600`, `1h`, `24h`, `7d`
- Min/max TTL constraints can be enforced

#### IP Address Parsing
- IPv4 addresses: standard dotted-quad notation (e.g., `192.0.2.1`)
- IPv6 addresses: standard colon notation (e.g., `2001:db8::1`)
- CIDR notation: `address/prefix_length`
- Wildcards (IP4 only): `address.octet.*` or `address.*.*`

### Entry Sorting and Deduplication
- Entries are typically sorted during zone file loading
- Duplicate domain names may be deduplicated (pointed to same location in memory)
- Entries are organized by type for efficient lookup

## Example Zone Files

### Simple IP4SET Blocklist
```
# Simple RBL blocklist
192.0.2.0/24 127.0.0.2
192.0.3.0/24 127.0.0.3
203.0.113.4 127.0.0.5:Spam source

# Exclusions
203.0.113.0/24 127.0.0.2
!203.0.113.42
```

### IP4TRIE with Defaults
```
# Default catch-all
0/0 127.0.0.2

# Specific overrides
127.0.0.1 listed
203.0.113.0/24 127.0.0.5
!203.0.113.42
```

### Generic Dataset Example

Zone file (dns-records.txt):
```
example.org 3600 IN A 192.0.2.1
mail.example.org 3600 IN A 192.0.2.2
example.org 3600 IN MX 10 mail.example.org
example.org 3600 IN TXT "v=spf1 mx ~all"
example.org 3600 IN AAAA 2001:db8::1
```

Configuration (rbldnsd.yaml):
```yaml
zones:
  - name: example.org
    type: generic
    files:
      - dns-records.txt
    ns:
      - ns1.example.org
      - ns2.example.org
    soa:
      mname: ns1.example.org
      rname: hostmaster.example.org
      serial: 2024010101
```


## Parsing Flow

1. **File Reading**: Lines are read using buffered I/O (istream) with efficient line-by-line processing
2. **Line Processing**: 
   - Skip comments (lines starting with `#`)
   - Skip blank lines
   - Handle metadata lines (starting with `$`)
   - Parse data entries based on dataset type
3. **Data Parsing**: 
   - Parse domain names, IP addresses, and values
   - Store in memory pool (mp-allocated)
   - Accumulate entries
4. **Sorting**: Sort and deduplicate entries for efficient lookup
5. **Query**: Use appropriate lookup function (binary search, trie, etc.) for the dataset type

## Performance Optimizations

- **Memory Pooling**: Allocates memory in pools rather than individual allocations
- **Wire Format Storage**: Domain names stored in DNS wire format for fast comparison
- **Efficient Lookup Structures**:
  - Binary search for generic and simple formats
  - Tries (btrie) for IP address hierarchies
  - Range-based lookup for CIDR blocks
- **Lazy Sorting**: Entries sorted once during load, not at query time

## Command-Line Usage

```bash
rbldnsd -n -b 127.0.0.1/5300 example.com:ip4set:zone.txt other.com:generic:other.zone
```

Options:
- `-n`: Foreground (no fork)
- `-b address/port`: Bind address and port
- `zone:type:file[,file,...]`: Zone specification(s)

## IP4TSet Dataset Type

IP4 addresses with per-entry values (trivial set).

**Format:**
```
# Default value
:127.0.0.2

# Individual IPs with optional values
192.0.2.1
192.0.2.2 127.0.0.3
192.0.2.3 127.0.0.4:3600
```

**Features:**
- Exact IP address matching only (no CIDR ranges)
- Per-entry value override
- Per-entry TTL support

## IP6TSet Dataset Type

IPv6 addresses with per-entry values.

**Format:**
```
# Default value
:2001:db8::1

# Individual IPv6 addresses
2001:db8::dead:beef
2001:db8::1234 2001:db8::2:1
```

**Features:**
- Exact IPv6 address matching
- Per-entry value override
- Per-entry TTL support

## DNSet Dataset Type

Domain name sets with wildcard support.

**Format:**
```
# Default value
:127.0.0.2

# Exact domain matches
example.com 127.0.0.3
badactor.org 127.0.0.4

# Wildcard matches
*.spam.example 127.0.0.5

# Negation (exclude from matching)
!good.spam.example
```

**Features:**
- Exact domain name matching
- Wildcard subdomain matching (`*.domain`)
- Negation support (`!domain`)
- Case-insensitive matching
- Per-entry values and TTL

**Matching Priority:**
1. Negated exact matches
2. Non-negated exact matches  
3. Negated wildcard matches
4. Non-negated wildcard matches

**Examples:**
```
# Block all subdomains of spam.example but allow mail.spam.example
*.spam.example 127.0.0.2
!mail.spam.example

# Block specific domains
malware.com 127.0.0.10
phishing.net 127.0.0.11:7200
```
