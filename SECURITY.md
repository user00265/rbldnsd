# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest | ✅ Yes |
| Older   | ❌ No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, please email sam@samresto.dev privately. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

The maintainers will:
- Acknowledge your report within 48 hours
- Work on a fix
- Notify you when a patch is released
- Credit you in release notes (unless you prefer anonymity)

## Security Considerations

### For rbldnsd Operators

- Use distroless Docker image for minimal attack surface
- Run as non-root user (default in container)
- Keep zone files and ACL files on read-only volumes
- Monitor DNS query logs for anomalies
- Use firewalls to restrict DNS access to trusted networks
- Enable ACLs to limit client access

### Known Limitations

- UDP only (no TCP support)
- No DNSSEC support
- No rate limiting (implement at firewall/load balancer level)
- No query logging (use external monitoring)

## Supported Go Versions

| Version | Supported |
|---------|-----------|
| 1.25    | ✅ Yes |
| 1.24    | ✅ Yes |
| < 1.24  | ❌ No |

rbldnsd is built and tested against Go 1.24. Compatibility with newer versions is verified locally before release.

## Dependencies

rbldnsd has minimal dependencies:
- `fsnotify` - File system monitoring
- `prometheus/client_golang` - Metrics (optional)
- `go.opentelemetry.io` - OpenTelemetry (optional)
- `gopkg.in/yaml.v3` - YAML parsing

We regularly review dependencies for known vulnerabilities.
