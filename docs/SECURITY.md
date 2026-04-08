# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch | ✅ |
| Tagged releases | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report security issues privately via GitHub's
[Security Advisory](https://github.com/sambaguard/sambaguard/security/advisories/new) feature.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

We aim to respond within **72 hours** and resolve critical issues within **7 days**.

## Security Architecture Summary

| Layer | Mechanism |
|---|---|
| Authentication | JWT (HS256), bcrypt (cost 12+), account lockout |
| Session | Access token in JS memory, refresh token in httpOnly cookie |
| CSRF | Double-submit cookie (constant-time comparison) |
| Rate limiting | Per-IP token bucket, configurable threshold |
| Command injection | Explicit `exec.Command` args — never `sh -c` + input |
| Input validation | Strict regex on all usernames, paths, share names |
| Transport | TLS recommended; HSTS headers set |
| HTTP headers | CSP, X-Frame-Options, X-Content-Type-Options |
| Audit | Every action logged with actor, target, IP, result |
