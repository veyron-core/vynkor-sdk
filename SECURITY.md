# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Reporting a Vulnerability

Do not open a public issue.

- **Preferred:** GitHub Security Advisories → `Security → Report a vulnerability` on the repo
- **Email:** btemirkhodjaev@gmail.com with subject `[vynkor security]`

Include: affected repo/commit, reproduction steps, impact, and whether HMAC/JWT/frame handling is involved.

We acknowledge within 48h and aim to ship a fix within 14 days. We will credit you unless you prefer to stay anonymous.

## Scope

In scope: frame MAC bypass, JWT forgery, permission bypass, sandbox escape, path traversal in plugins, signature verification bypass in `vynm`.

Out of scope: DoS via resource exhaustion without bypass, social engineering.
