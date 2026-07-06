# Server-Side Request Forgery (SSRF)

## Detection Signals
- Parameters: `url`, `fetch`, `proxy`, `redirect`, `callback`, `webhook`
- Image/document import features
- PDF generators, screenshot services

## Attack Targets
- Cloud metadata: `169.254.169.254`, `metadata.google.internal`
- Internal services: Redis, Elasticsearch, Docker API
- Local files: `file:///etc/passwd`
- Protocol handlers: `gopher://`, `dict://`, `ftp://`

## Bypass Techniques
- IP encoding: decimal, octal, hex, IPv6
- DNS rebinding
- URL parser confusion: `localhost@evil.com`
- Redirect chains through allowed domains

## Impact Chains
- SSRF → Cloud credentials → Full account compromise
- SSRF → Internal Redis → RCE via CONFIG SET
- SSRF → Admin panels → Privilege escalation