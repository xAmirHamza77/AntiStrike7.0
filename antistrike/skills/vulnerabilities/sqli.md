# SQL Injection Testing

## Detection Signals
- Parameters: `id`, `user`, `search`, `category`, `sort`, `filter`
- Database error messages in responses
- Different response lengths for true/false conditions

## Techniques
1. **Error-based** — Trigger syntax errors to leak DB info
2. **Union-based** — Extract data via UNION SELECT
3. **Boolean blind** — Compare response differences for true/false
4. **Time-based** — Use SLEEP/WAITFOR for blind confirmation
5. **Stacked queries** — Execute additional SQL statements

## Bypass Methods
- Comment variations: `--`, `#`, `/**/`
- Case manipulation: `UnIoN SeLeCt`
- Encoding: URL, double-URL, hex, unicode
- WAF bypass: inline comments, scientific notation, null bytes

## Validation
- Extract version string or table name as proof
- Document exact parameter and payload
- Assess data exposure scope