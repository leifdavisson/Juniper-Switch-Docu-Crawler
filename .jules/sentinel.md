## 2024-05-24 - Path Traversal in File Backups
**Vulnerability:** Untrusted network device outputs (hostnames, IPs) were directly interpolated into backup and raw log file paths, leading to a path traversal vulnerability.
**Learning:** Even internal tool logs that read from networked devices can be vulnerable to path traversal if device hostnames or IPs are maliciously crafted.
**Prevention:** Always sanitize any input originating from networked devices before using it to construct file paths. Use a strict allowlist (e.g., regex `[^a-zA-Z0-9_\-\.]`) ensuring valid values like IPv4 addresses are not malformed while excluding path separators like slashes.
