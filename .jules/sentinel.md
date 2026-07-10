## 2024-05-18 - Path Traversal in Device Output Files
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) were directly used to construct file paths for logs and configuration backups, leading to a path traversal vulnerability.
**Learning:** Even internal or expected network data (like hostnames) can be manipulated by an attacker to write files outside intended directories, which can lead to system compromise or data overwrites.
**Prevention:** All device-provided inputs must be explicitly sanitized before being used in file path construction. When sanitizing, ensure the regex allowlist permits periods (e.g., `[^a-zA-Z0-9_\-\.]`) so valid IPv4 addresses are not malformed.
