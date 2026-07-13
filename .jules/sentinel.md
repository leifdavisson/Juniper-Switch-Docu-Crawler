## 2024-05-24 - Path Traversal Prevention in File Naming
**Vulnerability:** The codebase generated local backup and log files based on untrusted network device outputs (e.g., hostnames, IPs) without any sanitization, which introduced a potential path traversal vulnerability if a device hostname contained strings like "../" or similar malicious characters.
**Learning:** All device-provided inputs must be explicitly sanitized before being used in file path construction.
**Prevention:** Always use a sanitization function containing a regex allowlist (e.g. `[^a-zA-Z0-9_\-\.]`) when constructing file paths from any external data source. Ensure dots are allowed so IP addresses are not malformed.
