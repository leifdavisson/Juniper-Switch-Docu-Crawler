## 2024-06-24 - Path Traversal via Unsanitized Hostname
**Vulnerability:** A path traversal vulnerability existed where an attacker-controlled network device returning a malicious hostname (e.g., `../../../etc/cron.d/malicious`) could result in arbitrary file writes outside the intended backup directory when configuration backups are saved.
**Learning:** External or device-provided input (like hostnames) should never be trusted or directly interpolated into file paths. It must always be sanitized to prevent directory traversal and directory creation attacks.
**Prevention:** Always use safe filename extraction (like `os.path.basename`) and strictly filter out invalid characters (e.g., using `re.sub(r'[^a-zA-Z0-9_\-.]', '_', name)`) before using the input to construct file paths.
