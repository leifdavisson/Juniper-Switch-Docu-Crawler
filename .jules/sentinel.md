## 2026-06-27 - Path Traversal in Device Hostname

**Vulnerability:** The crawler script used un-sanitized output from device polling (such as `hostname` and `ip`) to construct file paths for writing configuration backups and raw logs.
**Learning:** Network discovery tools often blindly trust data from the devices they poll. However, a maliciously configured or compromised switch could return a payload like `../../../../etc/cron.d/malicious` as its hostname, which would result in arbitrary file writes (path traversal) on the machine running the crawler.
**Prevention:** Always sanitize any data returned from remote devices before using it in file paths. In this case, replacing slashes (`/`) and backslashes (`\`) with underscores (`_`) was sufficient to prevent path traversal.
