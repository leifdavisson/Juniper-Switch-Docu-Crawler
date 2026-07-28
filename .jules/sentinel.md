## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2026-07-28 - Insecure External Resource Download
**Vulnerability:** External database files (IEEE OUI) were downloaded using unencrypted HTTP (`http://standards-oui.ieee.org/oui/oui.txt`), exposing the application to Man-in-the-Middle (MitM) attacks where the downloaded file could be intercepted and modified.
**Learning:** All external network communications, especially when downloading data or executable code, must use encrypted channels (HTTPS) to guarantee data integrity and confidentiality.
**Prevention:** Enforce secure HTTPS connections (`https://`) when making external requests or downloading files. Also be aware of server-side restrictions on default User-Agents (like `Mozilla/5.0` being blocked).
