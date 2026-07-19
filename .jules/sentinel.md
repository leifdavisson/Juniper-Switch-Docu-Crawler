## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2026-07-19 - Insecure Download URL for External Dependencies
**Vulnerability:** The script downloads the IEEE OUI registry over an insecure HTTP connection, leaving it vulnerable to Man-in-the-Middle (MitM) attacks where the downloaded file could be intercepted and altered.
**Learning:** All external requests for data or dependencies must enforce secure, encrypted connections (HTTPS) to guarantee data integrity and confidentiality.
**Prevention:** Always verify that URLs for downloading external assets use HTTPS by default, especially when the downloaded data is parsed or executed by the application.
