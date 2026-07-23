## 2026-07-23 - Insecure External Data Download via HTTP
**Vulnerability:** The application was downloading the official IEEE OUI registry using an unencrypted `http://` URL instead of `https://`.
**Learning:** Hardcoded URLs for external resources that omit TLS/SSL (HTTPS) leave the application vulnerable to Man-in-the-Middle (MitM) attacks where an attacker could intercept or tamper with the downloaded data.
**Prevention:** Always enforce secure HTTPS connections (`https://`) when making external requests or downloading files to ensure data integrity and confidentiality.

## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.
