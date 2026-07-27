## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2026-07-27 - Man-in-the-Middle (MitM) Vulnerability in External Downloads
**Vulnerability:** The IEEE OUI database was being downloaded over an unencrypted `http://` connection, making the application vulnerable to Man-in-the-Middle (MitM) attacks where the downloaded data could be intercepted and maliciously altered.
**Learning:** All external requests or file downloads must enforce secure HTTPS connections (`https://`) to ensure data integrity and confidentiality. Additionally, the IEEE server intentionally blocks standard browser User-Agents (like 'Mozilla/5.0') with an HTTP 418 error, requiring an alternative User-Agent like 'curl/8.5.0'.
**Prevention:** Use `https://` for all URLs in code and verify external endpoints for specific blocking behaviors when integrating with third-party servers.
