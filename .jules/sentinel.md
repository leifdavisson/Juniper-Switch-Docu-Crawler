## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2026-07-16 - Insecure File Download over HTTP
**Vulnerability:** The IEEE OUI database was being downloaded over an unencrypted HTTP connection (`http://standards-oui.ieee.org/oui/oui.txt`), exposing the application to Man-in-the-Middle (MITM) attacks. An attacker could intercept the traffic and provide a malicious OUI database.
**Learning:** Always use secure, encrypted protocols (HTTPS) for downloading resources, especially data that forms a part of the application's runtime logic or security databases, even when downloading from a trusted domain.
**Prevention:** Hardcode HTTPS protocols instead of HTTP for all external resource requests. Consider using automated tools (like Bandit or Checkov) to scan for unencrypted HTTP links in the codebase.
