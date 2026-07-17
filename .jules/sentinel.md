## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2024-07-16 - Unencrypted Data Transmission and Missing Timeout
**Vulnerability:** The IEEE OUI database was being downloaded over HTTP, risking unencrypted data transmission and Man-in-the-Middle (MitM) attacks. Additionally, the download request lacked a timeout, leading to potential Denial of Service (DoS) if the server hung.
**Learning:** External resources should always be fetched securely using HTTPS to maintain data integrity and prevent tampering. Also, network requests must have reasonable timeouts to prevent hanging the application.
**Prevention:** Always use HTTPS for external downloads and explicitly set timeouts on network requests (e.g., `urllib.request.urlopen(url, timeout=10)`).
