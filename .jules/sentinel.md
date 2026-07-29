## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2024-07-29 - Unencrypted OUI Database Download and User-Agent Blocking
**Vulnerability:** The IEEE OUI database was being downloaded over an unencrypted HTTP connection (`http://standards-oui.ieee.org/oui/oui.txt`), exposing the application to Man-in-the-Middle (MitM) attacks which could result in data manipulation or interception.
**Learning:** External resources should always be retrieved over secure HTTPS connections. Additionally, some servers intentionally block standard browser `User-Agent` strings (like `Mozilla/5.0`) with HTTP 418 errors, requiring an alternative user-agent (like `curl/8.5.0`) for successful retrieval.
**Prevention:** Enforce `https://` for all external data downloads to ensure data integrity and confidentiality. When interacting with servers like the IEEE OUI registry, configure non-standard or tool-specific `User-Agent` headers if standard ones are blocked.
