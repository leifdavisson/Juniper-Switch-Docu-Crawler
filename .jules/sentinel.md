## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2026-07-20 - Insecure OUI Database Download (MitM Risk)
**Vulnerability:** The script downloads the IEEE OUI registry over unencrypted HTTP (`http://standards-oui.ieee.org/oui/oui.txt`), making it vulnerable to Man-in-the-Middle (MitM) attacks. An attacker could intercept and alter the downloaded database.
**Learning:** External resources should never be downloaded over unencrypted connections. HTTP provides no data integrity or confidentiality.
**Prevention:** Always enforce secure HTTPS connections (`https://`) when making external requests or downloading files to ensure data integrity and confidentiality.
