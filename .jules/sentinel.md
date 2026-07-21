## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.
## 2023-10-27 - Insecure HTTP Download of OUI Database
**Vulnerability:** The application downloaded the official IEEE OUI registry over an insecure HTTP connection (`http://standards-oui.ieee.org/oui/oui.txt`).
**Learning:** External resources should always be fetched over HTTPS to prevent Man-in-the-Middle (MitM) attacks where an attacker could serve a malicious or tampered OUI database.
**Prevention:** Enforce secure HTTPS connections (`https://`) when making external requests or downloading files to ensure data integrity and confidentiality.
