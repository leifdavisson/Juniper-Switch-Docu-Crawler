## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2024-07-26 - Insecure HTTP Download of OUI Database
**Vulnerability:** The IEEE OUI database was being downloaded over an unencrypted HTTP connection (`http://standards-oui.ieee.org/oui/oui.txt`).
**Learning:** External assets and datasets downloaded at runtime without encryption are susceptible to Man-in-the-Middle (MitM) attacks, allowing an attacker to intercept and modify the contents of the database.
**Prevention:** Always use HTTPS (`https://`) when downloading external resources or making API requests to ensure confidentiality and data integrity.
