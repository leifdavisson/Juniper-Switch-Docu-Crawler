## 2024-07-15 - Path Traversal in Device Data Serialization
**Vulnerability:** Untrusted network device outputs (e.g., hostnames, IPs) are used directly in file path construction (e.g., `filename_hostname = device_data["hostname"] or ip; backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`) leading to potential path traversal vulnerabilities.
**Learning:** Network device outputs, even internal ones, must be treated as untrusted input and explicitly sanitized before being used in file system operations.
**Prevention:** Implement an explicit sanitization function (e.g., using a regex allowlist like `[^a-zA-Z0-9_\-\.]`) for all device-provided inputs before using them in file path construction.

## 2024-07-25 - Unencrypted External Request in OUI Download
**Vulnerability:** The application downloaded the IEEE OUI registry using an unencrypted HTTP connection (`http://standards-oui.ieee.org/oui/oui.txt`), leaving it vulnerable to Man-in-the-Middle (MitM) attacks where the downloaded file could be intercepted or manipulated.
**Learning:** External requests for resources or data must always be performed over secure HTTPS connections, even for seemingly benign public data, to ensure integrity and prevent tampering.
**Prevention:** Always enforce secure HTTPS connections (`https://`) when making external requests or downloading files.
