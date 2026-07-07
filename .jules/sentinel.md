## 2024-05-24 - Path Traversal in Log Files
**Vulnerability:** Path traversal vulnerability in `juniper_crawler.py` due to using unsanitized network device outputs (such as `hostname` and `ip`) when constructing local backup and log file paths.
**Learning:** Unsanitized device outputs can contain characters like `../` allowing an attacker-controlled device to write files outside the intended log directories.
**Prevention:** All device-provided inputs must be explicitly sanitized (e.g., via regex matching alphanumeric characters) before being used in file path construction to prevent path traversal vulnerabilities.
