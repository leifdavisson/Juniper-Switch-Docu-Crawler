## 2024-05-24 - [CRITICAL] Path Traversal in File Writes
**Vulnerability:** Unsanitized user inputs `ip` and `hostname` (from device prompt) were directly concatenated to file paths using `f"{ip}_show_version.log"` and `f"{filename_hostname}_backup_{timestamp}.cfg"` inside `juniper_crawler.py`.
**Learning:** Even internal network tool scripts that generate local files are vulnerable to path traversal if device hostnames or IPs are spoofed or crafted to include directory traversal characters (e.g., `../`). This could allow writing arbitrary files on the local filesystem.
**Prevention:** Always sanitize any untrusted input used in file path construction by removing or replacing any characters other than alphanumeric characters, dots, dashes, and underscores.
