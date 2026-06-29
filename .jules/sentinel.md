## 2026-06-29 - Path Traversal via Untrusted Hostname
**Vulnerability:** The device hostname obtained from the network device was directly used in file paths (e.g., `backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"`), allowing path traversal (e.g., `../../../evil`).
**Learning:** Always treat data from network devices (even administrative ones) as untrusted user input, especially when used in I/O operations.
**Prevention:** Sanitize the hostname (e.g., using `re.sub(r'[^a-zA-Z0-9_.-]', '_', hostname)`) before using it to construct file paths.