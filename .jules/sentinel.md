## 2026-07-01 - Fix Path Traversal in Hostname Backup File
**Vulnerability:** A Path Traversal vulnerability existed because the script used the raw `device_data["hostname"]` to build file paths for configuration backups (`f"{filename_hostname}_backup_{timestamp}.cfg"`). A malicious or compromised device returning `../../../hostname` could cause files to be written outside the intended backup directory.
**Learning:** Network device outputs like `hostname` or descriptions should never be implicitly trusted when constructing local system file paths. They should be treated as untrusted input.
**Prevention:** All parsed dynamic fields from network devices must be explicitly sanitized (e.g., using `re.sub(r'[^a-zA-Z0-9_.-]', '_', value)`) before being used in os.path or file I/O operations.
