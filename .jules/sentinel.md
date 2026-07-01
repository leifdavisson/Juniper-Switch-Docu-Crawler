## 2026-07-01 - Fix Unencrypted Data Transmission in oui_lookup.py
**Vulnerability:** Unencrypted Data Transmission (HTTP) for downloading OUI registry database.
**Learning:** HTTP was used for downloading a remote database, risking a MITM attack. The remote server does support HTTPS, so the URL should be changed to HTTPS.
**Prevention:** Always use HTTPS for downloading data to ensure integrity and confidentiality.
