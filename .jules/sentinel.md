## 2026-06-30 - Insecure Data Transmission in OUI Lookup

**Vulnerability:** The `oui_lookup.py` script was downloading the IEEE OUI registry over an unencrypted `http` connection (`http://standards-oui.ieee.org/oui/oui.txt`). This exposes the application to Man-In-The-Middle (MITM) attacks where an attacker could intercept and modify the downloaded registry.

**Learning:** Data transmission over the network should always be encrypted, especially when downloading resources or updating databases that are then trusted and loaded into the application. Even if the data is public, tampering is a risk.

**Prevention:** Ensure that all URLs used for downloading files, querying APIs, or transmitting data use `https` instead of `http`. When utilizing third-party libraries for network requests, enforce secure connections.
