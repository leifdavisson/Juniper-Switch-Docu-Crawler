# Cisco Switch Docu-Crawler

A portable, self-contained Python 3 CLI tool that performs network discovery, logs into Cisco switches (supporting **IOS / IOS-XE**, **NX-OS**, and **IOS-XR**), runs safe read-only commands, and compiles authoritative network inventory and documentation reports.

## Features
* **Nmap & Socket Scanner Fallback:** Uses `nmap` via subprocess for scanning. If `nmap` is not installed, it falls back to a built-in multi-threaded Python TCP port scanner.
* **Auto-OS Detection:** Connects initially, detects the Cisco OS (IOS, NX-OS, IOS-XR) via system strings, and dynamically loads the correct Netmiko driver.
* **Safe, Read-Only CLI Commands:** Executes safe status commands (e.g., `show version`, `show running-config`, `show ip interface brief`, `show interfaces`, `show arp`, `show cdp/lldp neighbors`, `show spanning-tree`, `show ip route`).
* **Offline OUI Lookup:** Resolves manufacturer MAC addresses using a built-in common vendor database, with automatic fallback to loading or downloading the official IEEE OUI registry.
* **Failure Management / Retry:** Logs failed or partial hosts to `failed_hosts.json`. You can resume/retry scanning just those hosts using new credentials or network configurations.

---

## 📂 Deliverables Generated
After a successful scan, the crawler generates the following reports in the current directory:
1. **`asset_inventory.csv`**: The authoritative inventory database including Hostname, IP, MAC Address, Device Type, Model, Firmware, Serial Number, Role, and Management Protocol.
2. **`L2_network_diagrams.md`**: Physical topologies, switch-to-switch uplinks, switch stacks, wireless AP connections, and STP blocking/forwarding links documented in standard **Mermaid.js** diagrams.
3. **`L3_network_diagrams.md`**: Logical routing boundaries, Switch Virtual Interfaces (SVIs), VLAN mapping tables, and VRF instances mapped out via Mermaid.js.
4. **`network_analysis_report.md`**: Detailed Layer 1-7 behavior analysis highlighting cabling errors, port utilization percentages, loop/STP risks, overlapping subnets, dynamic routing configurations, AAA/RADIUS setups, and security gaps.
5. **`failed_hosts.json`**: List of hosts that failed scanning for follow-up runs.

---

## 🚀 Getting Started

The easiest way to initialize the environment and run the crawler is using the interactive menu shell:
```bash
chmod +x run.sh
./run.sh
```
This shell will guide you through checking requirements, installing dependencies, executing discovery, retrying failed hosts, and listing backups.

---

### Manual CLI Execution (Alternative)

If you prefer to run the scripts manually, follow these steps:

#### 1. Installation
Install the light dependencies:
```bash
pip install -r requirements.txt
```

#### 2. Make Crawler Executable
```bash
chmod +x cisco_crawler.py
```

#### 3. Run the Discovery Scanner
```bash
./cisco_crawler.py
```
*If no subnets are passed, the script automatically detects your machine's local IP and suggests your local `/24` subnet as the default.*

To specify target subnets directly via CLI:
```bash
./cisco_crawler.py --subnets 192.168.1.0/24,10.0.5.0/24
```

#### 4. Retry Failed/Partial Scans
If any switches fail (due to network timeout, bad credentials, or AAA/enable issues), their details are logged in `failed_hosts.json`. 

You can rerun the crawler to target **only** the failed devices:
```bash
./cisco_crawler.py --retry failed_hosts.json
```
*(The script will scan only those hosts and prompt for credentials again, making it easy to try alternate passwords or troubleshoot connectivity)*

---

## 🛠️ Safe Command Comparison Cheat Sheet
This crawler normalizes command inputs across Cisco platforms based on the following differences:

| Function | IOS / IOS-XE | NX-OS | IOS-XR |
| --- | --- | --- | --- |
| **Interfaces Summary** | `show ip interface brief` | `show ip interface brief` | `show ipv4 interface brief` |
| **MAC Address Table** | `show mac address-table` | `show mac address-table` | Parsed from `show interfaces` / `show arp` |
| **ARP Table** | `show arp` | `show ip arp` | `show arp` |
| **Topology Discovery**| CDP + LLDP detail | CDP + LLDP detail | LLDP only |
| **Spanning Tree** | `show spanning-tree` | `show spanning-tree` | Disabled (Routing platforms) |
| **Routing Table** | `show ip route` | `show ip route` | `show route` |
| **Paging Control** | `terminal length 0` | `terminal length 0` | `terminal length 0` |

---

## 🔒 Security & Safety
This script uses **read-only** status commands and does not make configuration changes. All username/password prompting is done securely using Python's standard `getpass` module so that passwords never leak to the terminal logs or bash history.
