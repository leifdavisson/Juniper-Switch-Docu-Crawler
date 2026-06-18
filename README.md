# Juniper Switch Docu-Crawler

<p align="center">
  <img src="docs/images/banner.png" alt="Juniper Switch Docu-Crawler Banner" width="100%" max-width="800px" style="border-radius: 8px;" />
</p>

<p align="center">
  <a href="https://github.com/leifdavisson/Juniper-Switch-Docu-Crawler/actions/workflows/ci.yml">
    <img src="https://github.com/leifdavisson/Juniper-Switch-Docu-Crawler/actions/workflows/ci.yml/badge.svg" alt="CI Status" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL v3" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Support" />
  </a>
  <a href="https://github.com/ktbyers/netmiko">
    <img src="https://img.shields.io/badge/dependency-Netmiko%20v4+-orange.svg" alt="Netmiko Dependency" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform Support" />
  </a>
</p>

A portable, self-contained Python 3 CLI tool that performs network discovery, logs into Juniper switches (supporting **Junos**, **ELS**, and **Non-ELS**), runs safe read-only commands, and compiles authoritative network inventory, configuration backups, and network diagrams.

---

## ✨ Features

* **Nmap & Socket Scanner Fallback:** Uses `nmap` via subprocess for scanning. If `nmap` is not installed, it falls back to a built-in multi-threaded Python TCP port scanner.
* **Junos CLI Automation:** Connects using Netmiko's `juniper_junos` drivers and interacts specifically with Junos devices.
* **Safe, Read-Only CLI Commands:** Executes safe status commands (e.g., `show version`, `show chassis hardware`, `show interfaces terse`, `show interfaces`, `show lldp neighbors detail`, `show spanning-tree`, `show route`, `show configuration | display set`).
* **Switch Configuration Backups:** Saves `display set` running configurations as standard backups for documentation.
* **Offline OUI Lookup:** Resolves manufacturer MAC addresses using a built-in common vendor database, with automatic fallback to loading or downloading the official IEEE OUI registry.
* **Failure Management / Retry:** Logs failed or partial hosts to `juniper_failed_hosts.json`. You can resume/retry scanning just those hosts using new credentials or network configurations.

---

## 📂 Deliverables Generated

After a successful scan, the crawler compiles and generates the following reports in `outputs/juniper_run_<timestamp>/`:

1. **`asset_inventory.csv`**: The authoritative inventory database including Hostname, IP, MAC Address, Model, Firmware, Serial Number, and ELS/Non-ELS architecture.
2. **`L2_network_diagrams.md`**: Physical topologies, switch-to-switch uplinks, and STP blocking/forwarding links documented in standard **Mermaid.js** diagrams.
3. **`L3_network_diagrams.md`**: Logical routing boundaries and L3 interfaces mapped out via Mermaid.js.
4. **`network_analysis_report.md`**: Detailed Layer 1-7 behavior analysis highlighting cabling errors, port utilization, loop/STP risks, and L4-L7 configurations.

---

## 🚀 Getting Started

### 1. Installation
Ensure Python 3 is installed, then install the light dependencies:
```bash
pip install -r requirements.txt
```

### 2. Make Run Script Executable (Linux/macOS)
```bash
chmod +x juniper_run.sh
```

### 3. Run the Discovery Scanner
You can run the wrapper script:
```bash
./juniper_run.sh
```
*If no subnets are passed, the script automatically detects your machine's local IP and suggests your local `/24` subnet as the default.*

To specify target subnets directly via CLI:
```bash
./juniper_run.sh --subnets 192.168.1.0/24,10.0.5.0/24
```

Alternatively, you can run the python script directly:
```bash
python3 juniper_crawler.py --subnets 192.168.1.0/24
```

#### 4. Retry Failed/Partial Scans
If any switches fail (due to network timeout, bad credentials, etc.), their details are logged in `juniper_failed_hosts.json`. 

You can rerun the crawler to target **only** the failed devices:
```bash
./juniper_run.sh --retry juniper_failed_hosts.json
```

---

## 🖥️ How to View the Generated Reports (.md & Mermaid Diagrams)

The generated reports are written in **Markdown (`.md`)** format, which is a clean, readable text format. The physical and logical network diagrams are created using **Mermaid.js**, a text-to-diagram standard.

To view the reports with rich formatting and render the diagrams automatically, we recommend using one of the following tools:

### 1. Obsidian (Recommended & Easiest)
[Obsidian](https://obsidian.md/) natively supports Markdown and renders Mermaid diagrams instantly out-of-the-box.

### 2. GitHub (Zero Installation)
GitHub natively parses Markdown and renders Mermaid diagrams directly inside the web browser.

### 3. Visual Studio Code (VS Code)
Open any `.md` file and open the preview tab. Install the **Markdown Preview Mermaid Support** extension to render the topologies. After opening the doc press Ctrl + Shift + V to view the file. 

---

## 🔒 Security & Safety

This script uses **read-only** status commands and does not make configuration changes. All username/password prompting is done securely using Python's standard `getpass` module so that passwords never leak to the terminal logs or bash history.

---

## 📄 License

This project is licensed under the **GNU Affero General Public License Version 3.0 (AGPL-3.0)**. See the [LICENSE](LICENSE) file for the full license text.
