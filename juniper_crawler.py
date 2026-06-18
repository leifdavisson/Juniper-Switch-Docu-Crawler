#!/usr/bin/env python3
import os
import sys
import json
import argparse
import getpass
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork
import time

import oui_lookup
import juniper_parser
import juniper_report_generator

RAW_LOGS_DIR = "raw_logs"
BACKUPS_DIR = "backups"
os.makedirs(RAW_LOGS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

def get_local_ip_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
        subnet = ".".join(local_ip.split('.')[:3]) + ".0/24"
    except Exception:
        local_ip = "127.0.0.1"
        subnet = "192.168.1.0/24"
    finally:
        s.close()
    return local_ip, subnet

def check_nmap_installed():
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def run_nmap_scan(subnets):
    targets = " ".join(subnets)
    xml_output = "nmap_results_juniper.xml"
    print(f"Running Nmap scan on target subnets: {targets}")
    cmd = ["nmap", "-sS", "-p", "22,23", "-Pn", "-oX", xml_output] + subnets
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "You must be root" in result.stderr or result.returncode != 0:
            print("Non-root environment detected. Falling back to Nmap TCP Connect scan (-sT)...")
            cmd = ["nmap", "-sT", "-p", "22,23", "-Pn", "-oX", xml_output] + subnets
            subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed: {e}")
        return []
    return parse_nmap_xml(xml_output)

def parse_nmap_xml(xml_file):
    hosts = []
    if not os.path.exists(xml_file):
        return hosts
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            ip = ""
            mac = ""
            ports = []
            for addr in host.findall('address'):
                addr_type = addr.get('addrtype')
                if addr_type == 'ipv4':
                    ip = addr.get('addr')
                elif addr_type == 'mac':
                    mac = addr.get('addr')
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        ports.append(int(port.get('portid')))
            if ip and ports:
                hosts.append({"ip": ip, "mac": mac, "ports": ports})
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
    return hosts

def python_port_scan_worker(ip, ports):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    if open_ports:
        return {"ip": ip, "mac": "", "ports": open_ports}
    return None

def run_python_port_scan(subnets):
    print("Nmap not found. Falling back to internal Python multi-threaded port scanner...")
    discovered = []
    ips_to_scan = []
    for subnet in subnets:
        try:
            net = IPNetwork(subnet)
            if net.prefixlen < 31:
                ips_to_scan.extend([str(ip) for ip in list(net)[1:-1]])
            else:
                ips_to_scan.extend([str(ip) for ip in list(net)])
        except Exception as e:
            print(f"Invalid subnet range ignored: {subnet} ({e})")
    print(f"Scanning {len(ips_to_scan)} IP addresses on ports 22 and 23...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(python_port_scan_worker, ip, [22, 23]): ip for ip in ips_to_scan}
        for future in as_completed(futures):
            res = future.result()
            if res:
                discovered.append(res)
                print(f"  Discovered active host: {res['ip']} (Open ports: {res['ports']})")
    return discovered

def connect_to_device(ip, username, password, conn_type="ssh"):
    from netmiko import ConnectHandler
    device_type = 'juniper_junos' if conn_type == 'ssh' else 'juniper_junos_telnet'
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'global_delay_factor': 2,
    }
    net_connect = ConnectHandler(**device)
    return net_connect

def detect_els(config):
    # ELS uses irb for L3 vlan interfaces; non-ELS uses vlan
    if 'set interfaces irb' in config or 'set vlans ' in config and 'vlan-id' in config:
        # crude detection based on IRB usage which is typical for ELS
        if 'set interfaces irb' in config:
            return True
        # also vlan configuration syntax differences exist, but IRB is a good marker
    return False

def crawl_device(ip, ports, username, password, timestamp):
    conn = None
    mgmt_method = None
    run_dir = os.path.join("outputs", f"juniper_run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)
    raw_logs_dir = os.path.join(run_dir, RAW_LOGS_DIR)
    os.makedirs(raw_logs_dir, exist_ok=True)
    backups_dir = os.path.join(run_dir, BACKUPS_DIR)
    os.makedirs(backups_dir, exist_ok=True)

    if 22 in ports:
        try:
            print(f"[{ip}] Attempting SSH connection...")
            conn = connect_to_device(ip, username, password, conn_type="ssh")
            mgmt_method = "SSH"
        except Exception as e:
            print(f"[{ip}] SSH connection failed: {e}")
    if not conn and 23 in ports:
        try:
            print(f"[{ip}] Attempting Telnet fallback connection...")
            conn = connect_to_device(ip, username, password, conn_type="telnet")
            mgmt_method = "Telnet"
        except Exception as e:
            print(f"[{ip}] Telnet connection failed: {e}")

    if not conn:
        return {"ip": ip, "status": "failed", "reason": "Connection failed (both SSH and Telnet)"}

    device_data = {
        "ip": ip,
        "status": "success",
        "mgmt_method": mgmt_method,
        "os_type": "junos",
        "hostname": "",
        "model": "",
        "serial": "",
        "firmware": "",
        "mac_address": "",
        "is_els": False,
        "neighbors": [],
        "l3_interfaces": [],
        "interfaces_detail": {},
        "stp": {},
        "routes": [],
        "services": {},
        "raw_config": ""
    }

    try:
        # Disable CLI paging
        conn.send_command('set cli screen-length 0')

        # 1. Version information
        sh_ver = conn.send_command('show version')
        with open(os.path.join(raw_logs_dir, f"{ip}_show_version.log"), "w") as f:
            f.write(sh_ver)
        ver_data = juniper_parser.parse_juniper_show_version(sh_ver)
        device_data.update(ver_data)
        if not device_data["hostname"]:
            device_data["hostname"] = conn.find_prompt().split('@')[1].replace('>', '').replace('#', '').strip()

        # 2. Chassis Hardware
        sh_hw = conn.send_command('show chassis hardware')
        with open(os.path.join(raw_logs_dir, f"{ip}_show_chassis_hardware.log"), "w") as f:
            f.write(sh_hw)
        hw_data = juniper_parser.parse_juniper_chassis_hardware(sh_hw)
        if not device_data["model"] and hw_data.get("model"):
            device_data["model"] = hw_data["model"]
        if not device_data["serial"] and hw_data.get("serial"):
            device_data["serial"] = hw_data["serial"]

        # 3. Interfaces Terse
        sh_int_terse = conn.send_command('show interfaces terse')
        device_data["l3_interfaces"] = juniper_parser.parse_juniper_interfaces_terse(sh_int_terse)

        # 4. Interfaces Details
        sh_ints = conn.send_command('show interfaces')
        device_data["interfaces_detail"] = juniper_parser.parse_juniper_show_interfaces(sh_ints)

        # 5. LLDP Neighbors
        sh_lldp = conn.send_command('show lldp neighbors detail')
        device_data["neighbors"] = juniper_parser.parse_juniper_lldp_neighbors_detail(sh_lldp)

        # 6. Spanning Tree Bridge and Interface
        sh_stp_bridge = conn.send_command('show spanning-tree bridge')
        sh_stp_int = conn.send_command('show spanning-tree interface')
        device_data["stp"] = juniper_parser.parse_juniper_spanning_tree(sh_stp_bridge, sh_stp_int)

        # 7. Route
        sh_route = conn.send_command('show route')
        device_data["routes"] = juniper_parser.parse_juniper_show_route(sh_route)

        # 8. Configuration
        sh_config = conn.send_command('show configuration | display set')
        device_data["raw_config"] = sh_config
        with open(os.path.join(raw_logs_dir, f"{ip}_configuration.cfg"), "w") as f:
            f.write(sh_config)
            
        filename_hostname = device_data["hostname"] or ip
        backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"
        with open(os.path.join(backups_dir, backup_filename), "w") as f:
            f.write(sh_config)

        device_data["services"] = juniper_parser.parse_juniper_services(sh_config)
        device_data["is_els"] = detect_els(sh_config)

        print(f"[{ip}] Scanned successfully. Hostname: {device_data['hostname']}, Model: {device_data['model']}")
    except Exception as e:
        print(f"[{ip}] Error executing discovery commands: {e}")
        device_data["status"] = "partial"
        device_data["reason"] = f"CLI Command execution failed: {e}"
    finally:
        conn.disconnect()

    return device_data, run_dir

def main():
    parser_arg = argparse.ArgumentParser(description="Juniper Switch Discovery & Documentation Engine")
    parser_arg.add_argument("--subnets", help="Comma-separated target subnets (e.g. 192.168.1.0/24)")
    parser_arg.add_argument("--retry", help="Retry failed scan IPs using a JSON failure log file")
    args = parser_arg.parse_args()

    if not os.path.exists(oui_lookup.OUI_FILE):
        oui_lookup.download_oui_db()

    targets = []
    if args.retry:
        if not os.path.exists(args.retry):
            print(f"Error: Retry file {args.retry} does not exist.")
            sys.exit(1)
        try:
            with open(args.retry, 'r') as f:
                failed_data = json.load(f)
                targets_ips = failed_data.get("failed_ips", [])
                print(f"Loaded {len(targets_ips)} failed hosts from {args.retry} for retry.")
                for ip in targets_ips:
                    targets.append({"ip": ip, "mac": "", "ports": [22, 23]})
        except Exception as e:
            print(f"Error reading retry file: {e}")
            sys.exit(1)
    else:
        local_ip, local_subnet = get_local_ip_subnet()
        subnets_input = args.subnets
        if not subnets_input:
            subnets_input = input(f"Enter target subnets to scan (comma separated) [Default: {local_subnet}]: ").strip()
            if not subnets_input:
                subnets_input = local_subnet

        subnets = [s.strip() for s in subnets_input.split(',')]
        valid_subnets = []
        for s in subnets:
            try:
                IPNetwork(s)
                valid_subnets.append(s)
            except Exception:
                print(f"Skipping invalid subnet input: {s}")

        if not valid_subnets:
            print("No valid target subnets to scan. Exiting.")
            sys.exit(1)

        print("\n--- Phase 1: Subnet Discovery ---")
        if check_nmap_installed():
            targets = run_nmap_scan(valid_subnets)
        else:
            targets = run_python_port_scan(valid_subnets)

        print(f"Discovered {len(targets)} active hosts with open SSH/Telnet ports.")
        if not targets:
            print("No switch management ports (22/23) found. Exiting.")
            sys.exit(1)

    print("\n--- Phase 2: Credentials Input ---")
    username = input("Enter SSH/Telnet username: ").strip()
    password = getpass.getpass("Enter password: ")

    print("\n--- Phase 3: Switch Discovery Crawl ---")
    scanned_devices = {}
    failed_devices = []
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join("outputs", f"juniper_run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(
                crawl_device,
                t["ip"],
                t["ports"],
                username,
                password,
                timestamp
            ): t for t in targets
        }
        for future in as_completed(futures):
            res, dev_run_dir = future.result()
            if dev_run_dir: run_dir = dev_run_dir
            ip = res["ip"]
            if res["status"] == "success":
                scanned_devices[ip] = res
            elif res["status"] == "partial":
                scanned_devices[ip] = res
                failed_devices.append({"ip": ip, "reason": res["reason"], "status": "partial"})
            else:
                failed_devices.append({"ip": ip, "reason": res["reason"], "status": "failed"})

    print("\n--- Phase 4: Generating Deliverables ---")
    if scanned_devices:
        juniper_report_generator.generate_reports(scanned_devices, run_dir)
    else:
        print("No devices were successfully scanned. Skipping reports generation.")

    failed_ips_list = [f["ip"] for f in failed_devices]
    if failed_ips_list:
        failed_log = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "failed_ips": failed_ips_list,
            "details": failed_devices
        }
        with open("juniper_failed_hosts.json", "w") as f:
            json.dump(failed_log, f, indent=4)
        print(f"\nWARNING: {len(failed_ips_list)} devices failed or partial-scanned. Details saved to juniper_failed_hosts.json")

    print("\nNetwork Discovery Complete!")
    print(f"Successfully Scanned: {len(scanned_devices)}")
    print(f"Failed/Partial Scanned: {len(failed_ips_list)}")

if __name__ == "__main__":
    main()
