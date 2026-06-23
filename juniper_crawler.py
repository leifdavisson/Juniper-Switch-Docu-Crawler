#!/usr/bin/env python3
import os
import sys
import json
import argparse
import getpass
import socket
import subprocess
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork
import time
import queue
import threading

import oui_lookup
import juniper_parser
import juniper_report_generator

RAW_LOGS_DIR = "raw_logs"
BACKUPS_DIR = "backups"

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

def run_nmap_scan_producer(subnets, discovered_queue, scanning_complete_event):
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
        
        hosts = parse_nmap_xml(xml_output)
        for h in hosts:
            discovered_queue.put(h)
    except Exception as e:
        print(f"Nmap scan failed: {e}")
    finally:
        scanning_complete_event.set()

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

def run_python_port_scan_producer(subnets, discovered_queue, scanning_complete_event):
    print("Nmap not found. Falling back to internal Python multi-threaded port scanner...")
    max_active_futures = 500
    futures = set()
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        for subnet in subnets:
            try:
                net = IPNetwork(subnet)
                hosts_iter = net.iter_hosts() if net.prefixlen < 31 else iter(net)
                
                for ip in hosts_iter:
                    ip_str = str(ip)
                    # Cap outstanding futures to avoid memory issues
                    while len(futures) >= max_active_futures:
                        completed = {f for f in futures if f.done()}
                        for f in completed:
                            res = f.result()
                            if res:
                                discovered_queue.put(res)
                                print(f"  Discovered active host: {res['ip']} (Open ports: {res['ports']})")
                        futures -= completed
                        time.sleep(0.01)
                    
                    futures.add(executor.submit(python_port_scan_worker, ip_str, [22, 23]))
                    
            except Exception as e:
                print(f"Invalid subnet range ignored: {subnet} ({e})")
        
        # Wait for all remaining futures to complete
        for f in as_completed(futures):
            res = f.result()
            if res:
                discovered_queue.put(res)
                print(f"  Discovered active host: {res['ip']} (Open ports: {res['ports']})")
                
    scanning_complete_event.set()

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

def detect_model_series(model):
    if not model:
        return "EX"
    model_upper = model.upper()
    if "EX" in model_upper:
        return "EX"
    elif "QFX" in model_upper:
        return "QFX"
    elif "MX" in model_upper:
        return "MX"
    elif "SRX" in model_upper:
        return "SRX"
    return "EX"

def send_command_paced(conn, command, mgmt_method):
    if mgmt_method == "Telnet":
        time.sleep(1.0)
    res = conn.send_command(command)
    if mgmt_method == "Telnet":
        time.sleep(0.5)
    return res

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
        return {"ip": ip, "status": "failed", "reason": "Connection failed (both SSH and Telnet)"}, run_dir

    device_data = {
        "ip": ip,
        "status": "success",
        "mgmt_method": mgmt_method,
        "os_type": "junos",
        "hostname": "",
        "model": "",
        "model_series": "EX",
        "serial": "",
        "firmware": "",
        "mac_address": "",
        "is_els": False,
        "neighbors": [],
        "l3_interfaces": [],
        "interfaces_detail": {},
        "stp": {},
        "routes": [],
        "ospf_neighbors": [],
        "bgp_peers": [],
        "security_zones": [],
        "security_policies": [],
        "services": {},
        "raw_config": ""
    }

    try:
        # Disable CLI paging
        send_command_paced(conn, 'set cli screen-length 0', mgmt_method)

        # 1. Version information
        sh_ver = send_command_paced(conn, 'show version', mgmt_method)
        with open(os.path.join(raw_logs_dir, f"{ip}_show_version.log"), "w", encoding="utf-8") as f:
            f.write(sh_ver)
        ver_data = juniper_parser.parse_juniper_show_version(sh_ver)
        device_data.update(ver_data)
        if not device_data["hostname"]:
            device_data["hostname"] = conn.find_prompt().split('@')[1].replace('>', '').replace('#', '').strip()

        # 2. Chassis Hardware
        sh_hw = send_command_paced(conn, 'show chassis hardware', mgmt_method)
        with open(os.path.join(raw_logs_dir, f"{ip}_show_chassis_hardware.log"), "w", encoding="utf-8") as f:
            f.write(sh_hw)
        hw_data = juniper_parser.parse_juniper_chassis_hardware(sh_hw)
        if not device_data["model"] and hw_data.get("model"):
            device_data["model"] = hw_data["model"]
        if not device_data["serial"] and hw_data.get("serial"):
            device_data["serial"] = hw_data["serial"]

        # 3. Interfaces Terse
        sh_int_terse = send_command_paced(conn, 'show interfaces terse', mgmt_method)
        device_data["l3_interfaces"] = juniper_parser.parse_juniper_interfaces_terse(sh_int_terse)

        # 4. Interfaces Details
        sh_ints = send_command_paced(conn, 'show interfaces', mgmt_method)
        device_data["interfaces_detail"] = juniper_parser.parse_juniper_show_interfaces(sh_ints)

        # 5. LLDP Neighbors
        sh_lldp = send_command_paced(conn, 'show lldp neighbors detail', mgmt_method)
        device_data["neighbors"] = juniper_parser.parse_juniper_lldp_neighbors_detail(sh_lldp)

        model_series = detect_model_series(device_data["model"])
        device_data["model_series"] = model_series

        # 6. Spanning Tree (EX and QFX only)
        if model_series in ("EX", "QFX"):
            try:
                sh_stp_bridge = send_command_paced(conn, 'show spanning-tree bridge', mgmt_method)
                sh_stp_int = send_command_paced(conn, 'show spanning-tree interface', mgmt_method)
                device_data["stp"] = juniper_parser.parse_juniper_spanning_tree(sh_stp_bridge, sh_stp_int)
            except Exception as e:
                print(f"[{ip}] Spanning tree query failed: {e}")
                device_data["stp"] = {"enabled": False, "vlans": {}}
        else:
            device_data["stp"] = {"enabled": False, "vlans": {}}

        # 7. Route
        sh_route = send_command_paced(conn, 'show route', mgmt_method)
        device_data["routes"] = juniper_parser.parse_juniper_show_route(sh_route)

        # 7b. OSPF and BGP (MX, SRX, QFX)
        if model_series in ("MX", "SRX", "QFX"):
            try:
                sh_ospf = send_command_paced(conn, 'show ospf neighbor', mgmt_method)
                device_data["ospf_neighbors"] = juniper_parser.parse_juniper_ospf_neighbors(sh_ospf)
            except Exception as e:
                pass
            try:
                sh_bgp = send_command_paced(conn, 'show bgp summary', mgmt_method)
                device_data["bgp_peers"] = juniper_parser.parse_juniper_bgp_summary(sh_bgp)
            except Exception as e:
                pass

        # 7c. Security Zone & Policies (SRX only)
        if model_series == "SRX":
            try:
                sh_sec_zones = send_command_paced(conn, 'show security zones', mgmt_method)
                device_data["security_zones"] = juniper_parser.parse_juniper_security_zones(sh_sec_zones)
            except Exception as e:
                pass
            try:
                sh_sec_policies = send_command_paced(conn, 'show security policies', mgmt_method)
                device_data["security_policies"] = juniper_parser.parse_juniper_security_policies(sh_sec_policies)
            except Exception as e:
                pass

        # 8. Configuration
        sh_config = send_command_paced(conn, 'show configuration | display set', mgmt_method)
        device_data["raw_config"] = sh_config
        with open(os.path.join(raw_logs_dir, f"{ip}_configuration.cfg"), "w", encoding="utf-8") as f:
            f.write(sh_config)
            
        raw_hostname = device_data["hostname"] or ip
        filename_hostname = re.sub(r'[^a-zA-Z0-9_.-]', '_', raw_hostname)
        backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"
        with open(os.path.join(backups_dir, backup_filename), "w", encoding="utf-8") as f:
            f.write(sh_config)

        device_data["services"] = juniper_parser.parse_juniper_services(sh_config)
        device_data["is_els"] = detect_els(sh_config)
        device_data["vlans"] = juniper_parser.parse_juniper_vlans(sh_config)
        device_data["irb_l3"] = juniper_parser.parse_juniper_irb_l3(sh_config)
        device_data["routing_instances"] = juniper_parser.parse_juniper_routing_instances(sh_config)
        device_data["firewall_filters"] = juniper_parser.parse_juniper_firewall_filters(sh_config)
        device_data["dhcp_services"] = juniper_parser.parse_juniper_dhcp_services(sh_config)
        device_data["static_routes"] = juniper_parser.parse_juniper_static_routes(sh_config)
        device_data["audit_issues"] = juniper_parser.audit_juniper_config(sh_config)

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
    parser_arg.add_argument("--save-baseline", help="Save the current operational state as a baseline file")
    parser_arg.add_argument("--compare-baseline", help="Compare current operational state against a baseline file")
    args = parser_arg.parse_args()

    print("\n--- Credentials Input ---")
    username = input("Enter SSH/Telnet username: ").strip()
    password = getpass.getpass("Enter password: ")

    if not os.path.exists(oui_lookup.OUI_FILE):
        oui_lookup.download_oui_db()

    discovered_queue = queue.Queue()
    scanning_complete_event = threading.Event()
    targets_loaded_directly = False

    if args.retry:
        if not os.path.exists(args.retry):
            print(f"Error: Retry file {args.retry} does not exist.")
            sys.exit(1)
        try:
            with open(args.retry, 'r', encoding="utf-8") as f:
                failed_data = json.load(f)
                targets_ips = failed_data.get("failed_ips", [])
                print(f"Loaded {len(targets_ips)} failed hosts from {args.retry} for retry.")
                for ip in targets_ips:
                    discovered_queue.put({"ip": ip, "mac": "", "ports": [22, 23]})
                scanning_complete_event.set()
                targets_loaded_directly = True
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

        print("\n--- Phase 1: Subnet Discovery (Running in Background) ---")
        if check_nmap_installed():
            scanner_thread = threading.Thread(
                target=run_nmap_scan_producer,
                args=(valid_subnets, discovered_queue, scanning_complete_event)
            )
        else:
            scanner_thread = threading.Thread(
                target=run_python_port_scan_producer,
                args=(valid_subnets, discovered_queue, scanning_complete_event)
            )
        scanner_thread.daemon = True
        scanner_thread.start()

    # Wait for the first host to be discovered (or scanning to complete if nothing found)
    if not targets_loaded_directly:
        print("Scanning and waiting for the first active host to be discovered...")
    
    first_host = None
    while not scanning_complete_event.is_set() or not discovered_queue.empty():
        try:
            first_host = discovered_queue.get(timeout=0.1)
            break
        except queue.Empty:
            continue

    if not first_host:
        print("No switch management ports (22/23) found. Exiting.")
        sys.exit(1)

    print(f"\n[✓] Discovered active host: {first_host['ip']} (Open ports: {first_host['ports']})")

    print("\n--- Phase 3: Switch Discovery Crawl (Concurrently scanning in background) ---")
    scanned_devices = {}
    failed_devices = []
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join("outputs", f"juniper_run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    # Put the first host back into the queue so it gets crawled
    discovered_queue.put(first_host)

    with ThreadPoolExecutor(max_workers=10) as crawler_executor:
        crawler_futures = []
        
        while not scanning_complete_event.is_set() or not discovered_queue.empty():
            try:
                t = discovered_queue.get(timeout=0.1)
                future = crawler_executor.submit(
                    crawl_device,
                    t["ip"],
                    t["ports"],
                    username,
                    password,
                    timestamp
                )
                crawler_futures.append(future)
            except queue.Empty:
                continue

        # Wait for all crawler jobs to finish
        print("[*] Scan complete or finalizing. Waiting for crawling workers to finish...")
        for future in as_completed(crawler_futures):
            try:
                res, dev_run_dir = future.result()
                if dev_run_dir:
                    run_dir = dev_run_dir
                ip = res["ip"]
                if res["status"] == "success":
                    scanned_devices[ip] = res
                elif res["status"] == "partial":
                    scanned_devices[ip] = res
                    failed_devices.append({"ip": ip, "reason": res["reason"], "status": "partial"})
                else:
                    failed_devices.append({"ip": ip, "reason": res["reason"], "status": "failed"})
            except Exception as e:
                print(f"Error executing crawl: {e}")

    print("\n--- Phase 4: Generating Deliverables ---")
    if scanned_devices:
        juniper_report_generator.generate_reports(scanned_devices, run_dir)
        if args.save_baseline:
            juniper_report_generator.save_baseline_state(scanned_devices, args.save_baseline)
        if args.compare_baseline:
            juniper_report_generator.compare_baseline_state(scanned_devices, args.compare_baseline, run_dir)
    else:
        print("No devices were successfully scanned. Skipping reports generation.")

    failed_ips_list = [f["ip"] for f in failed_devices]
    if failed_ips_list:
        failed_log = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "failed_ips": failed_ips_list,
            "details": failed_devices
        }
        with open("juniper_failed_hosts.json", "w", encoding="utf-8") as f:
            json.dump(failed_log, f, indent=4)
        run_failed_hosts_path = os.path.join(run_dir, "juniper_failed_hosts.json")
        with open(run_failed_hosts_path, "w", encoding="utf-8") as f:
            json.dump(failed_log, f, indent=4)
        print(f"\nWARNING: {len(failed_ips_list)} devices failed or partial-scanned.")
        print(f"Details saved to:")
        print(f"  - juniper_failed_hosts.json (workspace root)")
        print(f"  - {run_failed_hosts_path}")

    print("\nNetwork Discovery Complete!")
    print(f"Successfully Scanned: {len(scanned_devices)}")
    print(f"Failed/Partial Scanned: {len(failed_ips_list)}")

if __name__ == "__main__":
    main()
