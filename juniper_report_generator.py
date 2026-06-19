import os
import csv
import json
import re

def sanitize_node_id(name):
    # Mermaid node IDs must be alphanumeric and underscore only
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

def generate_asset_inventory(devices, run_dir):
    filepath = os.path.join(run_dir, "asset_inventory.csv")
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Hostname", "Model", "Serial Number", "Junos Version", "MAC Address", "Architecture"])
        
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                writer.writerow([ip, "Failed/Partial", "", "", "", "", ""])
                continue
                
            writer.writerow([
                ip,
                dev.get("hostname", ""),
                dev.get("model", ""),
                dev.get("serial", ""),
                dev.get("firmware", ""),
                dev.get("mac_address", ""),
                "ELS" if dev.get("is_els") else "Non-ELS"
            ])
    print(f"Generated Asset Inventory: {filepath}")

def generate_l2_diagram(devices, run_dir):
    filepath = os.path.join(run_dir, "L2_network_diagrams.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Juniper L2 Network Diagram\n\n")
        f.write("```mermaid\n")
        f.write("graph TD;\n")
        
        edges = set()
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            host_id = sanitize_node_id(host)
            f.write(f'    {host_id}["{host}\\n{dev.get("model", "Unknown")}"]\n')
            
            for n in dev.get("neighbors", []):
                remote = n.get("remote_device", "Unknown")
                remote_id = sanitize_node_id(remote)
                lport = n.get("local_port", "")
                rport = n.get("remote_port", "")
                edge = f'    {host_id} -- "{lport} to {rport}" --> {remote_id}["{remote}"];\n'
                edges.add(edge)
                
        for edge in edges:
            f.write(edge)
        f.write("```\n")
    print(f"Generated L2 Diagram: {filepath}")

def generate_l3_diagram(devices, run_dir):
    filepath = os.path.join(run_dir, "L3_network_diagrams.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Juniper L3 Network Diagram\n\n")
        f.write("```mermaid\n")
        f.write("graph TD;\n")
        
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            host_id = sanitize_node_id(host)
            f.write(f'    {host_id}["{host} - {ip}"]\n')
            
            for l3 in dev.get("l3_interfaces", []):
                subnet = l3.get("ip_address", "")
                if subnet and subnet != "unassigned":
                    subnet_id = sanitize_node_id(subnet)
                    f.write(f'    {host_id} --- {subnet_id}["{subnet}"]\n')
                    
        f.write("```\n")
    print(f"Generated L3 Diagram: {filepath}")

def generate_network_analysis_report(devices, run_dir):
    filepath = os.path.join(run_dir, "network_analysis_report.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Juniper Network Analysis & Migration Audit Report\n\n")
        
        f.write("## Port Errors & Health\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            errors_found = False
            for port, data in dev.get("interfaces_detail", {}).items():
                in_err = data.get("input_errors", 0)
                out_err = data.get("output_errors", 0)
                if in_err > 0 or out_err > 0:
                    if not errors_found:
                        f.write(f"### {host}\n")
                        errors_found = True
                    f.write(f"- **{port}**: {in_err} input errors, {out_err} output errors.\n")
            if not errors_found:
                f.write(f"### {host}\n- No significant port errors detected.\n")
                
        f.write("\n## Spanning Tree (STP) State\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            stp = dev.get("stp", {})
            f.write(f"### {host}\n")
            if stp.get("enabled"):
                f.write(f"- STP is Enabled.\n")
                if stp.get("is_root"):
                    f.write(f"- **This device is a Root Bridge.**\n")
                vlans = stp.get("vlans", {})
                for inst, ports in vlans.items():
                    f.write(f"- Instance {inst}: {len(ports)} active STP ports.\n")
            else:
                f.write("- STP is Disabled or not configured.\n")
                
        f.write("\n## L4-L7 Services Consistency\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            services = dev.get("services", {})
            f.write(f"### {host}\n")
            f.write(f"- DNS Servers: {', '.join(services.get('dns_servers', [])) or 'None'}\n")
            f.write(f"- NTP Servers: {', '.join(services.get('ntp_servers', [])) or 'None'}\n")
            f.write(f"- RADIUS Servers: {', '.join(services.get('radius_servers', [])) or 'None'}\n")
            f.write(f"- TACACS Servers: {', '.join(services.get('tacacs_servers', [])) or 'None'}\n")

        # --- VLANs & IRB Interfaces ---
        f.write("\n## VLAN & IRB Interface Database\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"### {host}\n")
            vlans = dev.get("vlans", [])
            irbs = {item["interface"]: item for item in dev.get("irb_l3", [])}
            if vlans:
                f.write("| VLAN Name | VLAN ID | Routed Interface | Assigned IP Address / Mode | Description |\n")
                f.write("| --- | --- | --- | --- | --- |\n")
                for v in sorted(vlans, key=lambda x: x.get("vlan_id") or 0):
                    v_name = v.get("name", "")
                    v_id = v.get("vlan_id", "")
                    l3_int = v.get("l3_interface", "")
                    
                    ip_addr = "N/A"
                    desc = ""
                    if l3_int in irbs:
                        ip_addr = irbs[l3_int].get("ip_address") or "Unassigned"
                        desc = irbs[l3_int].get("description") or ""
                        
                    f.write(f"| {v_name} | {v_id} | {l3_int or 'Layer 2 Only'} | {ip_addr} | {desc} |\n")
            else:
                f.write("- No VLANs or IRB interfaces explicitly configured in the database.\n")

        # --- VRFs & Routing Instances ---
        f.write("\n## VRFs & Routing Instances\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"### {host}\n")
            ri = dev.get("routing_instances", [])
            if ri:
                for inst in ri:
                    f.write(f"#### VRF / Instance: `{inst.get('name')}` (Type: `{inst.get('type') or 'N/A'}`)\n")
                    f.write("- **Interfaces bound**: " + (", ".join(inst.get("interfaces", [])) or "None") + "\n")
                    inst_routes = inst.get("routes", [])
                    if inst_routes:
                        f.write("- **Instance Routes**:\n")
                        for r in inst_routes:
                            f.write(f"  - `{r['subnet']}` next-hop `{r['next_hop']}`\n")
            else:
                f.write("- No VRFs or custom routing instances configured (Default routing table only).\n")

        # --- ACLs / Firewall Filters ---
        f.write("\n## ACLs & Firewall Filters\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"### {host}\n")
            filters = dev.get("firewall_filters", [])
            if filters:
                for filt in filters:
                    f.write(f"#### Filter: `{filt['name']}`\n")
                    for term in filt.get("terms", []):
                        f.write(f"- **Term `{term['name']}`**:\n")
                        if term.get("from"):
                            f.write("  - **Match conditions**:\n")
                            for match in term["from"]:
                                f.write(f"    - `{match}`\n")
                        if term.get("then"):
                            f.write("  - **Action**:\n")
                            for action in term["then"]:
                                f.write(f"    - `{action}`\n")
            else:
                f.write("- No Firewall Filters / ACLs configured.\n")

        # --- IP Helpers & DHCP Services ---
        f.write("\n## IP Helpers & DHCP Services\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"### {host}\n")
            dhcp = dev.get("dhcp_services", {})
            relays = dhcp.get("relays", [])
            pools = dhcp.get("local_pools", [])
            
            if relays:
                f.write("#### DHCP Relays (IP Helpers)\n")
                for r in relays:
                    f.write(f"- **Relay Group**: `{r.get('group')}`\n")
                    f.write("  - **Helper IP(s)**: " + ", ".join(r.get("servers", [])) + "\n")
                    f.write("  - **Bound Interface(s)**: " + ", ".join(r.get("interfaces", [])) + "\n")
            if pools:
                f.write("#### Local DHCP Server Pools\n")
                f.write("| Pool Name | Network Subnet | Low IP | High IP | Router IP |\n")
                f.write("| --- | --- | --- | --- | --- |\n")
                for p in pools:
                    f.write(f"| {p.get('pool')} | {p.get('network')} | {p.get('range_low')} | {p.get('range_high')} | {p.get('router')} |\n")
            
            if not relays and not pools:
                f.write("- No DHCP Relays or local DHCP pools configured.\n")

        # --- Static Routes ---
        f.write("\n## Static & Dynamic Routing\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"### {host}\n")
            routes = dev.get("static_routes", [])
            if routes:
                f.write("| Destination Subnet | Next Hop IP / Interface |\n")
                f.write("| --- | --- |\n")
                for r in routes:
                    f.write(f"| {r.get('subnet')} | {r.get('next_hop')} |\n")
            else:
                f.write("- No static routes defined in the base routing table.\n")

        # --- Security & Best Practices Audit ---
        f.write("\n## Security & Best Practices Migration Audit\n")
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"### {host}\n")
            issues = dev.get("audit_issues", [])
            if issues:
                f.write("| Severity | Category | Check/Item | Audit Observation & Recommendation |\n")
                f.write("| --- | --- | --- | --- |\n")
                for issue in issues:
                    sev = issue["severity"]
                    sev_str = f"🔴 {sev}" if sev == "High" else f"🟡 {sev}" if sev == "Medium" else f"ℹ️ {sev}"
                    f.write(f"| {sev_str} | {issue['category']} | {issue['item']} | {issue['detail']} |\n")
            else:
                f.write("- ✅ Configuration aligns with basic audit best practices (no critical risks found).\n")

    print(f"Generated Analysis Report: {filepath}")

def generate_reports(devices, run_dir):
    generate_asset_inventory(devices, run_dir)
    generate_l2_diagram(devices, run_dir)
    generate_l3_diagram(devices, run_dir)
    generate_network_analysis_report(devices, run_dir)
