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
        f.write("mindmap\n")
        f.write("    root((Network L2 Neighbors))\n")
        
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            host_id = sanitize_node_id(host)
            f.write(f'        {host_id}["{host}\\n{dev.get("model", "Unknown")}"]\n')
            
            for n in dev.get("neighbors", []):
                remote = n.get("remote_device", "Unknown")
                lport = n.get("local_port", "")
                rport = n.get("remote_port", "")
                neighbor_node_id = sanitize_node_id(f"{host}_{remote}")
                f.write(f'            {neighbor_node_id}["{remote}\\n({lport} to {rport})"]\n')
                
        f.write("```\n")
    print(f"Generated L2 Diagram: {filepath}")

def generate_l3_diagram(devices, run_dir):
    filepath = os.path.join(run_dir, "L3_network_diagrams.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Juniper L3 Network Diagram\n\n")
        f.write("```mermaid\n")
        f.write("mindmap\n")
        f.write("    root((Network L3 Interfaces))\n")
        
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            host_id = sanitize_node_id(host)
            f.write(f'        {host_id}["{host} - {ip}"]\n')
            
            for l3 in dev.get("l3_interfaces", []):
                subnet = l3.get("ip_address", "")
                if subnet and subnet != "unassigned":
                    subnet_id = sanitize_node_id(subnet)
                    f.write(f'            {subnet_id}["{subnet}"]\n')
                    
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

def generate_config_variables(devices, run_dir):
    variables = {}
    for ip, dev in devices.items():
        if dev.get("status") != "success":
            continue
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})
        
        vlans_list = []
        for v in dev.get("vlans", []):
            vlans_list.append({"id": v.get("vlan_id"), "name": v.get("name")})
            
        svis_list = []
        for irb in dev.get("irb_l3", []):
            svis_list.append({
                "interface": irb.get("interface"),
                "ip_address": irb.get("ip_address"),
                "description": irb.get("description", "")
            })
            
        variables[hostname] = {
            "management_ip": ip,
            "model": dev.get("model", "Unknown"),
            "model_series": dev.get("model_series", "EX"),
            "firmware": dev.get("firmware", "Unknown"),
            "serial": dev.get("serial", "Unknown"),
            "dns_servers": services.get("dns_servers", []),
            "ntp_servers": services.get("ntp_servers", []),
            "radius_servers": services.get("radius_servers", []),
            "tacacs_servers": services.get("tacacs_servers", []),
            "vlans": vlans_list,
            "l3_interfaces": svis_list
        }
    filepath = os.path.join(run_dir, "migration_config_variables.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(variables, f, indent=4)
    print(f"Generated Config Variables JSON: {filepath}")

def generate_cabling_matrix(devices, run_dir):
    filepath = os.path.join(run_dir, "migration_cabling_matrix.csv")
    fields = [
        "Source Hostname", "Source Port", "Description", "Status", "Speed", 
        "Neighbor Hostname", "Neighbor Port", "Target Hostname (Placeholder)", "Target Port (Placeholder)"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            hostname = dev.get("hostname") or ip
            ints_detail = dev.get("interfaces_detail", {})
            neighbors = dev.get("neighbors", [])
            
            # Map neighbors by normalized port name
            neighbor_map = {}
            for n in neighbors:
                lp = n.get("local_port", "")
                if lp:
                    neighbor_map[lp] = n
                    
            for name, stats in ints_detail.items():
                if name.startswith("irb") or name.startswith("vlan") or name.startswith("lo"):
                    continue
                neighbor = neighbor_map.get(name)
                writer.writerow({
                    "Source Hostname": hostname,
                    "Source Port": name,
                    "Description": stats.get("description", ""),
                    "Status": stats.get("status", "down"),
                    "Speed": stats.get("speed", ""),
                    "Neighbor Hostname": neighbor.get("remote_device", "") if neighbor else "",
                    "Neighbor Port": neighbor.get("remote_port", "") if neighbor else "",
                    "Target Hostname (Placeholder)": "",
                    "Target Port (Placeholder)": ""
                })
    print(f"Generated Cabling Matrix: {filepath}")

def generate_protocol_translation(devices, run_dir):
    filepath = os.path.join(run_dir, "juniper_to_target_translation.md")
    lines = [
        "# Juniper Non-ELS to ELS Protocol & CLI Translation Matrix",
        "",
        "This matrix details command and syntax differences between older Junos switches (Non-ELS) and newer switches (ELS - Enhanced Layer 2 Software).",
        ""
    ]
    for ip, dev in devices.items():
        if dev.get("status") != "success":
            continue
        hostname = dev.get("hostname") or ip
        is_els = dev.get("is_els", False)
        lines.append(f"## Device: {hostname} ({ip})")
        lines.append(f"**Detected Architecture**: {'ELS (Modern)' if is_els else 'Non-ELS (Legacy)'}")
        lines.append("")
        lines.append("| Feature | Legacy Non-ELS Command | Modern ELS Target Command | Recommendation |")
        lines.append("| --- | --- | --- | --- |")
        lines.append("| **VLAN L3 Interface** | `set interfaces vlan unit X family inet address Y` | `set interfaces irb unit X family inet address Y` | Convert vlan-interface bindings to routing interface (irb). |")
        lines.append("| **VLAN Definition** | `set vlans name vlan-id ID l3-interface vlan.X` | `set vlans name vlan-id ID l3-interface irb.X` | Map legacy vlan logical interface bindings to irb unit logical interfaces. |")
        lines.append("| **Access Port** | `set interfaces port unit 0 family ethernet-switching port-mode access vlan members VLAN` | `set interfaces port unit 0 family ethernet-switching interface-mode access vlan members VLAN` | Change port-mode to interface-mode. |")
        lines.append("| **Trunk Port** | `set interfaces port unit 0 family ethernet-switching port-mode trunk vlan members [VLANs]` | `set interfaces port unit 0 family ethernet-switching interface-mode trunk vlan members [VLANs]` | Change port-mode to interface-mode. |")
        lines.append("")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Generated Protocol Translation Matrix: {filepath}")

def generate_best_practices_report(devices, run_dir):
    filepath = os.path.join(run_dir, "juniper_best_practices.md")
    lines = [
        "# Juniper Best Practices & Security Audit Report",
        "",
        "This report audits configuration options on Junos devices to ensure secure management and deployment compliance.",
        ""
    ]
    for ip, dev in devices.items():
        if dev.get("status") != "success":
            continue
        hostname = dev.get("hostname") or ip
        issues = dev.get("audit_issues", [])
        
        lines.append(f"## Device: {hostname} ({ip})")
        lines.append("| Severity | Category | Check | Recommendation |")
        lines.append("| --- | --- | --- | --- |")
        for iss in issues:
            lines.append(f"| {iss['severity']} | {iss['category']} | {iss['item']} | {iss['detail']} |")
        if not issues:
            lines.append("| ✅ Pass | General | Configuration matches baseline best practices | No fixes recommended |")
        lines.append("")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Generated Best Practices Report: {filepath}")

def save_baseline_state(devices, output_path):
    baseline = {}
    for ip, dev in devices.items():
        if dev.get("status") != "success":
            continue
        hostname = dev.get("hostname") or ip
        
        up_ints = []
        for name, stats in dev.get("interfaces_detail", {}).items():
            if stats.get("status") == "up":
                up_ints.append(name)
                
        neighbors = []
        for n in dev.get("neighbors", []):
            neighbors.append({
                "local_port": n.get("local_port", ""),
                "remote_device": n.get("remote_device", ""),
                "remote_port": n.get("remote_port", "")
            })
            
        routes = [r.get("prefix") for r in dev.get("routes", []) if r.get("prefix")]
        
        svis = {}
        for l3 in dev.get("l3_interfaces", []):
            svis[l3.get("interface")] = {
                "ip": l3.get("ip_address"),
                "status": l3.get("status")
            }
            
        ospf = []
        for n in dev.get("ospf_neighbors", []):
            ospf.append({
                "neighbor_id": n.get("neighbor_id"),
                "interface": n.get("interface"),
                "state": n.get("state")
            })
            
        bgp = []
        for p in dev.get("bgp_peers", []):
            bgp.append({
                "peer": p.get("peer"),
                "state": p.get("state")
            })
            
        zones = [z.get("name") for z in dev.get("security_zones", [])]
        policies = []
        for pol in dev.get("security_policies", []):
            policies.append({
                "name": pol.get("name"),
                "from_zone": pol.get("from_zone"),
                "to_zone": pol.get("to_zone"),
                "action": pol.get("action")
            })
            
        baseline[hostname] = {
            "management_ip": ip,
            "up_interfaces": up_ints,
            "neighbors": neighbors,
            "routes": routes,
            "svis": svis,
            "ospf": ospf,
            "bgp": bgp,
            "zones": zones,
            "policies": policies
        }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=4)
    print(f"Saved baseline state to {output_path}")

def compare_baseline_state(devices, baseline_path, run_dir):
    if not os.path.exists(baseline_path):
        print(f"Baseline file {baseline_path} does not exist.")
        return
    with open(baseline_path, "r", encoding="utf-8") as f:
        baseline = json.load(f)
        
    filepath = os.path.join(run_dir, "migration_verification_report.md")
    lines = [
        "# Post-Migration Verification & Validation Report",
        "",
        f"This report compares the current Junos network state against the baseline file: `{os.path.basename(baseline_path)}`.",
        ""
    ]
    
    total_failures = 0
    for host_base, base_state in baseline.items():
        current_dev = None
        base_ip = base_state.get("management_ip")
        for ip, dev in devices.items():
            if ip == base_ip or (dev.get("hostname") and dev.get("hostname").lower() == host_base.lower()):
                current_dev = dev
                break
                
        lines.append(f"## Device: {host_base}")
        if not current_dev:
            lines.append("❌ **CRITICAL: Device is UNREACHABLE or missing in current scan!**\n")
            total_failures += 1
            continue
            
        dev_failures = 0
        
        # 1. Compare Interfaces
        base_up = base_state.get("up_interfaces", [])
        curr_ints = current_dev.get("interfaces_detail", {})
        curr_up = [name for name, stats in curr_ints.items() if stats.get("status") == "up"]
        missing_up = [n for n in base_up if n not in curr_up]
        if missing_up:
            lines.append(f"❌ **Interface Status Mismatch**: {len(missing_up)} interfaces that were UP are now DOWN or missing: " + ", ".join(missing_up))
            dev_failures += 1
        else:
            lines.append("✓ **Interface Status**: All baseline UP interfaces are currently UP.")
            
        # 2. Compare SVI / IRB
        base_svis = base_state.get("svis", {})
        curr_svis = {x.get("interface"): x for x in current_dev.get("l3_interfaces", [])}
        svi_err = []
        for name, bs in base_svis.items():
            cs = curr_svis.get(name)
            if not cs:
                svi_err.append(f"Interface {name} missing")
            elif cs.get("ip_address") != bs.get("ip"):
                svi_err.append(f"Interface {name} IP mismatch: current {cs.get('ip_address')} (Expected {bs.get('ip')})")
        if svi_err:
            lines.append("❌ **L3 Interface Mismatches**:\n" + "\n".join([f"  * {x}" for x in svi_err]))
            dev_failures += 1
        else:
            lines.append("✓ **L3 Interfaces**: All baseline L3 interfaces and IPs match.")
            
        # 3. Compare Neighbors
        base_neigh = base_state.get("neighbors", [])
        curr_neigh = current_dev.get("neighbors", [])
        missing_neigh = []
        for bn in base_neigh:
            match = False
            for cn in curr_neigh:
                if cn.get("remote_device") == bn.get("remote_device") and cn.get("local_port") == bn.get("local_port"):
                    match = True
                    break
            if not match:
                missing_neigh.append(f"Port {bn.get('local_port')} lost neighbor {bn.get('remote_device')}")
        if missing_neigh:
            lines.append("❌ **Neighbor Adjacencies Lost**:\n" + "\n".join([f"  * {x}" for x in missing_neigh]))
            dev_failures += 1
        else:
            lines.append("✓ **Neighbor Adjacencies**: All LLDP/CDP neighbors match baseline.")

        # 4. Routing Protocols (OSPF/BGP)
        base_ospf = base_state.get("ospf", [])
        curr_ospf = current_dev.get("ospf_neighbors", [])
        missing_ospf = []
        for bo in base_ospf:
            match = False
            for co in curr_ospf:
                if co.get("neighbor_id") == bo.get("neighbor_id") and co.get("state").lower() == bo.get("state").lower():
                    match = True
                    break
            if not match:
                missing_ospf.append(f"OSPF Neighbor {bo.get('neighbor_id')} on {bo.get('interface')} not in state {bo.get('state')}")
        if missing_ospf:
            lines.append("❌ **OSPF Adjacencies Mismatch**:\n" + "\n".join([f"  * {x}" for x in missing_ospf]))
            dev_failures += 1
        elif base_ospf:
            lines.append("✓ **OSPF Routing**: All OSPF sessions match baseline state.")

        base_bgp = base_state.get("bgp", [])
        curr_bgp = current_dev.get("bgp_peers", [])
        missing_bgp = []
        for bb in base_bgp:
            match = False
            for cb in curr_bgp:
                if cb.get("peer") == bb.get("peer") and cb.get("state").lower() == bb.get("state").lower():
                    match = True
                    break
            if not match:
                missing_bgp.append(f"BGP Peer {bb.get('peer')} not in state {bb.get('state')}")
        if missing_bgp:
            lines.append("❌ **BGP Peers Mismatch**:\n" + "\n".join([f"  * {x}" for x in missing_bgp]))
            dev_failures += 1
        elif base_bgp:
            lines.append("✓ **BGP Routing**: All BGP peers match baseline state.")
            
        # 5. SRX Security Zones & Policies
        base_zones = base_state.get("zones", [])
        curr_zones = [z.get("name") for z in current_dev.get("security_zones", [])]
        missing_zones = [z for z in base_zones if z not in curr_zones]
        if missing_zones:
            lines.append("❌ **Security Zones Missing**: " + ", ".join(missing_zones))
            dev_failures += 1
            
        base_pol = base_state.get("policies", [])
        curr_pol = current_dev.get("security_policies", [])
        missing_pols = []
        for bp in base_pol:
            match = False
            for cp in curr_pol:
                if cp.get("name") == bp.get("name") and cp.get("from_zone") == bp.get("from_zone") and cp.get("to_zone") == bp.get("to_zone"):
                    match = True
                    break
            if not match:
                missing_pols.append(f"Policy '{bp.get('name')}' ({bp.get('from_zone')} -> {bp.get('to_zone')}) missing or modified")
        if missing_pols:
            lines.append("❌ **Security Policies Missing/Modified**:\n" + "\n".join([f"  * {x}" for x in missing_pols]))
            dev_failures += 1
        elif base_pol:
            lines.append("✓ **Security Policies**: All base security policies match.")
            
        if dev_failures > 0:
            lines.append(f"\n⚠️ **Verification Summary**: {dev_failures} state verification checks failed for switch **{host_base}**.\n")
            total_failures += 1
        else:
            lines.append(f"\n✓ **Verification Summary**: Switch **{host_base}** passed all state verification checks.\n")
            
    lines.append("---")
    if total_failures > 0:
        lines.append(f"# ❌ Verification Verdict: FAILED ({total_failures} devices failed validation checks)")
    else:
        lines.append("# ✓ Verification Verdict: PASSED (All devices match their baseline states)")
        
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Generated Post-Migration Verification Report: {filepath}")

def generate_reports(devices, run_dir):
    generate_asset_inventory(devices, run_dir)
    generate_l2_diagram(devices, run_dir)
    generate_l3_diagram(devices, run_dir)
    generate_network_analysis_report(devices, run_dir)
    generate_config_variables(devices, run_dir)
    generate_cabling_matrix(devices, run_dir)
    generate_protocol_translation(devices, run_dir)
    generate_best_practices_report(devices, run_dir)
