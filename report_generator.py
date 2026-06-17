import csv
import os
import json
from netaddr import IPNetwork, IPSet

def generate_asset_inventory(devices, output_path="asset_inventory.csv"):
    """
    Generates the authoritative Asset Inventory CSV.
    Fields: Hostname, IP Address, MAC Address, Device Type, Model + Firmware, Serial Number, Role, Mgmt Method
    """
    fields = [
        "Hostname", 
        "IP Address", 
        "MAC Address", 
        "Device Type", 
        "Model", 
        "Firmware", 
        "Serial Number", 
        "Role", 
        "Management Method"
    ]
    
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ip, dev in devices.items():
                # Determine role based on model/hostname/LLDP neighbors
                role = "Access"
                model_lower = dev.get("model", "").lower()
                hostname_lower = dev.get("hostname", "").lower()
                
                if "core" in hostname_lower or "c9500" in model_lower or "4500" in model_lower:
                    role = "Core"
                elif "dist" in hostname_lower or "c3850" in model_lower or "c9300" in model_lower:
                    role = "Distribution"
                elif "edge" in hostname_lower or "asr" in model_lower or "isr" in model_lower:
                    role = "Edge/Router"
                
                # Determine device type
                dev_type = "Switch"
                if "asr" in model_lower or "isr" in model_lower or "router" in hostname_lower:
                    dev_type = "Router"
                elif "ap" in model_lower or "wlc" in model_lower:
                    dev_type = "Wireless AP/Controller"
                
                writer.writerow({
                    "Hostname": dev.get("hostname") or "Unknown",
                    "IP Address": ip,
                    "MAC Address": dev.get("mac_address") or "Unknown",
                    "Device Type": dev_type,
                    "Model": dev.get("model") or "Unknown",
                    "Firmware": dev.get("firmware") or "Unknown",
                    "Serial Number": dev.get("serial") or "Unknown",
                    "Role": role,
                    "Management Method": dev.get("mgmt_method") or "SSH"
                })
        print(f"Asset inventory successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating asset inventory CSV: {e}")

def generate_l2_diagram(devices, output_path="L2_network_diagrams.md"):
    """
    Generates the L2/Physical Network Diagram using Mermaid.js.
    Shows switch stacks, APs, uplinks, fiber paths, and STP states.
    """
    lines = [
        "# Layer 2 & Physical Network Diagrams",
        "",
        "This file contains physical topologies, switch-to-switch uplinks, and wireless AP connections discovered via CDP/LLDP and local port statuses.",
        "",
        "## Physical Connectivity Diagram",
        "```mermaid",
        "graph TD",
        "  %% Style configurations",
        "  classDef core fill:#3399ff,stroke:#0066cc,stroke-width:2px,color:#fff;",
        "  classDef dist fill:#85c1e9,stroke:#2e86c1,stroke-width:2px;",
        "  classDef access fill:#d5dbdb,stroke:#7f8c8d,stroke-width:1px;",
        "  classDef ap fill:#f9e79f,stroke:#f1c40f,stroke-width:1px;",
        "  classDef root fill:#2ecc71,stroke:#27ae60,stroke-width:3px,color:#fff;",
        ""
    ]
    
    # Track link duplicates: we only want to draw links once (e.g. A->B and B->A is one link)
    seen_links = set()
    link_idx = 0
    link_styles = []
    
    # 1. Define nodes and their styles
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        model = dev.get("model") or "Unknown"
        is_root = dev.get("stp", {}).get("is_root", False)
        
        # Node label with Model
        label = f"{hostname}[\"{hostname}<br/>({model})\"]"
        lines.append(f"  {hostname}{label}")
        
        # Apply classes
        model_lower = model.lower()
        hn_lower = hostname.lower()
        if is_root:
            lines.append(f"  class {hostname} root;")
        elif "core" in hn_lower or "c9500" in model_lower:
            lines.append(f"  class {hostname} core;")
        elif "dist" in hn_lower or "c3850" in model_lower or "c9300" in model_lower:
            lines.append(f"  class {hostname} dist;")
        else:
            lines.append(f"  class {hostname} access;")
            
    lines.append("")
    lines.append("  %% Topology links")
    
    # 2. Draw connections from neighbors
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        neighbors = dev.get("neighbors", [])
        
        for n in neighbors:
            remote_host = n.get("remote_device")
            if not remote_host:
                continue
                
            # Clean remote hostname
            remote_host = remote_host.split('.')[0]
            
            # Find matching remote node in scanned devices if possible to use IP/Hostname
            matched_remote = None
            for rip, rdev in devices.items():
                rhn = rdev.get("hostname", "")
                if rhn and rhn.split('.')[0].lower() == remote_host.lower():
                    matched_remote = rhn
                    break
            
            # If not in scanned devices, we still add it
            node_b = matched_remote or remote_host
            
            # Sort node names to prevent duplicates
            link_key = tuple(sorted([hostname, node_b]))
            if link_key in seen_links:
                continue
            seen_links.add(link_key)
            
            local_port = n.get("local_port", "")
            remote_port = n.get("remote_port", "")
            
            # Determine link characteristics (e.g., STP blocking)
            is_blocked = False
            stp_vlans = dev.get("stp", {}).get("vlans", {})
            for vlan_id, ports in stp_vlans.items():
                if local_port in ports and ports[local_port].get("state") == "BLK":
                    is_blocked = True
                    break
            
            # Label link with ports
            link_label = f"|{local_port} -- {remote_port}|"
            
            if is_blocked:
                # Dotted red line for blocked paths
                lines.append(f"  {hostname} -.-> {node_b}")
                # Add link styling index
                link_styles.append(f"  linkStyle {link_idx} stroke:#ff3333,stroke-width:2px,stroke-dasharray: 5 5;")
            else:
                lines.append(f"  {hostname} === {node_b}")
                
            link_idx += 1

    # 3. Add link styles for blocked links
    if link_styles:
        lines.append("")
        lines.append("  %% Link Styles (STP Blocked paths in dotted red)")
        lines.extend(link_styles)
        
    lines.extend([
        "```",
        "",
        "### Legend",
        "* **Green Highlighted Node**: STP Root Bridge.",
        "* **Blue Node**: Core / Distribution switches.",
        "* **Grey Node**: Access switches.",
        "* **Dashed Red Lines**: STP Blocking (`BLK`) links.",
        "* **Double Solid Lines**: Active forwarding links.",
        "",
        "## Wireless Overlay Layout",
        "Discovered Wireless Access Points connected to switches:"
    ])
    
    # Extract AP neighbors
    ap_count = 0
    ap_table = ["| Switch Hostname | Local Port | AP Hostname/MAC | AP IP | AP Model |", "| --- | --- | --- | --- | --- |"]
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        for n in dev.get("neighbors", []):
            platform = n.get("platform", "").lower()
            if "ap" in platform or "air-" in platform or "access point" in platform:
                ap_count += 1
                ap_table.append(f"| {hostname} | {n.get('local_port')} | {n.get('remote_device')} | {n.get('remote_ip') or 'N/A'} | {n.get('platform')} |")
                
    if ap_count > 0:
        lines.append(f"\nTotal Discovered Access Points: **{ap_count}**\n")
        lines.extend(ap_table)
    else:
        lines.append("\nNo wireless access points were directly discovered via LLDP/CDP neighbor tables.")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"L2 Diagrams successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating L2 diagram file: {e}")

def generate_l3_diagram(devices, output_path="L3_network_diagrams.md"):
    """
    Generates L3 logical and routing topologies using Mermaid.js.
    Lists subnets, SVIs, VLANs, and VRFs.
    """
    lines = [
        "# Layer 3 & Logical Network Diagrams",
        "",
        "This file documents Layer 3 boundaries, Switch Virtual Interfaces (SVIs), VLAN maps, and routing domains/VRFs.",
        "",
        "## Logical Routing Boundary Diagram",
        "```mermaid",
        "graph LR",
        "  classDef subnet fill:#eafaf1,stroke:#2ecc71,stroke-width:1px;",
        "  classDef router fill:#ebf5fb,stroke:#2980b9,stroke-width:2px;",
        ""
    ]
    
    subnets_seen = set()
    switch_svis = [] # list of (switch, interface, ip, subnet)
    
    # Collect all L3 SVIs and routing interfaces
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        interfaces = dev.get("l3_interfaces", [])
        
        for intf in interfaces:
            intf_ip = intf.get("ip_address")
            if not intf_ip or intf_ip in ["unassigned", "down", "up", "unset"]:
                continue
            
            # Simple assumption of subnet for SVI / routing interface
            # Since SVI might not show mask in 'brief' output, we look for running config or guess
            # For mapping, we represent the SVI as linking the switch to a subnet node
            # We will generate a subnet label.
            # E.g., we look up IP masks from running configuration or guess a /24 if unknown
            # To keep it clean, we create a subnet node "Subnet_IP_X"
            clean_ip_base = ".".join(intf_ip.split('.')[:3]) + ".0/24"
            subnet_id = "subnet_" + clean_ip_base.replace('.', '_').replace('/', '_')
            
            if subnet_id not in subnets_seen:
                subnets_seen.add(subnet_id)
                lines.append(f"  {subnet_id}[\"Subnet: {clean_ip_base}\"]")
                lines.append(f"  class {subnet_id} subnet;")
                
            lines.append(f"  {hostname} --- {subnet_id}")
            switch_svis.append({
                "switch": hostname,
                "interface": intf.get("interface"),
                "ip": intf_ip,
                "subnet": clean_ip_base
            })
            
    # Include router devices node class styling
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        lines.append(f"  class {hostname} router;")
        
    lines.extend([
        "```",
        "",
        "## Authoritative VLAN, Subnet & SVI Map",
        "",
        "| Switch Hostname | Interface / VLAN | SVI IP Address | Subnet Range | Interface Status |",
        "| --- | --- | --- | --- | --- |"
    ])
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", [])
        for intf in l3_ints:
            lines.append(f"| {hostname} | {intf.get('interface')} | {intf.get('ip_address')} | {'.'.join(intf.get('ip_address').split('.')[:3]) + '.0/24' if '.' in intf.get('ip_address') else 'N/A'} | {intf.get('status')} |")
            
    lines.extend([
        "",
        "## VRF Routing Instances & Boundaries",
        "Discovered VRF routing instances and their associated interfaces:"
    ])
    
    # Search running config for VRFs
    vrf_found = False
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        # Look for "vrf definition X" or "ip vrf X"
        vrfs = list(set(re.findall(r'(?:ip vrf|vrf definition)\s+(\S+)', cfg)))
        if vrfs:
            vrf_found = True
            lines.append(f"\n### {hostname} VRF Instances:")
            for vrf in vrfs:
                lines.append(f"* **VRF Name:** `{vrf}`")
                
    if not vrf_found:
        lines.append("\nNo virtual routing and forwarding (VRF) instances were detected in active device configurations (standard global table only).")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"L3 Diagrams successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating L3 diagram file: {e}")

def generate_network_analysis_report(devices, output_path="network_analysis_report.md"):
    """
    Generates a structured Layer 1-7 network analysis report.
    Details cabling errors, speed mismatches, STP loop risks, subnets, and L4-L7 services.
    """
    lines = [
        "# Layered Network Analysis Report (OSI-Oriented)",
        "",
        "This report evaluates network behavior, health indicators, configuration consistency, and security gaps parsed from active switch running-states.",
        "",
        "## 1. Layer 1/2 (Physical & Data Link) Analysis",
        ""
    ]
    
    # A. Cabling & Speed Mismatches
    lines.append("### Cabling Issues & Speed/Duplex Mismatches")
    mismatches = []
    errors_found = []
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        ints_detail = dev.get("interfaces_detail", {})
        
        for name, stats in ints_detail.items():
            desc = stats.get("description", "")
            speed = stats.get("speed", "")
            duplex = stats.get("duplex", "")
            in_err = stats.get("input_errors", 0)
            crc = stats.get("crc", 0)
            out_err = stats.get("output_errors", 0)
            
            # Check half duplex (often a mismatch indicator on switchports)
            if duplex and "half" in duplex.lower():
                mismatches.append(f"* **{hostname}** Interface `{name}` (`{desc}`): Operating at **{duplex}** / **{speed}** (Potential mismatch).")
                
            # Speed constraints
            if speed and "10Mb/s" in speed:
                mismatches.append(f"* **{hostname}** Interface `{name}` (`{desc}`): Speed restricted to **10 Mbps**.")
                
            # Errors
            if in_err > 0 or crc > 0 or out_err > 0:
                errors_found.append(f"* **{hostname}** Interface `{name}`: Input Errors: `{in_err}`, CRCs: `{crc}`, Output Errors: `{out_err}`.")
                
    if mismatches:
        lines.extend(mismatches)
    else:
        lines.append("  * No active speed/duplex mismatches or half-duplex anomalies detected.")
        
    lines.append("\n### Interface Packet & CRC Errors")
    if errors_found:
        lines.extend(errors_found)
    else:
        lines.append("  * No packet errors or CRC checksum failures detected on active interfaces (clean physical paths).")
        
    # B. Port Utilization
    lines.append("\n### Interface Port Utilization Summary")
    lines.append("| Switch Hostname | Connected Ports | Total Ports | Utilization % |")
    lines.append("| --- | --- | --- | --- |")
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        ints_detail = dev.get("interfaces_detail", {})
        total = len(ints_detail)
        connected = 0
        for name, stats in ints_detail.items():
            if stats.get("status") == "up":
                connected += 1
                
        pct = (connected / total * 100) if total > 0 else 0
        lines.append(f"| {hostname} | {connected} | {total} | {pct:.1f}% |")
        
    # C. Spanning Tree State
    lines.append("\n### Loop Risks & Spanning Tree (STP) Audit")
    stp_issues = []
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        stp = dev.get("stp", {})
        
        if not stp.get("enabled"):
            stp_issues.append(f"* **{hostname}**: **Spanning Tree is DISABLED** (Extreme loop risk if redundant links exist).")
            continue
            
        # Count blocked interfaces
        blocked_ports = []
        for vlan_id, ports in stp.get("vlans", {}).items():
            for port_name, state_dict in ports.items():
                if state_dict.get("state") == "BLK":
                    blocked_ports.append(f"`{port_name}` (VLAN {vlan_id})")
                    
        if blocked_ports:
            lines.append(f"* **{hostname}**: Currently blocking loops on {len(set(blocked_ports))} ports: {', '.join(list(set(blocked_ports)))}")
            
    if stp_issues:
        lines.extend(stp_issues)
        
    # 2. Layer 3 (Routing) Analysis
    lines.extend([
        "",
        "## 2. Layer 3 (Routing) Analysis",
        ""
    ])
    
    # Subnet overlaps
    lines.append("### Overlapping Subnets & IP Space Conflicts")
    ip_subnets = []
    overlap_found = False
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", [])
        for intf in l3_ints:
            intf_ip = intf.get("ip_address")
            if intf_ip and intf_ip not in ["unassigned", "down", "up", "unset"]:
                try:
                    # Parse subnet (guess /24 if not specified)
                    net = IPNetwork(f"{intf_ip}/24")
                    ip_subnets.append((hostname, intf.get("interface"), net))
                except Exception:
                    pass
                    
    # Compare each subnet for overlaps
    for i in range(len(ip_subnets)):
        for j in range(i+1, len(ip_subnets)):
            h1, int1, net1 = ip_subnets[i]
            h2, int2, net2 = ip_subnets[j]
            # If subnets are identical but on different devices or interfaces
            if net1.network == net2.network and h1 != h2:
                lines.append(f"* **Overlap Warning:** Same network range `{net1.network}/{net1.prefixlen}` configured on **{h1}** (`{int1}`) and **{h2}** (`{int2}`).")
                overlap_found = True
                
    if not overlap_found:
        lines.append("  * No overlapping subnets or IP address space collisions detected.")
        
    # Routing protocols
    lines.append("\n### Active Routing Protocols")
    routes_summary = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        protocols = list(set([r.get("protocol") for r in routes if r.get("protocol")]))
        if protocols:
            routes_summary[hostname] = protocols
            
    if routes_summary:
        for host, protos in routes_summary.items():
            lines.append(f"* **{host}**: Running routing protocols: {', '.join(protos)}")
    else:
        lines.append("  * Devices are operating entirely on Static routing or directly connected Layer 3 boundaries.")
        
    # 3. Layer 4-7 Services Analysis
    lines.extend([
        "",
        "## 3. Layer 4-7 (Services & Security) Analysis",
        ""
    ])
    
    lines.append("### Infrastructure Services Consistency (NTP, DNS, AAA)")
    lines.append("| Switch Hostname | DNS Servers | NTP Servers | RADIUS/TACACS Servers | Management Protocol |")
    lines.append("| --- | --- | --- | --- | --- |")
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})
        dns = ", ".join(services.get("dns_servers", [])) or "None"
        ntp = ", ".join(services.get("ntp_servers", [])) or "None"
        aaa = []
        if services.get("radius_servers"):
            aaa.append(f"RADIUS({len(services['radius_servers'])})")
        if services.get("tacacs_servers"):
            aaa.append(f"TACACS({len(services['tacacs_servers'])})")
        aaa_str = ", ".join(aaa) or "None"
        mgmt = dev.get("mgmt_method", "SSH")
        
        lines.append(f"| {hostname} | {dns} | {ntp} | {aaa_str} | {mgmt} |")
        
    # Security/Visibility Gaps
    lines.append("\n### Visibility & Security Gaps")
    gaps = []
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        mgmt = dev.get("mgmt_method", "SSH")
        services = dev.get("services", {})
        
        if mgmt == "Telnet":
            gaps.append(f"* **{hostname}** is using unencrypted **Telnet** for management interface (Security risk).")
        if not services.get("ntp_servers"):
            gaps.append(f"* **{hostname}** has **no NTP servers** configured (Log timestamps may be out of sync).")
        if not services.get("dns_servers"):
            gaps.append(f"* **{hostname}** has **no DNS name-servers** configured (Unable to resolve hostnames).")
        if not services.get("radius_servers") and not services.get("tacacs_servers"):
            gaps.append(f"* **{hostname}** does not use central AAA authentication (Using local fallback users).")
            
    if gaps:
        lines.extend(gaps)
    else:
        lines.append("  * No primary visibility or security gaps found. Central AAA, NTP synchronization, and secure SSH management are properly configured.")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Network analysis report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating network analysis report: {e}")
