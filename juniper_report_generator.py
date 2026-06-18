import os
import csv
import json

def generate_asset_inventory(devices, run_dir):
    filepath = os.path.join(run_dir, "asset_inventory.csv")
    with open(filepath, "w", newline="") as f:
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
    with open(filepath, "w") as f:
        f.write("# Juniper L2 Network Diagram\n\n")
        f.write("```mermaid\n")
        f.write("graph TD;\n")
        
        edges = set()
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"    {host}[{host}\\n{dev.get('model', 'Unknown')}]\n")
            
            for n in dev.get("neighbors", []):
                remote = n.get("remote_device", "Unknown")
                lport = n.get("local_port", "")
                rport = n.get("remote_port", "")
                edge = f"    {host} -- {lport} to {rport} --> {remote};\n"
                edges.add(edge)
                
        for edge in edges:
            f.write(edge)
        f.write("```\n")
    print(f"Generated L2 Diagram: {filepath}")

def generate_l3_diagram(devices, run_dir):
    filepath = os.path.join(run_dir, "L3_network_diagrams.md")
    with open(filepath, "w") as f:
        f.write("# Juniper L3 Network Diagram\n\n")
        f.write("```mermaid\n")
        f.write("graph TD;\n")
        
        for ip, dev in devices.items():
            if dev.get("status") != "success":
                continue
            host = dev.get("hostname", ip)
            f.write(f"    {host}[{host} - {ip}]\n")
            
            for l3 in dev.get("l3_interfaces", []):
                subnet = l3.get("ip_address", "")
                if subnet and subnet != "unassigned":
                    f.write(f"    {host} --- {subnet}({subnet})\n")
                    
        f.write("```\n")
    print(f"Generated L3 Diagram: {filepath}")

def generate_network_analysis_report(devices, run_dir):
    filepath = os.path.join(run_dir, "network_analysis_report.md")
    with open(filepath, "w") as f:
        f.write("# Juniper Network Analysis Report\n\n")
        
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

    print(f"Generated Analysis Report: {filepath}")

def generate_reports(devices, run_dir):
    generate_asset_inventory(devices, run_dir)
    generate_l2_diagram(devices, run_dir)
    generate_l3_diagram(devices, run_dir)
    generate_network_analysis_report(devices, run_dir)
