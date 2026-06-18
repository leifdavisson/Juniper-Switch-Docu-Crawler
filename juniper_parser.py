import re

def parse_juniper_show_version(output):
    data = {
        "hostname": "",
        "firmware": "",
        "model": "",
        "serial": ""
    }
    
    hn_match = re.search(r'^Hostname:\s*(\S+)', output, re.MULTILINE)
    if hn_match:
        data["hostname"] = hn_match.group(1)
        
    fw_match = re.search(r'Junos:?\s+([A-Za-z0-9.-]+)', output, re.IGNORECASE)
    if not fw_match:
        fw_match = re.search(r'JUNOS.*?\s+\[([A-Za-z0-9.-]+)\]', output, re.IGNORECASE)
    if fw_match:
        data["firmware"] = fw_match.group(1)
        
    model_match = re.search(r'^Model:\s*(\S+)', output, re.MULTILINE)
    if model_match:
        data["model"] = model_match.group(1)
        
    return data

def parse_juniper_chassis_hardware(output):
    data = {"model": "", "serial": ""}
    
    lines = output.splitlines()
    for line in lines:
        # Looking for Chassis or Routing Engine for serial
        if line.startswith('Chassis'):
            parts = line.split()
            # typically: Chassis       SERIALNUMBER      Model
            if len(parts) >= 3:
                data["serial"] = parts[1]
                data["model"] = " ".join(parts[2:])
            break
            
    return data

def parse_juniper_interfaces_terse(output):
    interfaces = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('Interface'):
            continue
            
        parts = line.split()
        if len(parts) >= 4:
            interface = parts[0]
            admin = parts[1]
            link = parts[2]
            proto = parts[3]
            ip_addr = parts[4] if len(parts) > 4 else ""
            
            # Juniper uses 'inet' for IPv4, 'inet6' for IPv6. We mainly care about l3 configs.
            if proto in ('inet', 'inet6') and ip_addr:
                interfaces.append({
                    "interface": interface,
                    "ip_address": ip_addr,
                    "status": link.lower(),
                    "protocol": "Connected"
                })
    return interfaces

def parse_juniper_show_interfaces(output):
    interfaces = {}
    current_int = None
    lines = output.splitlines()
    for line in lines:
        # e.g., "Physical interface: ge-0/0/0, Enabled, Physical link is Up"
        phys_match = re.match(r'^Physical interface:\s*(\S+),\s*(Enabled|Administratively down),\s*Physical link is\s*(Up|Down)', line)
        if phys_match:
            current_int = phys_match.group(1)
            interfaces[current_int] = {
                "status": phys_match.group(3).lower(),
                "mac_address": "",
                "speed": "",
                "duplex": "",
                "input_errors": 0,
                "crc": 0,
                "output_errors": 0,
                "description": ""
            }
            continue
            
        if not current_int:
            continue
            
        desc_match = re.search(r'Description:\s*(.+)$', line)
        if desc_match:
            interfaces[current_int]["description"] = desc_match.group(1).strip()
            
        mac_match = re.search(r'Current address:\s*([0-9a-fA-F:]+)', line)
        if mac_match:
            interfaces[current_int]["mac_address"] = mac_match.group(1).replace(':', '')
            
        speed_match = re.search(r'Speed:\s*(\S+)', line)
        if speed_match:
            interfaces[current_int]["speed"] = speed_match.group(1)
            
        duplex_match = re.search(r'Duplex:\s*(\S+)', line)
        if duplex_match:
            interfaces[current_int]["duplex"] = duplex_match.group(1)
            
        err_match = re.search(r'Input errors:\s*(\d+),\s*Output errors:\s*(\d+)', line)
        if err_match:
            interfaces[current_int]["input_errors"] = int(err_match.group(1))
            interfaces[current_int]["output_errors"] = int(err_match.group(2))
            
        # Optional CRC depending on Junos version
        crc_match = re.search(r'Framing errors:\s*\d+,\s*Runts:\s*\d+,\s*Policed discards:\s*\d+,\s*L3 incompletes:\s*\d+,\s*L2 channel errors:\s*\d+,\s*L2 mismatch timeouts:\s*\d+,\s*FIFO errors:\s*\d+,\s*Resource errors:\s*\d+', line)
        
    return interfaces

def parse_juniper_lldp_neighbors_detail(output):
    neighbors = []
    current = {}
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("Local Interface:"):
            if current and "local_port" in current:
                neighbors.append(current)
            current = {
                "local_port": line.split(":")[1].split(',')[0].strip(),
                "remote_device": "",
                "remote_port": "",
                "remote_ip": "",
                "platform": ""
            }
            continue
            
        if not current:
            continue
            
        if line.startswith("System name"):
            current["remote_device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Port description") or line.startswith("Port ID"):
            current["remote_port"] = line.split(":", 1)[1].strip()
        elif line.startswith("Management address"):
            current["remote_ip"] = line.split(":", 1)[1].strip()
        elif line.startswith("System description"):
            current["platform"] = line.split(":", 1)[1].strip()
            
    if current and "local_port" in current:
        neighbors.append(current)
    return neighbors

def parse_juniper_spanning_tree(bridge_output, int_output):
    data = {
        "enabled": False,
        "root_bridge": "",
        "is_root": False,
        "vlans": {} # for Junos, might be contexts or instances
    }
    
    if "Routing instance" in bridge_output or "STP bridge parameters" in bridge_output:
        data["enabled"] = True
        
    # We parse context/instance from interface output
    current_instance = "default"
    lines = int_output.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("Spanning tree interface parameters for instance"):
            current_instance = line.split("for instance")[1].strip()
            data["vlans"][current_instance] = {}
        elif line and not line.startswith("Interface") and not line.startswith("---") and not line.startswith("Spanning tree"):
            parts = line.split()
            if len(parts) >= 4:
                port = parts[0]
                role = parts[2]
                state = parts[3]
                if current_instance not in data["vlans"]:
                    data["vlans"][current_instance] = {}
                data["vlans"][current_instance][port] = {
                    "role": role,
                    "state": state
                }
    return data

def parse_juniper_show_route(output):
    routes = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("inet") or line.startswith("---"):
            continue
            
        # Typical Junos route:
        # 10.1.1.0/24        *[Direct/0] 1w4d 13:21:40
        #                     > via ge-0/0/1.0
        # 192.168.1.0/24     *[OSPF/10] 01:22:33, metric 20
        #                     > to 10.1.1.2 via ge-0/0/2.0
        
        match = re.match(r'^([0-9a-fA-F.:]+/\d+)\s+\*?\[([^/]+)/\d+\]', line)
        if match:
            subnet = match.group(1)
            proto = match.group(2)
            routes.append({
                "subnet": subnet,
                "protocol": proto,
                "next_hop": "Unknown",
                "interface": ""
            })
            continue
            
        via_match = re.search(r'>\s+to\s+([0-9a-fA-F.:]+)\s+via\s+(\S+)', line)
        if via_match and routes:
            routes[-1]["next_hop"] = via_match.group(1)
            routes[-1]["interface"] = via_match.group(2)
            continue
            
        dir_match = re.search(r'>\s+via\s+(\S+)', line)
        if dir_match and routes:
            routes[-1]["next_hop"] = "Directly Connected"
            routes[-1]["interface"] = dir_match.group(1)
            
    return routes

def parse_juniper_services(config):
    services = {
        "dns_servers": [],
        "ntp_servers": [],
        "radius_servers": [],
        "tacacs_servers": []
    }
    
    lines = config.splitlines()
    for line in lines:
        line = line.strip()
        
        if line.startswith("set system name-server"):
            parts = line.split()
            if len(parts) >= 4:
                services["dns_servers"].append(parts[3])
                
        elif line.startswith("set system ntp server"):
            parts = line.split()
            if len(parts) >= 5:
                services["ntp_servers"].append(parts[4])
                
        elif line.startswith("set system radius-server"):
            parts = line.split()
            if len(parts) >= 4:
                services["radius_servers"].append(parts[3])
                
        elif line.startswith("set system tacplus-server"):
            parts = line.split()
            if len(parts) >= 4:
                services["tacacs_servers"].append(parts[3])
                
    # De-duplicate
    for key in services:
        services[key] = list(set(services[key]))
        
    return services
