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

def parse_juniper_vlans(config):
    vlans = {}
    for line in config.splitlines():
        line = line.strip()
        match_id = re.match(r'^set vlans\s+(\S+)\s+vlan-id\s+(\d+)', line)
        if match_id:
            name = match_id.group(1)
            vlan_id = int(match_id.group(2))
            if name not in vlans:
                vlans[name] = {"name": name, "vlan_id": vlan_id, "l3_interface": ""}
            else:
                vlans[name]["vlan_id"] = vlan_id
            continue
            
        match_l3 = re.match(r'^set vlans\s+(\S+)\s+l3-interface\s+(\S+)', line)
        if match_l3:
            name = match_l3.group(1)
            l3_int = match_l3.group(2)
            if name not in vlans:
                vlans[name] = {"name": name, "vlan_id": None, "l3_interface": l3_int}
            else:
                vlans[name]["l3_interface"] = l3_int
    return list(vlans.values())

def parse_juniper_irb_l3(config):
    l3_ints = {}
    for line in config.splitlines():
        line = line.strip()
        match_addr = re.match(r'^set interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+(\S+)', line)
        if match_addr:
            name = f"{match_addr.group(1)}.{match_addr.group(2)}"
            ip = match_addr.group(3)
            if name not in l3_ints:
                l3_ints[name] = {"interface": name, "ip_address": ip, "dhcp": False, "description": ""}
            else:
                l3_ints[name]["ip_address"] = ip
            continue
            
        match_dhcp = re.match(r'^set interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+dhcp', line)
        if match_dhcp:
            name = f"{match_dhcp.group(1)}.{match_dhcp.group(2)}"
            if name not in l3_ints:
                l3_ints[name] = {"interface": name, "ip_address": "dhcp", "dhcp": True, "description": ""}
            else:
                l3_ints[name]["ip_address"] = "dhcp"
                l3_ints[name]["dhcp"] = True
            continue

        match_desc = re.match(r'^set interfaces\s+(\S+)\s+unit\s+(\d+)\s+description\s+(.+)', line)
        if match_desc:
            name = f"{match_desc.group(1)}.{match_desc.group(2)}"
            desc = match_desc.group(3).strip('"')
            if name not in l3_ints:
                l3_ints[name] = {"interface": name, "ip_address": "", "dhcp": False, "description": desc}
            else:
                l3_ints[name]["description"] = desc
    return list(l3_ints.values())

def parse_juniper_routing_instances(config):
    instances = {}
    for line in config.splitlines():
        line = line.strip()
        if not line.startswith("set routing-instances"):
            continue
        match_type = re.match(r'^set routing-instances\s+(\S+)\s+instance-type\s+(\S+)', line)
        if match_type:
            name = match_type.group(1)
            itype = match_type.group(2)
            if name not in instances:
                instances[name] = {"name": name, "type": itype, "interfaces": [], "routes": []}
            else:
                instances[name]["type"] = itype
            continue
            
        match_int = re.match(r'^set routing-instances\s+(\S+)\s+interface\s+(\S+)', line)
        if match_int:
            name = match_int.group(1)
            iface = match_int.group(2)
            if name not in instances:
                instances[name] = {"name": name, "type": "", "interfaces": [iface], "routes": []}
            else:
                instances[name]["interfaces"].append(iface)
            continue
            
        match_route = re.match(r'^set routing-instances\s+(\S+)\s+routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)', line)
        if match_route:
            name = match_route.group(1)
            subnet = match_route.group(2)
            nh = match_route.group(3)
            route_info = {"subnet": subnet, "next_hop": nh}
            if name not in instances:
                instances[name] = {"name": name, "type": "", "interfaces": [], "routes": [route_info]}
            else:
                instances[name]["routes"].append(route_info)
    for inst in instances.values():
        inst["interfaces"] = list(set(inst["interfaces"]))
    return list(instances.values())

def parse_juniper_firewall_filters(config):
    filters = {}
    for line in config.splitlines():
        line = line.strip()
        if not line.startswith("set firewall"):
            continue
        match_term = re.match(r'^set firewall\s+(?:family\s+\S+\s+)?filter\s+(\S+)\s+term\s+(\S+)\s+(from|then)\s+(.+)', line)
        if match_term:
            filter_name = match_term.group(1)
            term_name = match_term.group(2)
            direction = match_term.group(3)
            action_detail = match_term.group(4)
            
            if filter_name not in filters:
                filters[filter_name] = {"name": filter_name, "terms": {}}
            if term_name not in filters[filter_name]["terms"]:
                filters[filter_name]["terms"][term_name] = {"name": term_name, "from": [], "then": []}
                
            if direction == "from":
                filters[filter_name]["terms"][term_name]["from"].append(action_detail)
            else:
                filters[filter_name]["terms"][term_name]["then"].append(action_detail)
    
    result = []
    for f_name, f_data in filters.items():
        terms_list = []
        for t_name, t_data in f_data["terms"].items():
            terms_list.append(t_data)
        result.append({"name": f_name, "terms": terms_list})
    return result

def parse_juniper_dhcp_services(config):
    dhcp_services = {
        "relays": [],
        "local_pools": []
    }
    
    relay_groups = {}
    local_pools = {}
    
    for line in config.splitlines():
        line = line.strip()
        match_relay_srv = re.match(r'^set forwarding-options\s+dhcp-relay\s+server-group\s+(\S+)\s+(\S+)', line)
        if match_relay_srv:
            group = match_relay_srv.group(1)
            srv = match_relay_srv.group(2)
            if group not in relay_groups:
                relay_groups[group] = {"group": group, "servers": [srv], "interfaces": []}
            else:
                relay_groups[group]["servers"].append(srv)
            continue
            
        match_relay_int = re.match(r'^set forwarding-options\s+dhcp-relay\s+group\s+(\S+)\s+interface\s+(\S+)', line)
        if match_relay_int:
            group = match_relay_int.group(1)
            iface = match_relay_int.group(2)
            if group not in relay_groups:
                relay_groups[group] = {"group": group, "servers": [], "interfaces": [iface]}
            else:
                relay_groups[group]["interfaces"].append(iface)
            continue
            
        match_bootp_srv = re.match(r'^set forwarding-options\s+helpers\s+bootp\s+server\s+(\S+)', line)
        if match_bootp_srv:
            srv = match_bootp_srv.group(1)
            if "bootp" not in relay_groups:
                relay_groups["bootp"] = {"group": "bootp_helper", "servers": [srv], "interfaces": []}
            else:
                relay_groups["bootp"]["servers"].append(srv)
            continue
        match_bootp_int = re.match(r'^set forwarding-options\s+helpers\s+bootp\s+interface\s+(\S+)', line)
        if match_bootp_int:
            iface = match_bootp_int.group(1)
            if "bootp" not in relay_groups:
                relay_groups["bootp"] = {"group": "bootp_helper", "servers": [], "interfaces": [iface]}
            else:
                relay_groups["bootp"]["interfaces"].append(iface)
            continue
            
        match_pool_net = re.match(r'^set access\s+address-assignment\s+pool\s+(\S+)\s+family\s+inet\s+network\s+(\S+)', line)
        if match_pool_net:
            pool = match_pool_net.group(1)
            net = match_pool_net.group(2)
            if pool not in local_pools:
                local_pools[pool] = {"pool": pool, "network": net, "range_low": "", "range_high": "", "router": ""}
            else:
                local_pools[pool]["network"] = net
            continue
            
        match_pool_low = re.match(r'^set access\s+address-assignment\s+pool\s+(\S+)\s+family\s+inet\s+range\s+\S+\s+low\s+(\S+)', line)
        if match_pool_low:
            pool = match_pool_low.group(1)
            val = match_pool_low.group(2)
            if pool not in local_pools:
                local_pools[pool] = {"pool": pool, "network": "", "range_low": val, "range_high": "", "router": ""}
            else:
                local_pools[pool]["range_low"] = val
            continue
            
        match_pool_high = re.match(r'^set access\s+address-assignment\s+pool\s+(\S+)\s+family\s+inet\s+range\s+\S+\s+high\s+(\S+)', line)
        if match_pool_high:
            pool = match_pool_high.group(1)
            val = match_pool_high.group(2)
            if pool not in local_pools:
                local_pools[pool] = {"pool": pool, "network": "", "range_low": "", "range_high": val, "router": ""}
            else:
                local_pools[pool]["range_high"] = val
            continue
            
        match_pool_rt = re.match(r'^set access\s+address-assignment\s+pool\s+(\S+)\s+family\s+inet\s+dhcp-attributes\s+router\s+(\S+)', line)
        if match_pool_rt:
            pool = match_pool_rt.group(1)
            val = match_pool_rt.group(2)
            if pool not in local_pools:
                local_pools[pool] = {"pool": pool, "network": "", "range_low": "", "range_high": "", "router": val}
            else:
                local_pools[pool]["router"] = val
            continue
            
    for g in relay_groups.values():
        g["servers"] = list(set(g["servers"]))
        g["interfaces"] = list(set(g["interfaces"]))
        dhcp_services["relays"].append(g)
    for p in local_pools.values():
        dhcp_services["local_pools"].append(p)
    return dhcp_services

def parse_juniper_static_routes(config):
    routes = []
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("set routing-options static route"):
            match_rt = re.match(r'^set routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)', line)
            if match_rt:
                routes.append({
                    "subnet": match_rt.group(1),
                    "next_hop": match_rt.group(2)
                })
    return routes

def audit_juniper_config(config):
    issues = []
    
    # 1. SNMP Checks
    if re.search(r'set snmp community public\b', config):
        issues.append({
            "category": "Security",
            "severity": "High",
            "item": "Default SNMP Community String (public)",
            "detail": "SNMP community 'public' is configured. This is a common security risk."
        })
    if re.search(r'set snmp community private\b', config):
        issues.append({
            "category": "Security",
            "severity": "High",
            "item": "Default SNMP Community String (private)",
            "detail": "SNMP community 'private' is configured. This is a common security risk."
        })
    if re.search(r'set snmp community\s+\S+\b', config) and not re.search(r'set snmp v3\b', config):
        issues.append({
            "category": "Security",
            "severity": "Medium",
            "item": "Legacy SNMP v1/v2c Configured",
            "detail": "SNMP v1/v2c community strings are configured. DISA STIG mandates SNMPv3 with USM authentication/encryption."
        })

    # 2. Insecure Services
    if re.search(r'set system services telnet\b', config):
        issues.append({
            "category": "Security",
            "severity": "High",
            "item": "Telnet Protocol Enabled",
            "detail": "Telnet protocol is enabled. Telnet transmits credentials in plain text. Use SSH instead."
        })
    if re.search(r'set system services ftp\b', config):
        issues.append({
            "category": "Security",
            "severity": "High",
            "item": "FTP Service Enabled",
            "detail": "FTP service is enabled. FTP transmits credentials and files in cleartext. SFTP/SCP should be used instead."
        })
    if re.search(r'set system services web-management http\b', config):
        issues.append({
            "category": "Security",
            "severity": "High",
            "item": "Insecure HTTP Web Management Enabled",
            "detail": "Unencrypted HTTP web management is enabled. Use HTTPS or disable web-management completely."
        })

    # 3. SSH Configuration Hardening
    if re.search(r'set system services ssh root-login allow\b', config):
        issues.append({
            "category": "Security",
            "severity": "Medium",
            "item": "SSH Root Login Allowed",
            "detail": "Direct root SSH login is allowed. Direct root access bypasses individual accountability. Recommend setting 'root-login deny'."
        })
    elif not re.search(r'set system services ssh root-login (deny|deny-password)\b', config):
        issues.append({
            "category": "Security",
            "severity": "Low",
            "item": "SSH Root Login Not Hardened",
            "detail": "SSH root-login is not explicitly configured to 'deny' or 'deny-password'. Direct root logins should be explicitly disabled."
        })
    if re.search(r'set system services ssh protocol-version v1\b', config):
        issues.append({
            "category": "Security",
            "severity": "High",
            "item": "SSH Protocol v1 Enabled",
            "detail": "Deprecated SSH Protocol Version 1 is enabled. DISA STIG requires forcing SSHv2 only."
        })
    if not re.search(r'set system services ssh connection-limit\b', config):
        issues.append({
            "category": "Security",
            "severity": "Medium",
            "item": "SSH Connection Limit Not Set",
            "detail": "No SSH connection-limit is configured. Limiting simultaneous SSH sessions reduces DoS risk (STIG recommends limit <= 5)."
        })
    if not re.search(r'set system services ssh client-alive-interval\b', config):
        issues.append({
            "category": "Security",
            "severity": "Low",
            "item": "SSH Client Alive Interval Not Configured",
            "detail": "SSH client-alive-interval is not configured. Configured timeouts ensure inactive sessions are terminated."
        })

    # 4. System Banners (Legal Disclaimer)
    if not (re.search(r'set system login message\b', config) or re.search(r'set system login announcement\b', config)):
        issues.append({
            "category": "Security",
            "severity": "Medium",
            "item": "Missing Login Warning Banner",
            "detail": "No system login message/announcement configured. DISA STIG mandates displaying a Notice and Consent Banner before user authentication."
        })

    # 5. Network Time Protocol (NTP)
    if not re.search(r'set system ntp server\b', config):
        issues.append({
            "category": "Best Practice",
            "severity": "Low",
            "item": "NTP Not Configured",
            "detail": "No network time protocol (NTP) servers are configured. Accurate clocks are vital for syslog correlation."
        })
    elif not re.search(r'set system ntp authentication-key\b', config):
        issues.append({
            "category": "Security",
            "severity": "Medium",
            "item": "NTP Authentication Missing",
            "detail": "NTP servers are configured, but NTP authentication-key is missing. Unauthenticated time sources are vulnerable to spoofing."
        })

    # 6. Auditing & Logging (Syslog)
    if not re.search(r'set system syslog\b', config):
        issues.append({
            "category": "Best Practice",
            "severity": "Medium",
            "item": "Syslog Not Configured",
            "detail": "Remote or local syslog logging is not configured, leaving logs volatile."
        })
    else:
        if not re.search(r'set system syslog host\b', config):
            issues.append({
                "category": "Security",
                "severity": "Medium",
                "item": "Remote Syslog Host Missing",
                "detail": "Syslog is configured locally but no remote syslog host target is defined. Critical logs should be streamed off-box."
            })
        if not re.search(r'set system syslog (host \S+|file \S+) interactive-commands\b', config):
            issues.append({
                "category": "Security",
                "severity": "Medium",
                "item": "Interactive Commands Logging Missing",
                "detail": "Logging of operator command history (interactive-commands) is not configured. Audit trails must track administrative activity."
            })

    # 7. Control Plane Hardening (Internet Options & Filters)
    if not re.search(r'set system no-redirects\b', config):
        issues.append({
            "category": "Security",
            "severity": "Low",
            "item": "ICMP Redirects Not Disabled",
            "detail": "ICMP redirects are not explicitly disabled. Devices should ignore redirect messages to prevent route hijacking."
        })
    if not re.search(r'set system internet-options tcp-drop-synfin-set\b', config):
        issues.append({
            "category": "Security",
            "severity": "Low",
            "item": "TCP SYN-FIN Scan Defense Disabled",
            "detail": "Junos is not configured to drop TCP SYN-FIN packets, allowing malicious host scanning."
        })
    if not re.search(r'set system internet-options icmpv4-rate-limit\b', config):
        issues.append({
            "category": "Security",
            "severity": "Low",
            "item": "ICMPv4 Rate Limiting Not Set",
            "detail": "Control plane ICMPv4 packet rate limit is not configured. Enforcing rate-limiting mitigates flood DoS attacks."
        })

    # 8. Loop Prevention (Spanning Tree)
    if not (re.search(r'set protocols rstp\b', config) or re.search(r'set protocols mstp\b', config) or re.search(r'set protocols stp\b', config)):
        issues.append({
            "category": "Resiliency",
            "severity": "High",
            "item": "Spanning Tree Disabled",
            "detail": "No Spanning Tree Protocol (STP/RSTP/MSTP) was detected in protocols configuration. Risk of network loops."
        })

    # 9. Control Plane AAA
    if not (re.search(r'set system tacplus-server\b', config) or re.search(r'set system radius-server\b', config)):
        issues.append({
            "category": "Security",
            "severity": "Medium",
            "item": "Centralized AAA Authentication Missing",
            "detail": "No TACACS+ or RADIUS server configuration detected. Administrative access should use centralized authentication."
        })

    return issues


def parse_juniper_ospf_neighbors(output):
    neighbors = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Address") or "Interface" in line:
            continue
        parts = line.split()
        if len(parts) >= 5:
            neighbors.append({
                "neighbor_address": parts[0],
                "interface": parts[1],
                "state": parts[2],
                "neighbor_id": parts[3],
                "priority": parts[4]
            })
    return neighbors


def parse_juniper_bgp_summary(output):
    peers = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Peer") or line.startswith("Groups:") or line.startswith("Table") or line.startswith("inet.0"):
            continue
        parts = line.split()
        if len(parts) >= 8:
            peer_ip = parts[0]
            if re.match(r'^[0-9a-fA-F.:]+$', peer_ip):
                peers.append({
                    "peer": peer_ip,
                    "as": parts[1],
                    "uptime_dwn": parts[6],
                    "state": parts[7]
                })
    return peers


def parse_juniper_security_zones(output):
    zones = []
    current_zone = None
    in_interfaces = False
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Security zone:"):
            current_zone = {
                "name": line.split(":")[1].strip(),
                "interfaces": []
            }
            zones.append(current_zone)
            in_interfaces = False
        elif line.startswith("Interfaces:") or line.startswith("Interfaces bound:"):
            if line.startswith("Interfaces:"):
                in_interfaces = True
        elif in_interfaces and line and not line.startswith("Security zone") and ":" not in line:
            if current_zone:
                current_zone["interfaces"].append(line)
        elif ":" in line:
            in_interfaces = False
    return zones


def parse_juniper_security_policies(output):
    policies = []
    current_from = ""
    current_to = ""
    current_policy = None
    for line in output.splitlines():
        line_strip = line.strip()
        match_zones = re.match(r'^From zone:\s*(\S+),\s*To zone:\s*(\S+)', line_strip, re.IGNORECASE)
        if match_zones:
            current_from = match_zones.group(1).replace(",", "")
            current_to = match_zones.group(2)
            continue
        match_policy = re.match(r'^Policy:\s*(\S+),\s*State:\s*(\S+)', line_strip, re.IGNORECASE)
        if match_policy:
            current_policy = {
                "from_zone": current_from,
                "to_zone": current_to,
                "name": match_policy.group(1).replace(",", ""),
                "state": match_policy.group(2).replace(",", ""),
                "source": [],
                "destination": [],
                "application": [],
                "action": ""
            }
            policies.append(current_policy)
            continue
        if current_policy:
            if line_strip.startswith("Source addresses:"):
                current_policy["source"] = [x.strip() for x in line_strip.split(":")[1].split(",")]
            elif line_strip.startswith("Destination addresses:"):
                current_policy["destination"] = [x.strip() for x in line_strip.split(":")[1].split(",")]
            elif line_strip.startswith("Applications:"):
                current_policy["application"] = [x.strip() for x in line_strip.split(":")[1].split(",")]
            elif line_strip.startswith("Action:"):
                current_policy["action"] = line_strip.split(":")[1].strip()
    return policies

