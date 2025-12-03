import click
import re
import ipaddress

def validate(target):
    #Validate is valid IP, hostname or CIDR range
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    hostname = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if re.march(hostname, target):
        return target

    raise click.BadParameter(f"'{target}' is not a valid IP address. Use: IP {192.168.1.1}, CIDR (10.0.0.0/24) or hostname (example.com)")

def validate_port(range_port):
    #Validate port range format
    try:
        if '-' in range_port:
            parts = range_port.split('-')
                
            if len(parts) == 2:
                start = int(parts[0])
                end = int(parts[1])

                if 1 <= start <= end <= 65535:
                    return range_port
        elif range_port.isdigit():
            port = int(range_port)

            if 1<= port <= 65535:
                return range_port

        elif ',' in range_port:
            ports = [int(p.strip()) for p in range_port.split(',')]
            
            if all(1 <= p <= 65535 for p in ports):
                return range_port
    except ValueError:
        pass

    raise click.BadParameter(f"'{range_port}' invalid. Use: single port (22), range (1-1000), or list (22,80,443)")
