import subprocess
from typing import List, Tuple

def nmap_run(target: str, ports: str = "1-1000") -> List[Tuple[int,str]]:
    cmd = ["nmap", "-sV", "-p", ports, target,]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300,)

    except FileNotFoundError:
        raise RuntimeError( 
                "Nmap is not installed or not in Path"
                "Install: apt-get install nmap (Linux) or brew install nmap (Mac)"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap scan timed out for {target}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError("Nmap failed: {e.stderr}")

    output = result.stdout

    open_ports: List[Tuple[int,str]] = []

    for i in output.splitlines():
        i = i.strip()

        if not i:
            continue
        if i.startswith("Nmap scan report") or \
           i.startwith("PORT") or \
           i.startwith("Host is") or \
           i.startwith("Starting") or \
           "Nmap done" in i:
               continue

        parts = i.split()
        if len(parts) < 3:
            continue

        port_prototype = parts[0]   # 22/tcp or 80 udp
        state = parts[1]            # 22 -> 22 (integer)
        service = parts[2]          # ssh, http, mongodb

        if state != "open":
            continue

        try:
            port_Str = port_prototype.split("/")[0] # 22/tcp -> 22
            port-num = int(port_str)                # 22 -> 22 (integer)
        except (ValueError, IndexError):
            continue
        open_ports.append((port_num, service))

    return open_ports

if __name__ == "__main__":
    target = "127.0.0.1"    # or any ip
    ports = "1-1000"

    print(f"[*] Scanning {target}:{ports}")
    try:
        results = run_nmap_basic(target, ports)
        print(f"[+] Found {len(results)} open ports")
        for port, service in results:
            print(f"    Port {port:5}: {service}")
    except RuntimeError as e:
        print(f"[!] Error: {e}")
