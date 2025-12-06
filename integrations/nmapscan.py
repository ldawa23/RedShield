import subprocess

def scan(target, ports="1-1000"):
    #Runs nmap scan and return list of open ports
    #Build a command (eg: nmap(tool using) -sV(service name and version) -p 1-1000(ports to check) 192.168.1.100(what to scan))
    command = [ "nmap", "-sV", "-p", ports, target ] 

    try:
        #RUnning the above command
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)   #runs the command, grabs the output, print it as text and wait for maximum 5 minutes
    
    except FileNotFoundError:
        print("ERROR: Nmap not installed. Run sudo apt-get install nmap")
        return []
    
    except subprocess.TimeoutExpired:
        print("ERROR: Scan took too long (>5 minutes)")
        return []

    #Converting the output
    output = result.stdout
    open_ports = []

    #Goes through each line
    for i in output.splitlines():
        i = i.strip()

        #EMpty lines and headers will be skipped
        if not i or "PORT" in i or "Nmap" in i:
            continue

        #Line like: "22/tcp open ssh    OpenSSH 7.4"
        parts = i.split()

        #Seperating into three parts as needed: port/prototype, state, service
        if len(parts) < 3:
            continue

        port_prototype = parts[0]   #22/tcp
        state = parts[1]            #open
        service = parts[2]          #ssh

