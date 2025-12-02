
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class Service:
    """Represents one port or service discovery from Nmap"""
    port: int
    protocol: str       # tcp or udp
    state: str          # open, closed, filtered
    service_name: str   # ssh, http
    version: str        # OpenSSH 7.4p1

class NmapScanner:  #Runs nmap and parses results
    def __init__(self, target: str):    #initialize scanner for a target
        self.target = target
        self.results: List[Service] = []
        self.xml_file = os.path.join(tempfile.gettempdir(), f"nmap_{target}.xml")

    def scan(self, ports: str="1-1000", aggressive: bool=False) -> List[Service]: # Run Nmap scan and return results
        #BUild nmap command
        cmd = ["nmap"]
        cmd.append("-sV")                   #Service version detection
        cmd.extend(["-p", ports])           #Specify ports
        cmd.extend(["-oX", self.xml_file])  #Outputs to XML
        
        if aggressive:
            cmd.append("-sC")   #Run default scripts

        cmd.append(self.target)

        try:
            print(f"[*} Running: {' '.join(cmd)}")
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)

            self.parse_results()

            return self.results
        except FileNotFoundError:
            raise RuntimeError(
                    "Nmap not found. INstall it: apt-get install nmap (Linux) or brew install nmap (Mac)"
            )
