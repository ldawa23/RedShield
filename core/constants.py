#Level of severity inspired by CVSS ranges
SEVERITY_LEVELS = {
        "CRITICAL": 10, # CVSS ranging from 9.0 - 10.0
        "HIGH": 7,      # CVSS ranging from 7.0 - 8.9
        "MEDIUM": 5,    # CVSS ranging from 4.0 - 6.9
        "LOW": 2,       # CVSS ranging from 0.1 - 3.9
        "NONE": 0,      # CVSS range with 0.0
}

# MOst used and common ports and services
COMMON_PORTS = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        123: "NTP",
        179: "BGP",
        443: "HTTPS",
        500: "ISAKMP",
        587: "SMTP-Submission",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
}

# A placeholder that for later work from KEV/CVE
AFFECTED_SERVICES = {
        # "Apache": ["2.4.6"],
        # "MongoDB": ["3.6.0"],
}

SUPPORTED_TOOLS = ["nmap", "nuclei"]
