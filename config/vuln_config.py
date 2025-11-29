Vulnerability_types={
        "EXPOSED_DATABASE_PORT": {
            "default_severity": "Critical",
            "fixable": True,
            "description": "Ports of database are exposed to the network (often without proper auth).",
        },
        "DEFAULT_CREDENTIALS": {
            "default_severity": "Critical",
            "fixable": True,
            "description": "Service found to be using old, default or weak credentials",
        },
        "OUTDATED_COMPONENT": {
            "default_severity": "High",
            "fixable": True,
            "description": "Software version with known public vulnerabilities (CVE)",
        },
        "MISSING_HTTPS": {
            "default_severity": "High",
            "fixable": True,
            "description": "HTTP used without HTTPS",
        },
}
