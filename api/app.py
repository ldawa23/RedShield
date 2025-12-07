from fastapi import FastAPI
from pydantic import BaseModel
from core.nmapvuln import scanrun

app = FastAPI()

class ScanRequest(BaseModel):
    target:str
    ports:str = "1-1000"

@app.post("/api/scans")
def scancreate(req: ScanRequest):
    scan = scanrun(req.target, req.ports)

    return { "scan_id": scan.id, "target": scan.target, "status": scan.status, 
            "vulnerabilities": [ {"severity": v.severity, "type": v.vuln_type, "service": v.service, "port": v.port, }
            for v in scan.vulnerabilites
            ],
    }

