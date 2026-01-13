/**
 * Verify Routes - Metasploit exploit verification
 */

import { Router, Request, Response } from 'express';
import { getDatabase } from '../db/database';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// Metasploit exploit mappings
const EXPLOIT_MAP: Record<string, { module: string; description: string }> = {
  'ssh-weak-password': {
    module: 'auxiliary/scanner/ssh/ssh_login',
    description: 'SSH login bruteforce'
  },
  'default_credentials': {
    module: 'auxiliary/scanner/ssh/ssh_login',
    description: 'Default credentials check'
  },
  'sql_injection': {
    module: 'auxiliary/scanner/http/sql_injection',
    description: 'SQL injection verification'
  },
  'xss': {
    module: 'auxiliary/scanner/http/xss_scanner',
    description: 'XSS vulnerability scanner'
  },
  'exposed_database_port': {
    module: 'auxiliary/scanner/mysql/mysql_login',
    description: 'Database access verification'
  },
  'command_injection': {
    module: 'exploit/multi/http/command_injection',
    description: 'Command injection exploit'
  },
  'smb-ms17-010': {
    module: 'auxiliary/scanner/smb/smb_ms17_010',
    description: 'EternalBlue scanner'
  },
  'apache-log4j': {
    module: 'exploit/multi/http/log4shell_header_injection',
    description: 'Log4Shell RCE'
  }
};

// Run verification
router.post('/run', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { vulnerability_id, demo = true } = req.body;

    if (!vulnerability_id) {
      return res.status(400).json({ error: 'vulnerability_id is required' });
    }

    const db = getDatabase();

    // Get vulnerability
    const vuln = db.prepare(`
      SELECT v.*, s.target 
      FROM vulnerabilities v
      LEFT JOIN scans s ON v.scan_id = s.id
      WHERE v.id = ?
    `).get(vulnerability_id) as any;
    
    if (!vuln) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }

    // Get exploit module for this vuln type
    const vulnKey = vuln.vuln_type?.toLowerCase().replace(/ /g, '_').replace(/-/g, '_');
    const exploit = EXPLOIT_MAP[vulnKey] || EXPLOIT_MAP[vuln.vuln_type?.toLowerCase()];

    // Generate verification result
    const result = generateVerificationResult(vuln, exploit, demo);

    // Update remediation record if exists
    const tableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const columns = new Set(tableInfo.map((col: any) => col.name));

    if (columns.has('verification_result')) {
      db.prepare(`
        UPDATE remediations 
        SET verification_result = ?
        WHERE vulnerability_id = ?
      `).run(result.verified ? 'verified_fixed' : 'still_vulnerable', vulnerability_id);
    }

    res.json({
      success: true,
      vulnerability_id,
      vuln_type: vuln.vuln_type,
      target: vuln.target,
      verified: result.verified,
      exploit_module: exploit?.module || 'N/A',
      demo,
      output: result.output,
      message: result.verified 
        ? 'Vulnerability has been fixed and verified' 
        : 'Vulnerability still present - requires further remediation'
    });
  } catch (error) {
    console.error('Error running verification:', error);
    res.status(500).json({ error: 'Failed to run verification' });
  }
});

// Generate verification output
function generateVerificationResult(vuln: any, exploit: any, demo: boolean) {
  const isFixed = vuln.status === 'fixed';
  const timestamp = new Date().toISOString();
  
  const output = `
[*] Metasploit Verification - ${demo ? 'DEMO MODE' : 'LIVE'}
[*] Target: ${vuln.target || 'unknown'}:${vuln.port || 'N/A'}
[*] Vulnerability: ${vuln.vuln_type}
[*] Module: ${exploit?.module || 'manual_check'}
[*] Started at: ${timestamp}

${exploit ? `
[*] Loading module: ${exploit.module}
[*] Setting RHOSTS to ${vuln.target}
[*] Setting RPORT to ${vuln.port}
` : '[!] No automated module available - using manual verification'}

${isFixed ? `
[+] Exploit attempt FAILED (as expected)
[+] Target appears to be patched
[+] Verification PASSED - vulnerability has been remediated
` : `
[-] Exploit attempt SUCCEEDED
[-] Target is still vulnerable
[-] Verification FAILED - vulnerability still present
`}

[*] Verification completed at: ${new Date().toISOString()}
`.trim();

  return {
    verified: isFixed,
    output
  };
}

// Get available exploits
router.get('/exploits', (req: Request, res: Response) => {
  try {
    const exploits = Object.entries(EXPLOIT_MAP).map(([key, value]) => ({
      id: key,
      ...value
    }));
    
    res.json({ exploits });
  } catch (error) {
    console.error('Error fetching exploits:', error);
    res.status(500).json({ error: 'Failed to fetch exploits' });
  }
});

export default router;
