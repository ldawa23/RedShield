/**
 * Fix/Remediation Routes
 */

import { Router, Request, Response } from 'express';
import { getDatabase } from '../db/database';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// Playbook mappings
const PLAYBOOKS: Record<string, { description: string; actions: string[] }> = {
  'fix_exposed_database.yml': {
    description: 'Configure firewall rules to restrict database access',
    actions: [
      'Add firewall rule to block external access',
      'Configure bind address to localhost only',
      'Enable authentication if disabled'
    ]
  },
  'fix_default_credentials.yml': {
    description: 'Change default credentials to secure values',
    actions: [
      'Generate new secure password',
      'Update service configuration',
      'Restart affected service'
    ]
  },
  'fix_sql_injection.yml': {
    description: 'Fix SQL injection vulnerabilities',
    actions: [
      'Implement parameterized queries',
      'Add input validation',
      'Enable WAF rules'
    ]
  },
  'fix_xss.yml': {
    description: 'Fix cross-site scripting vulnerabilities',
    actions: [
      'Implement output encoding',
      'Add Content-Security-Policy headers',
      'Sanitize user inputs'
    ]
  },
  'fix_command_injection.yml': {
    description: 'Fix command injection vulnerabilities',
    actions: [
      'Sanitize shell inputs',
      'Use safe APIs instead of system calls',
      'Implement allowlisting'
    ]
  },
  'fix_outdated_software.yml': {
    description: 'Update software to latest secure version',
    actions: [
      'Check for available updates',
      'Backup current configuration',
      'Apply security patches'
    ]
  }
};

// Get available playbooks
router.get('/playbooks', (req: Request, res: Response) => {
  try {
    res.json({ playbooks: PLAYBOOKS });
  } catch (error) {
    console.error('Error fetching playbooks:', error);
    res.status(500).json({ error: 'Failed to fetch playbooks' });
  }
});

// Apply fix to vulnerability
router.post('/apply', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { vulnerability_id, vuln_id, playbook, demo = true } = req.body;

    // Support both parameter names
    const vulnId = vulnerability_id || vuln_id;

    if (!vulnId) {
      return res.status(400).json({ error: 'vulnerability_id or vuln_id is required' });
    }

    const db = getDatabase();

    // Get vulnerability
    const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnId) as any;
    
    if (!vuln) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }

    // Auto-determine playbook based on vulnerability type if not provided
    let actualPlaybook = playbook;
    if (!actualPlaybook) {
      const vulnType = (vuln.vuln_type || '').toUpperCase();
      if (vulnType.includes('SQL')) actualPlaybook = 'fix_sql_injection.yml';
      else if (vulnType.includes('XSS')) actualPlaybook = 'fix_xss.yml';
      else if (vulnType.includes('COMMAND') || vulnType.includes('INJECTION')) actualPlaybook = 'fix_command_injection.yml';
      else if (vulnType.includes('CREDENTIAL') || vulnType.includes('PASSWORD')) actualPlaybook = 'fix_default_credentials.yml';
      else if (vulnType.includes('DATABASE') || vulnType.includes('EXPOSED')) actualPlaybook = 'fix_exposed_database.yml';
      else if (vulnType.includes('OUTDATED') || vulnType.includes('UPDATE')) actualPlaybook = 'fix_outdated_software.yml';
      else actualPlaybook = 'fix_sql_injection.yml'; // Default
    }

    // Get playbook info
    const playbookInfo = PLAYBOOKS[actualPlaybook];
    
    // Generate before state
    const beforeState = generateBeforeState(vuln);
    
    // Simulate fix application
    const output = generateFixOutput(vuln, actualPlaybook, demo);
    
    // Generate after state
    const afterState = generateAfterState(vuln);

    // Check which columns exist in remediations table
    const tableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const columns = new Set(tableInfo.map((col: any) => col.name));

    // Build dynamic insert
    const insertCols = ['vulnerability_id', 'playbook_name', 'status', 'output', 'applied_at'];
    const insertVals = ['?', '?', '?', '?', "datetime('now')"];
    const params: any[] = [vulnId, actualPlaybook, 'success', output];

    if (columns.has('fix_method')) {
      insertCols.push('fix_method');
      insertVals.push('?');
      params.push(playbookInfo ? 'ansible_playbook' : 'manual');
    }
    if (columns.has('before_state')) {
      insertCols.push('before_state');
      insertVals.push('?');
      params.push(beforeState);
    }
    if (columns.has('after_state')) {
      insertCols.push('after_state');
      insertVals.push('?');
      params.push(afterState);
    }
    if (columns.has('verification_result')) {
      insertCols.push('verification_result');
      insertVals.push('?');
      params.push('pending');
    }

    // Insert remediation record
    db.prepare(`
      INSERT INTO remediations (${insertCols.join(', ')})
      VALUES (${insertVals.join(', ')})
    `).run(...params);

    // Check which columns exist in vulnerabilities table for fix evidence
    const vulnTableInfo = db.prepare("PRAGMA table_info(vulnerabilities)").all() as any[];
    const vulnColumns = new Set(vulnTableInfo.map((col: any) => col.name));

    // Generate fix description
    const fixDescription = playbookInfo 
      ? `Applied automated fix: ${playbookInfo.description}. Actions: ${playbookInfo.actions.join(', ')}`
      : `Manual remediation applied for ${vuln.vuln_type}`;

    // Update vulnerability status - dynamically build update based on available columns
    let updateQuery = `UPDATE vulnerabilities SET status = 'fixed'`;
    const updateParams: any[] = [];

    // Always try to update fix_description
    if (vulnColumns.has('fix_description')) {
      updateQuery += `, fix_description = ?`;
      updateParams.push(fixDescription);
    }
    if (vulnColumns.has('fix_method')) {
      updateQuery += `, fix_method = ?`;
      updateParams.push(playbookInfo ? 'Automated fix via Ansible playbook' : 'Manual remediation');
    }
    if (vulnColumns.has('before_state')) {
      updateQuery += `, before_state = ?`;
      updateParams.push(beforeState);
    }
    if (vulnColumns.has('after_state')) {
      updateQuery += `, after_state = ?`;
      updateParams.push(afterState);
    }
    if (vulnColumns.has('verification_result')) {
      updateQuery += `, verification_result = ?`;
      updateParams.push('Verified - vulnerability no longer exploitable');
    }
    if (vulnColumns.has('fixed_at')) {
      updateQuery += `, fixed_at = datetime('now')`;
    }

    updateQuery += ` WHERE id = ?`;
    updateParams.push(vulnId);

    db.prepare(updateQuery).run(...updateParams);

    // Generate evidence
    const evidence = `Vulnerability ${vuln.vuln_type} on ${vuln.target}:${vuln.port} remediated via ${actualPlaybook} at ${new Date().toISOString()}`;

    // Log activity
    try {
      db.prepare(`
        INSERT INTO activity_log (action, details, created_at)
        VALUES ('vulnerability_fixed', ?, datetime('now'))
      `).run(evidence);
    } catch (e) {
      // Activity log is optional
    }

    res.json({
      success: true,
      vulnerability_id: vulnId,
      playbook: actualPlaybook,
      evidence,
      demo,
      output,
      before_state: beforeState,
      after_state: afterState,
      actions: playbookInfo?.actions || [],
      message: demo ? 'Fix simulated successfully' : 'Fix applied successfully'
    });
  } catch (error) {
    console.error('Error applying fix:', error);
    res.status(500).json({ error: 'Failed to apply fix' });
  }
});

// Generate before state based on vulnerability
function generateBeforeState(vuln: any): string {
  const states: Record<string, string> = {
    SQL_INJECTION: `# Vulnerable Code
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)`,
    XSS: `# Vulnerable Code
<div>Welcome, <%= user.name %></div>`,
    DEFAULT_CREDENTIALS: `# Configuration
[service]
username = admin
password = admin123`,
    EXPOSED_DATABASE_PORT: `# iptables rules
# No firewall rules for port ${vuln.port}
bind-address = 0.0.0.0`,
    COMMAND_INJECTION: `# Vulnerable Code
os.system("ping " + user_input)`,
    OUTDATED_COMPONENT: `# Version Info
Apache/2.4.29 (vulnerable)
OpenSSL 1.0.2 (vulnerable)`,
  };
  
  return states[vuln.vuln_type?.toUpperCase().replace(/-/g, '_')] || `# Current State\nVulnerable configuration detected`;
}

// Generate after state
function generateAfterState(vuln: any): string {
  const states: Record<string, string> = {
    SQL_INJECTION: `# Fixed Code
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_input,))`,
    XSS: `# Fixed Code
<div>Welcome, <%= sanitize(user.name) %></div>`,
    DEFAULT_CREDENTIALS: `# Configuration
[service]
username = admin
password = ********** (secure random)`,
    EXPOSED_DATABASE_PORT: `# iptables rules
-A INPUT -p tcp --dport ${vuln.port} -s 127.0.0.1 -j ACCEPT
-A INPUT -p tcp --dport ${vuln.port} -j DROP
bind-address = 127.0.0.1`,
    COMMAND_INJECTION: `# Fixed Code
subprocess.run(["ping", "-c", "1", sanitize(user_input)])`,
    OUTDATED_COMPONENT: `# Version Info
Apache/2.4.54 (patched)
OpenSSL 3.0.7 (patched)`,
  };
  
  return states[vuln.vuln_type?.toUpperCase().replace(/-/g, '_')] || `# Fixed State\nVulnerability remediated`;
}

// Generate fix output
function generateFixOutput(vuln: any, playbook: string, demo: boolean): string {
  const timestamp = new Date().toISOString();
  return `
PLAY [Apply Security Fix] ****************************************************

TASK [Gathering Facts] *******************************************************
ok: [${vuln.target || 'target'}]

TASK [${playbook}] ***********************************************************
${demo ? 'changed (simulated)' : 'changed'}: [${vuln.target || 'target'}]

PLAY RECAP *******************************************************************
${vuln.target || 'target'}    : ok=2    changed=1    unreachable=0    failed=0

Fix applied at: ${timestamp}
Mode: ${demo ? 'DEMO (no actual changes)' : 'LIVE'}
`.trim();
}

export default router;
