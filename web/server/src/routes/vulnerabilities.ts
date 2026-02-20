/**
 * Vulnerabilities Routes
 */

import { Router, Request, Response } from 'express';
import { getDatabase, dbHelpers } from '../db/database';

const router = Router();

// Get all vulnerabilities with pagination (deduplicated)
router.get('/', (req: Request, res: Response) => {
  try {
    const { page = 1, limit = 50, severity, status } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    const db = getDatabase();
    
    // First check which columns exist in remediations and vulnerabilities tables
    const remTableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const remediationColumns = new Set(remTableInfo.map((col: any) => col.name));
    
    const vulnTableInfo = db.prepare("PRAGMA table_info(vulnerabilities)").all() as any[];
    const vulnColumns = new Set(vulnTableInfo.map((col: any) => col.name));
    
    // Build subqueries for latest remediation data (only existing columns)
    const remediationSubqueries: string[] = [];
    
    // Only include columns that exist in the remediations table
    if (remediationColumns.has('playbook_name') || remediationColumns.has('playbook_path')) {
      const playCol = remediationColumns.has('playbook_name') ? 'playbook_name' : 'playbook_path';
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT ${playCol} FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as playbook_name`);
    }
    if (remediationColumns.has('status')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT status FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as remediation_status`);
    }
    if (remediationColumns.has('completed_at')) {
      remediationSubqueries.push('(SELECT completed_at FROM remediations WHERE vulnerability_id = v.id ORDER BY completed_at DESC LIMIT 1) as remediation_applied_at');
    }
    if (remediationColumns.has('output')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT output FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as remediation_output`);
    }
    if (remediationColumns.has('fix_method')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT fix_method FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as fix_method`);
    }
    if (remediationColumns.has('fix_command')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT fix_command FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as fix_command`);
    }
    if (remediationColumns.has('before_state')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT before_state FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as before_state`);
    }
    if (remediationColumns.has('after_state')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT after_state FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as after_state`);
    }
    if (remediationColumns.has('verification_result')) {
      const orderCol = remediationColumns.has('completed_at') ? 'completed_at' : 'id';
      remediationSubqueries.push(`(SELECT verification_result FROM remediations WHERE vulnerability_id = v.id ORDER BY ${orderCol} DESC LIMIT 1) as verification_result`);
    }
    
    // Build vulnerability column list (only existing columns)
    const vulnSelects: string[] = [
      'v.id',
      'v.scan_id as vuln_scan_id',
      'v.vuln_type',
      'v.service',
      'v.port',
      'UPPER(v.severity) as severity',
      'v.status',
      'v.description'
    ];
    
    // Add columns conditionally based on what exists in the database
    if (vulnColumns.has('cve_id')) vulnSelects.push('v.cve_id');
    if (vulnColumns.has('owasp_category')) vulnSelects.push('v.owasp_category');
    if (vulnColumns.has('mitre_id')) vulnSelects.push('v.mitre_id');
    if (vulnColumns.has('fix_available')) vulnSelects.push('v.fix_available');
    if (vulnColumns.has('fix_description')) vulnSelects.push('v.fix_description');
    if (vulnColumns.has('fixed_at')) vulnSelects.push('v.fixed_at');
    if (vulnColumns.has('discovered_at')) vulnSelects.push('v.discovered_at');
    if (vulnColumns.has('http_method')) vulnSelects.push('v.http_method');
    if (vulnColumns.has('vulnerable_url')) vulnSelects.push('v.vulnerable_url');
    if (vulnColumns.has('vulnerable_parameter')) vulnSelects.push('v.vulnerable_parameter');
    if (vulnColumns.has('payload_used')) vulnSelects.push('v.payload_used');
    if (vulnColumns.has('evidence')) vulnSelects.push('v.evidence');
    if (vulnColumns.has('request_example')) vulnSelects.push('v.request_example');
    if (vulnColumns.has('response_snippet')) vulnSelects.push('v.response_snippet');
    if (vulnColumns.has('affected_code')) vulnSelects.push('v.affected_code');
    if (vulnColumns.has('remediation_code')) vulnSelects.push('v.remediation_code');
    
    let selectColumns = vulnSelects.join(',\n        ') + ',\n        s.scan_id,\n        s.target';
    if (remediationSubqueries.length > 0) {
      selectColumns += ',\n        ' + remediationSubqueries.join(',\n        ');
    }
    
    let query = `
      SELECT 
        ${selectColumns}
      FROM vulnerabilities v
      LEFT JOIN scans s ON v.scan_id = s.scan_id
      WHERE 1=1
    `;
    
    const params: any[] = [];
    
    if (severity) {
      query += ' AND UPPER(v.severity) = UPPER(?)';
      params.push(severity);
    }
    
    if (status) {
      query += ' AND v.status = ?';
      params.push(status);
    }
    
    // Build ORDER BY clause based on existing columns
    const hasDiscoveredAt = vulnColumns.has('discovered_at');
    
    query += ` ORDER BY 
      CASE UPPER(v.severity) 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
      END${hasDiscoveredAt ? ',\n      v.discovered_at DESC' : ',\n      v.id DESC'}
      LIMIT ? OFFSET ?
    `;
    params.push(Number(limit), offset);
    
    const vulnerabilities = db.prepare(query).all(...params);
    
    // Get total count
    let countQuery = 'SELECT COUNT(*) as count FROM vulnerabilities WHERE 1=1';
    const countParams: any[] = [];
    if (severity) {
      countQuery += ' AND UPPER(severity) = UPPER(?)';
      countParams.push(severity);
    }
    if (status) {
      countQuery += ' AND status = ?';
      countParams.push(status);
    }
    const total = (db.prepare(countQuery).get(...countParams) as any).count;
    
    res.json(vulnerabilities);
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('Query failed with:', errorMessage);
    res.status(500).json({ error: 'Failed to fetch vulnerabilities', details: errorMessage });
  }
});

// Get single vulnerability details
router.get('/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const db = getDatabase();
    
    const vulnerability = db.prepare(`
      SELECT 
        v.*,
        s.target,
        s.started_at as scan_started,
        s.completed_at as scan_completed
      FROM vulnerabilities v
      LEFT JOIN scans s ON v.scan_id = s.scan_id
      WHERE v.id = ?
    `).get(id);
    
    if (!vulnerability) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }
    
    // Get remediation history
    const remediations = db.prepare(`
      SELECT * FROM remediations 
      WHERE vulnerability_id = ?
      ORDER BY completed_at DESC
    `).all(id);
    
    res.json({ vulnerability, remediations });
  } catch (error) {
    console.error('Error fetching vulnerability:', error);
    res.status(500).json({ error: 'Failed to fetch vulnerability' });
  }
});

// Get vulnerabilities by scan
router.get('/scan/:scanId', (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    const db = getDatabase();
    
    const scan = db.prepare('SELECT id FROM scans WHERE scan_id = ?').get(scanId) as any;
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Check which columns exist in remediations and vulnerabilities tables
    const remTableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const remediationColumns = new Set(remTableInfo.map((col: any) => col.name));
    
    const vulnTableInfo = db.prepare("PRAGMA table_info(vulnerabilities)").all() as any[];
    const vulnColumns = new Set(vulnTableInfo.map((col: any) => col.name));
    
    // Build subqueries for latest remediation data  
    const remediationSubqueries: string[] = [
      '(SELECT playbook_name FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as playbook_name',
      '(SELECT output FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as remediation_output',
      '(SELECT applied_at FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as fixed_at'
    ];
    
    // Add optional remediation columns if they exist
    if (remediationColumns.has('fix_method')) {
      remediationSubqueries.push('(SELECT fix_method FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as fix_method');
    }
    if (remediationColumns.has('fix_command')) {
      remediationSubqueries.push('(SELECT fix_command FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as fix_command');
    }
    if (remediationColumns.has('before_state')) {
      remediationSubqueries.push('(SELECT before_state FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as before_state');
    }
    if (remediationColumns.has('after_state')) {
      remediationSubqueries.push('(SELECT after_state FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as after_state');
    }
    if (remediationColumns.has('verification_result')) {
      remediationSubqueries.push('(SELECT verification_result FROM remediations WHERE vulnerability_id = v.id ORDER BY applied_at DESC LIMIT 1) as verification_result');
    }
    
    // Build vulnerability column list (only existing columns)
    const vulnSelects: string[] = [
      'v.id',
      'v.scan_id',
      'v.vuln_type',
      'v.service',
      'v.port',
      'UPPER(v.severity) as severity',
      'v.status',
      'v.description'
    ];
    
    // Add columns conditionally based on what exists
    if (vulnColumns.has('cve_id')) vulnSelects.push('v.cve_id');
    if (vulnColumns.has('owasp_category')) vulnSelects.push('v.owasp_category');
    if (vulnColumns.has('mitre_id')) vulnSelects.push('v.mitre_id');
    if (vulnColumns.has('fix_available')) vulnSelects.push('v.fix_available');
    if (vulnColumns.has('fix_description')) vulnSelects.push('v.fix_description');
    if (vulnColumns.has('discovered_at')) vulnSelects.push('v.discovered_at');
    if (vulnColumns.has('http_method')) vulnSelects.push('v.http_method');
    if (vulnColumns.has('vulnerable_url')) vulnSelects.push('v.vulnerable_url');
    if (vulnColumns.has('vulnerable_parameter')) vulnSelects.push('v.vulnerable_parameter');
    if (vulnColumns.has('payload_used')) vulnSelects.push('v.payload_used');
    if (vulnColumns.has('evidence')) vulnSelects.push('v.evidence');
    if (vulnColumns.has('request_example')) vulnSelects.push('v.request_example');
    if (vulnColumns.has('response_snippet')) vulnSelects.push('v.response_snippet');
    if (vulnColumns.has('affected_code')) vulnSelects.push('v.affected_code');
    if (vulnColumns.has('remediation_code')) vulnSelects.push('v.remediation_code');
    
    const vulnerabilities = db.prepare(`
      SELECT 
        ${vulnSelects.join(',\n        ')},
        ${remediationSubqueries.join(',\n        ')}
      FROM vulnerabilities v
      WHERE v.scan_id = ?
      ORDER BY 
        CASE UPPER(v.severity) 
          WHEN 'CRITICAL' THEN 1 
          WHEN 'HIGH' THEN 2 
          WHEN 'MEDIUM' THEN 3 
          WHEN 'LOW' THEN 4 
        END,
        v.discovered_at DESC
    `).all(scan.id);
    
    res.json(vulnerabilities);
  } catch (error) {
    console.error('Error fetching scan vulnerabilities:', error);
    res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
  }
});

// Get vulnerability statistics by severity
router.get('/stats/severity', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const stats = db.prepare(`
      SELECT 
        UPPER(severity) as severity,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed,
        SUM(CASE WHEN status != 'fixed' THEN 1 ELSE 0 END) as open
      FROM vulnerabilities
      GROUP BY UPPER(severity)
    `).all();
    
    res.json({ stats });
  } catch (error) {
    console.error('Error fetching severity stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Get vulnerability types
router.get('/stats/types', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const types = db.prepare(`
      SELECT 
        vuln_type,
        COUNT(*) as count,
        severity
      FROM vulnerabilities
      GROUP BY vuln_type
      ORDER BY count DESC
      LIMIT 20
    `).all();
    
    res.json({ types });
  } catch (error) {
    console.error('Error fetching vulnerability types:', error);
    res.status(500).json({ error: 'Failed to fetch types' });
  }
});

// Get remediation details for a vulnerability
router.get('/:id/remediation', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const db = getDatabase();
    
    const remediation = db.prepare(`
      SELECT 
        r.*,
        v.vuln_type,
        v.severity,
        v.service,
        v.port,
        v.http_method,
        v.vulnerable_url,
        v.vulnerable_parameter
      FROM remediations r
      JOIN vulnerabilities v ON r.vulnerability_id = v.id
      WHERE r.vulnerability_id = ?
      ORDER BY r.applied_at DESC
      LIMIT 1
    `).get(id);
    
    if (!remediation) {
      return res.status(404).json({ error: 'No remediation found for this vulnerability' });
    }
    
    res.json({ remediation });
  } catch (error) {
    console.error('Error fetching remediation:', error);
    res.status(500).json({ error: 'Failed to fetch remediation' });
  }
});

export default router;
