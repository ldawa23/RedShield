/**
 * Vulnerabilities Routes
 */

import { Router, Request, Response } from 'express';
import { getDatabase, dbHelpers } from '../db/database';

const router = Router();

// Get all vulnerabilities with pagination
router.get('/', (req: Request, res: Response) => {
  try {
    const { page = 1, limit = 50, severity, status } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    const db = getDatabase();
    
    // First check which columns exist in remediations table
    const tableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const remediationColumns = new Set(tableInfo.map((col: any) => col.name));
    
    // Build dynamic select for remediation columns
    const remediationSelects: string[] = [
      'r.playbook_name',
      'r.status as remediation_status',
      'r.applied_at as remediation_applied_at',
      'r.output as remediation_output'
    ];
    
    // Add optional columns if they exist
    if (remediationColumns.has('fix_method')) remediationSelects.push('r.fix_method');
    if (remediationColumns.has('fix_command')) remediationSelects.push('r.fix_command');
    if (remediationColumns.has('before_state')) remediationSelects.push('r.before_state');
    if (remediationColumns.has('after_state')) remediationSelects.push('r.after_state');
    if (remediationColumns.has('verification_result')) remediationSelects.push('r.verification_result');
    
    let query = `
      SELECT 
        v.*,
        s.scan_id,
        s.target,
        ${remediationSelects.join(',\n        ')}
      FROM vulnerabilities v
      LEFT JOIN scans s ON v.scan_id = s.id
      LEFT JOIN remediations r ON v.id = r.vulnerability_id
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
    
    query += ` ORDER BY 
      CASE UPPER(v.severity) 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        WHEN 'LOW' THEN 4 
      END,
      v.discovered_at DESC
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
    res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
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
        s.scan_id,
        s.target,
        s.started_at as scan_started,
        s.completed_at as scan_completed
      FROM vulnerabilities v
      LEFT JOIN scans s ON v.scan_id = s.id
      WHERE v.id = ?
    `).get(id);
    
    if (!vulnerability) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }
    
    // Get remediation history
    const remediations = db.prepare(`
      SELECT * FROM remediations 
      WHERE vulnerability_id = ?
      ORDER BY applied_at DESC
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
    
    // Check which columns exist in remediations table
    const tableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const remediationColumns = new Set(tableInfo.map((col: any) => col.name));
    
    // Build dynamic select for remediation columns
    const remediationSelects: string[] = [
      'r.playbook_name',
      'r.output as remediation_output',
      'r.applied_at as fixed_at'
    ];
    
    // Add optional columns if they exist
    if (remediationColumns.has('fix_method')) remediationSelects.push('r.fix_method');
    if (remediationColumns.has('fix_command')) remediationSelects.push('r.fix_command');
    if (remediationColumns.has('before_state')) remediationSelects.push('r.before_state');
    if (remediationColumns.has('after_state')) remediationSelects.push('r.after_state');
    if (remediationColumns.has('verification_result')) remediationSelects.push('r.verification_result');
    
    const vulnerabilities = db.prepare(`
      SELECT 
        v.*,
        ${remediationSelects.join(',\n        ')}
      FROM vulnerabilities v
      LEFT JOIN remediations r ON v.id = r.vulnerability_id
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
