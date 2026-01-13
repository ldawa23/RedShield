/**
 * Database Connection for RedShield Web Server
 * 
 * Connects to the existing SQLite database used by the CLI
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

// Path to the CLI's SQLite database
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../../../redshield.db');

let db: Database.Database;

export function getDatabase(): Database.Database {
  if (!db) {
    // Check if database exists
    if (!fs.existsSync(DB_PATH)) {
      console.warn('Database not found at:', DB_PATH);
      console.warn('Creating new database...');
    }
    
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    
    // Create tables if they don't exist (for standalone web usage)
    initializeTables();
    
    console.log('Database connected:', DB_PATH);
  }
  return db;
}

function initializeTables() {
  // Users table (for web auth, separate from CLI auth)
  db.exec(`
    CREATE TABLE IF NOT EXISTS web_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )
  `);
  
  // Activity log table
  db.exec(`
    CREATE TABLE IF NOT EXISTS activity_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      resource_type TEXT,
      resource_id TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES web_users(id)
    )
  `);
  
  // Sessions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES web_users(id)
    )
  `);
  
  // Dashboard preferences
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_preferences (
      user_id INTEGER PRIMARY KEY,
      theme TEXT DEFAULT 'dark',
      dashboard_layout TEXT,
      notifications_enabled INTEGER DEFAULT 1,
      FOREIGN KEY (user_id) REFERENCES web_users(id)
    )
  `);
  
  // Add missing columns to vulnerabilities table for fix evidence
  addMissingColumnsToVulnerabilities();
  
  // Add missing columns to remediations table
  addMissingColumnsToRemediations();
  
  // Create default admin user if no users exist
  createDefaultAdmin();
}

// Add fix-related columns to vulnerabilities table if they don't exist
function addMissingColumnsToVulnerabilities() {
  try {
    const tableInfo = db.prepare("PRAGMA table_info(vulnerabilities)").all() as any[];
    const existingColumns = new Set(tableInfo.map((col: any) => col.name));
    
    const columnsToAdd = [
      { name: 'fix_method', type: 'TEXT' },
      { name: 'fix_description', type: 'TEXT' },
      { name: 'before_state', type: 'TEXT' },
      { name: 'after_state', type: 'TEXT' },
      { name: 'verification_result', type: 'TEXT' },
      { name: 'fixed_at', type: 'DATETIME' },
      { name: 'fix_command', type: 'TEXT' }
    ];
    
    for (const col of columnsToAdd) {
      if (!existingColumns.has(col.name)) {
        try {
          db.exec(`ALTER TABLE vulnerabilities ADD COLUMN ${col.name} ${col.type}`);
          console.log(`Added column ${col.name} to vulnerabilities table`);
        } catch (err) {
          // Column might already exist or table doesn't exist yet
        }
      }
    }
  } catch (err) {
    // Table might not exist yet
  }
}

// Add fix-related columns to remediations table if they don't exist
function addMissingColumnsToRemediations() {
  try {
    const tableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const existingColumns = new Set(tableInfo.map((col: any) => col.name));
    
    const columnsToAdd = [
      { name: 'fix_method', type: 'TEXT' },
      { name: 'fix_command', type: 'TEXT' },
      { name: 'before_state', type: 'TEXT' },
      { name: 'after_state', type: 'TEXT' },
      { name: 'verification_result', type: 'TEXT' }
    ];
    
    for (const col of columnsToAdd) {
      if (!existingColumns.has(col.name)) {
        try {
          db.exec(`ALTER TABLE remediations ADD COLUMN ${col.name} ${col.type}`);
          console.log(`Added column ${col.name} to remediations table`);
        } catch (err) {
          // Column might already exist or table doesn't exist yet
        }
      }
    }
  } catch (err) {
    // Table might not exist yet
  }
}

async function createDefaultAdmin() {
  const bcrypt = require('bcryptjs');
  
  const userCount = db.prepare('SELECT COUNT(*) as count FROM web_users').get() as any;
  
  if (userCount.count === 0) {
    const passwordHash = bcrypt.hashSync('admin123', 10);
    
    try {
      db.prepare(`
        INSERT INTO web_users (username, email, password_hash, role, is_active)
        VALUES (?, ?, ?, ?, ?)
      `).run('admin', 'admin@redshield.local', passwordHash, 'admin', 1);
      
      console.log('✅ Default admin user created: admin / admin123');
    } catch (err) {
      // User might already exist
    }
  }
}

// Helper functions for common queries
export const dbHelpers = {
  // Get all scans with vulnerability counts
  getScansWithStats: () => {
    const stmt = db.prepare(`
      SELECT 
        s.*,
        COUNT(v.id) as vuln_count,
        SUM(CASE WHEN UPPER(v.severity) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN UPPER(v.severity) = 'HIGH' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN UPPER(v.severity) = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
        SUM(CASE WHEN UPPER(v.severity) = 'LOW' THEN 1 ELSE 0 END) as low_count,
        SUM(CASE WHEN v.status = 'fixed' THEN 1 ELSE 0 END) as fixed_count
      FROM scans s
      LEFT JOIN vulnerabilities v ON s.id = v.scan_id
      GROUP BY s.id
      ORDER BY s.started_at DESC
    `);
    return stmt.all();
  },
  
  // Get scan by ID
  getScanById: (scanId: string) => {
    const stmt = db.prepare('SELECT * FROM scans WHERE scan_id = ?');
    return stmt.get(scanId);
  },
  
  // Get vulnerabilities for a scan (includes new HTTP request fields)
  getVulnerabilitiesByScan: (scanId: number) => {
    // Check which columns exist in remediations table
    const tableInfo = db.prepare("PRAGMA table_info(remediations)").all() as any[];
    const remediationColumns = new Set(tableInfo.map((col: any) => col.name));
    
    // Build dynamic select for remediation columns
    const remediationSelects: string[] = [
      'r.playbook_name',
      'r.status as remediation_status',
      'r.applied_at',
      'r.output as remediation_output'
    ];
    
    // Add optional columns if they exist
    if (remediationColumns.has('fix_method')) remediationSelects.push('r.fix_method');
    if (remediationColumns.has('fix_command')) remediationSelects.push('r.fix_command');
    if (remediationColumns.has('before_state')) remediationSelects.push('r.before_state');
    if (remediationColumns.has('after_state')) remediationSelects.push('r.after_state');
    if (remediationColumns.has('verification_result')) remediationSelects.push('r.verification_result');
    
    const stmt = db.prepare(`
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
        END
    `);
    return stmt.all(scanId);
  },
  
  // Get dashboard statistics
  getDashboardStats: () => {
    const totalScans = db.prepare('SELECT COUNT(*) as count FROM scans').get() as any;
    const totalVulns = db.prepare('SELECT COUNT(*) as count FROM vulnerabilities').get() as any;
    const fixedVulns = db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'fixed'").get() as any;
    const severityCounts = db.prepare(`
      SELECT 
        UPPER(severity) as severity,
        COUNT(*) as count
      FROM vulnerabilities
      GROUP BY UPPER(severity)
    `).all();
    
    const recentScans = db.prepare(`
      SELECT * FROM scans 
      ORDER BY started_at DESC 
      LIMIT 5
    `).all();
    
    const vulnerabilityTrend = db.prepare(`
      SELECT 
        DATE(discovered_at) as date,
        COUNT(*) as count
      FROM vulnerabilities
      WHERE discovered_at >= DATE('now', '-30 days')
      GROUP BY DATE(discovered_at)
      ORDER BY date
    `).all();
    
    return {
      totalScans: totalScans.count,
      totalVulnerabilities: totalVulns.count,
      fixedVulnerabilities: fixedVulns.count,
      openVulnerabilities: totalVulns.count - fixedVulns.count,
      severityCounts: severityCounts.reduce((acc: any, curr: any) => {
        acc[curr.severity?.toLowerCase() || 'unknown'] = curr.count;
        return acc;
      }, {}),
      recentScans,
      vulnerabilityTrend
    };
  },
  
  // Compare two scans
  compareScans: (scanId1: string, scanId2: string) => {
    const scan1 = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId1) as any;
    const scan2 = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scanId2) as any;
    
    if (!scan1 || !scan2) return null;
    
    const vulns1 = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scan1.id);
    const vulns2 = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scan2.id);
    
    // Create fingerprints for comparison
    const fingerprint = (v: any) => `${v.vuln_type}|${v.port}|${v.service}|${v.vulnerable_parameter || ''}`;
    
    const before = new Map(vulns1.map((v: any) => [fingerprint(v), v]));
    const after = new Map(vulns2.map((v: any) => [fingerprint(v), v]));
    
    const fixed: any[] = [];
    const newVulns: any[] = [];
    const unchanged: any[] = [];
    
    // Find fixed vulnerabilities
    before.forEach((v, fp) => {
      if (!after.has(fp)) {
        fixed.push(v);
      } else {
        unchanged.push(v);
      }
    });
    
    // Find new vulnerabilities
    after.forEach((v, fp) => {
      if (!before.has(fp)) {
        newVulns.push(v);
      }
    });
    
    return {
      scan_before: scan1,
      scan_after: scan2,
      vulns_before: vulns1.length,
      vulns_after: vulns2.length,
      fixed: fixed,
      new: newVulns,
      unchanged: unchanged,
      improvement: vulns1.length > 0 ? ((vulns1.length - vulns2.length) / vulns1.length * 100).toFixed(1) : 0
    };
  },
  
  // Log activity
  logActivity: (userId: number | null, action: string, resourceType?: string, resourceId?: string, details?: string, ip?: string, userAgent?: string) => {
    const stmt = db.prepare(`
      INSERT INTO activity_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    return stmt.run(userId, action, resourceType, resourceId, details, ip, userAgent);
  },
  
  // Get activity log
  getActivityLog: (limit: number = 50) => {
    const stmt = db.prepare(`
      SELECT 
        a.*,
        u.username
      FROM activity_log a
      LEFT JOIN web_users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT ?
    `);
    return stmt.all(limit);
  }
};

export default getDatabase;
