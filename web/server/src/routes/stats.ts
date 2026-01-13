/**
 * Dashboard Statistics Routes
 */

import { Router, Request, Response } from 'express';
import { getDatabase, dbHelpers } from '../db/database';

const router = Router();

// Get comprehensive dashboard statistics
router.get('/', (req: Request, res: Response) => {
  try {
    const stats = dbHelpers.getDashboardStats();
    res.json(stats);
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Get vulnerability trend data (for charts)
router.get('/trends', (req: Request, res: Response) => {
  try {
    const { days = 30 } = req.query;
    const db = getDatabase();
    
    // Vulnerability discovery trend
    const discoveryTrend = db.prepare(`
      SELECT 
        DATE(discovered_at) as date,
        COUNT(*) as discovered,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low
      FROM vulnerability_records
      WHERE discovered_at >= DATE('now', '-' || ? || ' days')
      GROUP BY DATE(discovered_at)
      ORDER BY date
    `).all(days);
    
    // Fix trend
    const fixTrend = db.prepare(`
      SELECT 
        DATE(fixed_at) as date,
        COUNT(*) as fixed
      FROM vulnerability_records
      WHERE fixed_at IS NOT NULL 
        AND fixed_at >= DATE('now', '-' || ? || ' days')
      GROUP BY DATE(fixed_at)
      ORDER BY date
    `).all(days);
    
    // Scan activity trend
    const scanTrend = db.prepare(`
      SELECT 
        DATE(started_at) as date,
        COUNT(*) as scans
      FROM scan_records
      WHERE started_at >= DATE('now', '-' || ? || ' days')
      GROUP BY DATE(started_at)
      ORDER BY date
    `).all(days);
    
    res.json({
      discoveryTrend,
      fixTrend,
      scanTrend
    });
  } catch (error) {
    console.error('Error fetching trends:', error);
    res.status(500).json({ error: 'Failed to fetch trends' });
  }
});

// Get severity distribution
router.get('/severity', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const distribution = db.prepare(`
      SELECT 
        severity,
        COUNT(*) as count,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM vulnerability_records), 2) as percentage
      FROM vulnerability_records
      GROUP BY severity
      ORDER BY 
        CASE severity 
          WHEN 'Critical' THEN 1 
          WHEN 'High' THEN 2 
          WHEN 'Medium' THEN 3 
          WHEN 'Low' THEN 4 
        END
    `).all();
    
    res.json({ distribution });
  } catch (error) {
    console.error('Error fetching severity distribution:', error);
    res.status(500).json({ error: 'Failed to fetch distribution' });
  }
});

// Get fix rate statistics
router.get('/fix-rate', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const fixRate = db.prepare(`
      SELECT 
        severity,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed,
        ROUND(SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as fix_percentage
      FROM vulnerability_records
      GROUP BY severity
    `).all();
    
    const overall = db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed,
        ROUND(SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as fix_percentage
      FROM vulnerability_records
    `).get();
    
    res.json({ bySeverity: fixRate, overall });
  } catch (error) {
    console.error('Error fetching fix rate:', error);
    res.status(500).json({ error: 'Failed to fetch fix rate' });
  }
});

// Get top vulnerable services
router.get('/top-services', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const services = db.prepare(`
      SELECT 
        service,
        COUNT(*) as vuln_count,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high
      FROM vulnerability_records
      GROUP BY service
      ORDER BY vuln_count DESC
      LIMIT 10
    `).all();
    
    res.json({ services });
  } catch (error) {
    console.error('Error fetching top services:', error);
    res.status(500).json({ error: 'Failed to fetch services' });
  }
});

// Get OWASP category breakdown
router.get('/owasp', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const owasp = db.prepare(`
      SELECT 
        COALESCE(owasp_category, 'Uncategorized') as category,
        COUNT(*) as count
      FROM vulnerability_records
      GROUP BY owasp_category
      ORDER BY count DESC
    `).all();
    
    res.json({ owasp });
  } catch (error) {
    console.error('Error fetching OWASP stats:', error);
    res.status(500).json({ error: 'Failed to fetch OWASP statistics' });
  }
});

// Get real-time stats (for live dashboard)
router.get('/realtime', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    // Last 24 hours activity
    const recentActivity = {
      newVulns: (db.prepare(`
        SELECT COUNT(*) as count FROM vulnerability_records 
        WHERE discovered_at >= DATETIME('now', '-24 hours')
      `).get() as any).count,
      
      fixedVulns: (db.prepare(`
        SELECT COUNT(*) as count FROM vulnerability_records 
        WHERE fixed_at >= DATETIME('now', '-24 hours')
      `).get() as any).count,
      
      newScans: (db.prepare(`
        SELECT COUNT(*) as count FROM scan_records 
        WHERE started_at >= DATETIME('now', '-24 hours')
      `).get() as any).count
    };
    
    // Active threats (unfixed critical/high)
    const activeThreats = (db.prepare(`
      SELECT COUNT(*) as count FROM vulnerability_records 
      WHERE status != 'fixed' AND severity IN ('Critical', 'High')
    `).get() as any).count;
    
    // Latest scan
    const latestScan = db.prepare(`
      SELECT * FROM scan_records ORDER BY started_at DESC LIMIT 1
    `).get();
    
    res.json({
      recentActivity,
      activeThreats,
      latestScan,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching realtime stats:', error);
    res.status(500).json({ error: 'Failed to fetch realtime stats' });
  }
});

export default router;
