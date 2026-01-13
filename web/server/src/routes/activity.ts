/**
 * Activity Log Routes
 */

import { Router, Request, Response } from 'express';
import { getDatabase, dbHelpers } from '../db/database';

const router = Router();

// Get activity log
router.get('/', (req: Request, res: Response) => {
  try {
    const { limit = 100, page = 1 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    const db = getDatabase();
    
    const activities = db.prepare(`
      SELECT 
        a.*,
        u.username
      FROM activity_log a
      LEFT JOIN web_users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `).all(Number(limit), offset);
    
    res.json(activities);
  } catch (error) {
    console.error('Error fetching activity log:', error);
    res.status(500).json({ error: 'Failed to fetch activity log' });
  }
});

// Log a manual activity (for frontend actions)
router.post('/', (req: Request, res: Response) => {
  try {
    const { action, resourceType, resourceId, details } = req.body;
    
    // Get user from token if available
    let userId = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const jwt = require('jsonwebtoken');
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'redshield-super-secret-key-change-in-production') as any;
        userId = decoded.userId;
      } catch {}
    }
    
    const result = dbHelpers.logActivity(
      userId,
      action,
      resourceType,
      resourceId,
      details,
      req.ip,
      req.get('User-Agent')
    );
    
    res.status(201).json({ 
      message: 'Activity logged',
      id: result.lastInsertRowid 
    });
  } catch (error) {
    console.error('Error logging activity:', error);
    res.status(500).json({ error: 'Failed to log activity' });
  }
});

// Log activity (alternative endpoint for frontend compatibility)
router.post('/log', (req: Request, res: Response) => {
  try {
    const { action, resource_type, resource_id, details } = req.body;
    
    // Get user from token if available
    let userId = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const jwt = require('jsonwebtoken');
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'redshield-super-secret-key-change-in-production') as any;
        userId = decoded.userId;
      } catch {}
    }
    
    const result = dbHelpers.logActivity(
      userId,
      action,
      resource_type,
      resource_id,
      details,
      req.ip,
      req.get('User-Agent')
    );
    
    res.status(201).json({ 
      message: 'Activity logged',
      id: result.lastInsertRowid 
    });
  } catch (error) {
    console.error('Error logging activity:', error);
    res.status(500).json({ error: 'Failed to log activity' });
  }
});

// Get activity by resource
router.get('/resource/:type/:id', (req: Request, res: Response) => {
  try {
    const { type, id } = req.params;
    const db = getDatabase();
    
    const activities = db.prepare(`
      SELECT 
        a.*,
        u.username
      FROM activity_log a
      LEFT JOIN web_users u ON a.user_id = u.id
      WHERE a.resource_type = ? AND a.resource_id = ?
      ORDER BY a.created_at DESC
      LIMIT 50
    `).all(type, id);
    
    res.json({ activities });
  } catch (error) {
    console.error('Error fetching resource activity:', error);
    res.status(500).json({ error: 'Failed to fetch activity' });
  }
});

// Get activity summary (for dashboard)
router.get('/summary', (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    
    const summary = {
      today: (db.prepare(`
        SELECT COUNT(*) as count FROM activity_log 
        WHERE DATE(created_at) = DATE('now')
      `).get() as any).count,
      
      thisWeek: (db.prepare(`
        SELECT COUNT(*) as count FROM activity_log 
        WHERE created_at >= DATE('now', '-7 days')
      `).get() as any).count,
      
      byAction: db.prepare(`
        SELECT action, COUNT(*) as count 
        FROM activity_log 
        WHERE created_at >= DATE('now', '-7 days')
        GROUP BY action 
        ORDER BY count DESC
        LIMIT 10
      `).all(),
      
      activeUsers: db.prepare(`
        SELECT u.username, COUNT(*) as actions
        FROM activity_log a
        JOIN web_users u ON a.user_id = u.id
        WHERE a.created_at >= DATE('now', '-7 days')
        GROUP BY a.user_id
        ORDER BY actions DESC
        LIMIT 5
      `).all()
    };
    
    res.json(summary);
  } catch (error) {
    console.error('Error fetching activity summary:', error);
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

export default router;
