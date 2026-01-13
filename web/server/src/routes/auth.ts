/**
 * Authentication Routes
 */

import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import { getDatabase, dbHelpers } from '../db/database';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'redshield-super-secret-key-change-in-production';

// Register
router.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req: Request, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, email, password } = req.body;
    const db = getDatabase();
    
    // Check if user exists
    const existing = db.prepare('SELECT id FROM web_users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Check if this is the first user (make admin)
    const userCount = db.prepare('SELECT COUNT(*) as count FROM web_users').get() as any;
    const role = userCount.count === 0 ? 'admin' : 'user';
    
    // Create user
    const stmt = db.prepare(`
      INSERT INTO web_users (username, email, password_hash, role)
      VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(username, email, passwordHash, role);
    
    // Log activity
    dbHelpers.logActivity(result.lastInsertRowid as number, 'USER_REGISTERED', 'user', String(result.lastInsertRowid));
    
    // Generate token
    const token = jwt.sign(
      { userId: result.lastInsertRowid, username, role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      user: { id: result.lastInsertRowid, username, email, role },
      token
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', [
  body('username').trim().escape(),
  body('password').exists()
], async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    const db = getDatabase();
    
    // Find user
    const user = db.prepare('SELECT * FROM web_users WHERE username = ? OR email = ?').get(username, username) as any;
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    db.prepare('UPDATE web_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
    
    // Log activity
    dbHelpers.logActivity(user.id, 'USER_LOGIN', 'user', String(user.id), undefined, req.ip, req.get('User-Agent'));
    
    // Generate token
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      token
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
router.get('/me', (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    const db = getDatabase();
    const user = db.prepare('SELECT id, username, email, role, created_at, last_login FROM web_users WHERE id = ?').get(decoded.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
    
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Logout (client-side token removal, but log activity)
router.post('/logout', (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      dbHelpers.logActivity(decoded.userId, 'USER_LOGOUT', 'user', String(decoded.userId));
    }
    res.json({ message: 'Logged out successfully' });
  } catch {
    res.json({ message: 'Logged out' });
  }
});

// Change password
router.post('/change-password', [
  body('currentPassword').exists(),
  body('newPassword').isLength({ min: 6 })
], async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    
    const { currentPassword, newPassword } = req.body;
    const db = getDatabase();
    
    // Get current user
    const user = db.prepare('SELECT * FROM web_users WHERE id = ?').get(decoded.userId) as any;
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    
    // Update password
    db.prepare('UPDATE web_users SET password_hash = ? WHERE id = ?').run(newPasswordHash, decoded.userId);
    
    // Log activity
    dbHelpers.logActivity(decoded.userId, 'PASSWORD_CHANGED', 'user', String(decoded.userId));
    
    res.json({ message: 'Password changed successfully' });
    
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Admin: Get all users
router.get('/users', (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const db = getDatabase();
    const users = db.prepare('SELECT id, username, email, role, is_active, created_at, last_login FROM web_users ORDER BY created_at DESC').all();
    
    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin: Create user
router.post('/users', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('role').isIn(['admin', 'user'])
], async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, email, password, role } = req.body;
    const db = getDatabase();
    
    // Check if user exists
    const existing = db.prepare('SELECT id FROM web_users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    const stmt = db.prepare(`
      INSERT INTO web_users (username, email, password_hash, role)
      VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(username, email, passwordHash, role);
    
    dbHelpers.logActivity(decoded.userId, 'USER_CREATED', 'user', String(result.lastInsertRowid), JSON.stringify({ created_user: username }));
    
    res.status(201).json({
      message: 'User created successfully',
      user: { id: result.lastInsertRowid, username, email, role }
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Admin: Update user role
router.patch('/users/:id', (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { id } = req.params;
    const { role, is_active } = req.body;
    const db = getDatabase();
    
    if (role) {
      db.prepare('UPDATE web_users SET role = ? WHERE id = ?').run(role, id);
    }
    if (typeof is_active === 'boolean') {
      db.prepare('UPDATE web_users SET is_active = ? WHERE id = ?').run(is_active ? 1 : 0, id);
    }
    
    dbHelpers.logActivity(decoded.userId, 'USER_UPDATED', 'user', id, JSON.stringify({ role, is_active }));
    
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Admin: Delete user
router.delete('/users/:id', (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { id } = req.params;
    
    // Prevent self-deletion
    if (String(decoded.userId) === id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    const db = getDatabase();
    db.prepare('DELETE FROM web_users WHERE id = ?').run(id);
    
    dbHelpers.logActivity(decoded.userId, 'USER_DELETED', 'user', id);
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

export default router;
