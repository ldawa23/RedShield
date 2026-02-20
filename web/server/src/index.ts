/**
 * RedShield Backend Server
 * 
 * Professional Node.js/Express API server with TypeScript
 * Connects to SQLite database and provides REST API for the dashboard
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { rateLimit } from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';
import { Server } from 'socket.io';
import http from 'http';

// Import routes
import authRoutes from './routes/auth';
import scanRoutes from './routes/scans';
import vulnRoutes from './routes/vulnerabilities';
import statsRoutes from './routes/stats';
import activityRoutes from './routes/activity';
import fixRoutes from './routes/fix';
import verifyRoutes from './routes/verify';
import exploitsRoutes from './routes/exploits';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [process.env.CLIENT_URL || 'http://localhost:5173', 'http://localhost:5174'],
    methods: ['GET', 'POST']
  }
});

const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts for development
}));

// Rate limiting - generous limits for development
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 1000, // Limit each IP to 1000 requests per minute
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// CORS
app.use(cors({
  origin: [process.env.CLIENT_URL || 'http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging
app.use(morgan('dev'));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/vulnerabilities', vulnRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/activity', activityRoutes);
app.use('/api/fix', fixRoutes);
app.use('/api/verify', verifyRoutes);
app.use('/api/exploits', exploitsRoutes);

// Health check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Reset endpoint (for Settings page - clears activity log and scan data)
app.post('/api/reset', (req: Request, res: Response) => {
  try {
    // Only allow with valid admin token
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const jwt = require('jsonwebtoken');
      const token = authHeader.split(' ')[1];
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'redshield-super-secret-key-change-in-production') as any;
        if (decoded.role !== 'admin') {
          return res.status(403).json({ error: 'Admin access required' });
        }
      } catch {
        return res.status(401).json({ error: 'Invalid token' });
      }
    } else {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Import database
    const { getDatabase } = require('./db/database');
    const db = getDatabase();
    
    // Clear activity log
    db.prepare('DELETE FROM activity_log').run();
    
    // Clear scans and vulnerabilities (optional - can be controlled by body param)
    if (req.body.clearScans) {
      db.prepare('DELETE FROM scan_records').run();
      db.prepare('DELETE FROM vulnerability_records').run();
    }
    
    res.json({ message: 'Data cleared successfully' });
  } catch (error) {
    console.error('Reset error:', error);
    res.status(500).json({ error: 'Failed to clear data' });
  }
});

// Socket.IO for real-time updates
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('subscribe:scans', () => {
    socket.join('scans');
  });
  
  socket.on('subscribe:vulnerabilities', () => {
    socket.join('vulnerabilities');
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Export io for use in routes
export { io };

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Not Found' });
});

// Start server
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║          🛡️  RedShield API Server Started 🛡️             ║
╠══════════════════════════════════════════════════════════╣
║  Port: ${PORT}                                             ║
║  Mode: ${process.env.NODE_ENV || 'development'}                                    ║
║  API:  http://localhost:${PORT}/api                        ║
╚══════════════════════════════════════════════════════════╝
  `);
});

export default app;
