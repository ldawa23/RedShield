const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('./redshield.db');

// Check tables
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
console.log('Tables:', tables);

// Create web_users table if needed (this is the table used by auth.ts)
db.exec(`
  CREATE TABLE IF NOT EXISTS web_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
  )
`);

// Delete existing admin from web_users and create new one
db.prepare('DELETE FROM web_users WHERE username = ?').run('admin');

const hash = bcrypt.hashSync('admin123', 10);
db.prepare('INSERT INTO web_users (username, email, password_hash, role) VALUES (?, ?, ?, ?)').run('admin', 'admin@redshield.local', hash, 'admin');

console.log('Admin user created in web_users with password: admin123');

// Verify
const user = db.prepare('SELECT username, email, role FROM web_users WHERE username = ?').get('admin');
console.log('Verified user:', user);
