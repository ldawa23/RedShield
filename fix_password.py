import sqlite3
import os

# Check both database locations
db_paths = [
    r'c:\Users\Acer\RedShield\redshield.db',
    r'c:\Users\Acer\RedShield\web\server\redshield.db'
]

for db_path in db_paths:
    if os.path.exists(db_path):
        print(f"\n=== Checking {db_path} ===")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cursor.fetchall()]
        print(f"Tables: {tables}")
        
        if 'web_users' in tables:
            # Check users
            cursor.execute("SELECT id, username, email, role FROM web_users")
            users = cursor.fetchall()
            print(f"Users: {users}")
            
            # Update admin password (bcrypt hash for 'admin123')
            new_hash = '$2a$10$ypsMfgWP7jjDVjMsNHSzQuCw.BY9mk6M5Zo5IvwpaFUAw99yLySLu'
            cursor.execute("UPDATE web_users SET password_hash = ? WHERE username = ?", (new_hash, 'admin'))
            conn.commit()
            print(f"Password updated for admin: {cursor.rowcount} rows affected")
        
        conn.close()

print("\n=== Done ===")
print("You can now login with: admin / admin123")
