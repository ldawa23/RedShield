 """
DVWA Local Vulnerability Fixer
This script fixes vulnerabilities in a LOCAL DVWA installation
where we have full file system access.
"""

import os
import shutil
import re
from datetime import datetime

DVWA_PATH = r"C:\xampp\htdocs\dvwa"

def backup_file(filepath):
    """Create a backup of the file before modifying"""
    backup_path = filepath + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(filepath, backup_path)
    print(f"  ✓ Backup created: {backup_path}")
    return backup_path

def fix_sql_injection():
    """Fix SQL Injection vulnerability in DVWA low.php"""
    print("\n" + "="*60)
    print("🔧 FIXING: SQL Injection Vulnerability")
    print("="*60)
    
    vulnerable_file = os.path.join(DVWA_PATH, "vulnerabilities", "sqli", "source", "low.php")
    
    if not os.path.exists(vulnerable_file):
        print(f"  ❌ File not found: {vulnerable_file}")
        return False
    
    print(f"  📁 Target file: {vulnerable_file}")
    
    # Backup original
    backup_file(vulnerable_file)
    
    # Read current content
    with open(vulnerable_file, 'r') as f:
        content = f.read()
    
    print("\n  📋 VULNERABLE CODE (Before):")
    print("  " + "-"*50)
    # Show the vulnerable query
    if '$query' in content and 'SELECT' in content:
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if '$query' in line and 'SELECT' in line:
                print(f"  Line {i+1}: {line.strip()}")
    
    # The fix: Replace the vulnerable query with parameterized version
    fixed_content = '''<?php
// FIXED VERSION - Using prepared statements to prevent SQL Injection
// Fixed by RedShield Security Scanner on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input (sanitized)
    $id = $_REQUEST[ 'id' ];

    // Use prepared statement to prevent SQL injection
    $stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $id);
    $stmt->execute();
    $result = $stmt->get_result();

    // Get results
    while( $row = $result->fetch_assoc() ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    $stmt->close();
}

?>
'''
    
    with open(vulnerable_file, 'w') as f:
        f.write(fixed_content)
    
    print("\n  📋 FIXED CODE (After):")
    print("  " + "-"*50)
    print("  Using prepared statements with bind_param()")
    print("  $stmt = $mysqli->prepare('SELECT ... WHERE user_id = ?');")
    print("  $stmt->bind_param('s', $id);")
    
    print("\n  ✅ SQL Injection vulnerability FIXED!")
    return True

def fix_xss_reflected():
    """Fix Reflected XSS vulnerability in DVWA"""
    print("\n" + "="*60)
    print("🔧 FIXING: Reflected XSS Vulnerability")
    print("="*60)
    
    vulnerable_file = os.path.join(DVWA_PATH, "vulnerabilities", "xss_r", "source", "low.php")
    
    if not os.path.exists(vulnerable_file):
        print(f"  ❌ File not found: {vulnerable_file}")
        return False
    
    print(f"  📁 Target file: {vulnerable_file}")
    
    # Backup original
    backup_file(vulnerable_file)
    
    # Read current content
    with open(vulnerable_file, 'r') as f:
        content = f.read()
    
    print("\n  📋 VULNERABLE CODE (Before):")
    print("  " + "-"*50)
    print("  echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';")
    print("  (No output encoding - allows script injection)")
    
    # The fix: Add htmlspecialchars for output encoding
    fixed_content = '''<?php
// FIXED VERSION - Using htmlspecialchars to prevent XSS
// Fixed by RedShield Security Scanner on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''

header ("X-XSS-Protection: 1; mode=block");

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Sanitize input with htmlspecialchars to prevent XSS
    $name = htmlspecialchars( $_GET[ 'name' ], ENT_QUOTES, 'UTF-8' );
    echo "<pre>Hello {$name}</pre>";
}

?>
'''
    
    with open(vulnerable_file, 'w') as f:
        f.write(fixed_content)
    
    print("\n  📋 FIXED CODE (After):")
    print("  " + "-"*50)
    print("  $name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');")
    print("  echo '<pre>Hello {$name}</pre>';")
    
    print("\n  ✅ Reflected XSS vulnerability FIXED!")
    return True

def fix_command_injection():
    """Fix Command Injection vulnerability in DVWA"""
    print("\n" + "="*60)
    print("🔧 FIXING: Command Injection Vulnerability")
    print("="*60)
    
    vulnerable_file = os.path.join(DVWA_PATH, "vulnerabilities", "exec", "source", "low.php")
    
    if not os.path.exists(vulnerable_file):
        print(f"  ❌ File not found: {vulnerable_file}")
        return False
    
    print(f"  📁 Target file: {vulnerable_file}")
    
    # Backup original
    backup_file(vulnerable_file)
    
    # Read current content
    with open(vulnerable_file, 'r') as f:
        content = f.read()
    
    print("\n  📋 VULNERABLE CODE (Before):")
    print("  " + "-"*50)
    print("  shell_exec('ping  -c 4 ' . $target);")
    print("  (No input validation - allows command chaining)")
    
    # The fix: Validate IP format and escape shell arguments
    fixed_content = '''<?php
// FIXED VERSION - Input validation and shell escaping
// Fixed by RedShield Security Scanner on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Validate IP address format (only allow valid IPs)
    if( filter_var( $target, FILTER_VALIDATE_IP ) ) {
        // Determine OS and execute the ping command safely
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = 'ping ' . escapeshellarg( $target );
        }
        else {
            // *nix
            $cmd = 'ping -c 4 ' . escapeshellarg( $target );
        }

        // Execute safely
        $output = shell_exec( $cmd );
        echo "<pre>{$output}</pre>";
    }
    else {
        echo "<pre>Invalid IP address format. Please enter a valid IP.</pre>";
    }
}

?>
'''
    
    with open(vulnerable_file, 'w') as f:
        f.write(fixed_content)
    
    print("\n  📋 FIXED CODE (After):")
    print("  " + "-"*50)
    print("  if(filter_var($target, FILTER_VALIDATE_IP)) {")
    print("      $cmd = 'ping ' . escapeshellarg($target);")
    print("  }")
    
    print("\n  ✅ Command Injection vulnerability FIXED!")
    return True

def fix_brute_force():
    """Fix Brute Force vulnerability by adding rate limiting"""
    print("\n" + "="*60)
    print("🔧 FIXING: Brute Force Vulnerability (Weak Login)")
    print("="*60)
    
    vulnerable_file = os.path.join(DVWA_PATH, "vulnerabilities", "brute", "source", "low.php")
    
    if not os.path.exists(vulnerable_file):
        print(f"  ❌ File not found: {vulnerable_file}")
        return False
    
    print(f"  📁 Target file: {vulnerable_file}")
    
    # Backup original
    backup_file(vulnerable_file)
    
    print("\n  📋 VULNERABLE CODE (Before):")
    print("  " + "-"*50)
    print("  No rate limiting or account lockout")
    print("  Allows unlimited login attempts")
    
    # The fix: Add rate limiting and lockout
    fixed_content = '''<?php
// FIXED VERSION - Added rate limiting and lockout
// Fixed by RedShield Security Scanner on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''

// Rate limiting - track failed attempts
session_start();
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['lockout_time'] = 0;
}

// Check if locked out
$lockout_duration = 300; // 5 minutes
if ($_SESSION['login_attempts'] >= 3) {
    $time_remaining = $_SESSION['lockout_time'] + $lockout_duration - time();
    if ($time_remaining > 0) {
        echo "<pre><br />Account locked. Too many failed attempts. Try again in " . ceil($time_remaining/60) . " minutes.</pre>";
        return;
    } else {
        // Reset after lockout period
        $_SESSION['login_attempts'] = 0;
    }
}

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database (using prepared statement)
    $stmt = $GLOBALS["___mysqli_ston"]->prepare("SELECT * FROM `users` WHERE user = ? AND password = ?");
    $stmt->bind_param("ss", $user, $pass);
    $stmt->execute();
    $result = $stmt->get_result();

    if( $result->num_rows == 1 ) {
        // Get users details
        $row    = $result->fetch_assoc();
        $avatar = $row["avatar"];

        // Login successful - reset attempts
        $_SESSION['login_attempts'] = 0;
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\\"{$avatar}\\" />";
    }
    else {
        // Login failed - increment attempts
        $_SESSION['login_attempts']++;
        if ($_SESSION['login_attempts'] >= 3) {
            $_SESSION['lockout_time'] = time();
            echo "<pre><br />Account locked after 3 failed attempts. Try again in 5 minutes.</pre>";
        } else {
            $remaining = 3 - $_SESSION['login_attempts'];
            // Random delay to prevent timing attacks
            sleep( rand( 1, 3 ) );
            echo "<pre><br />Username and/or password incorrect. {$remaining} attempts remaining.</pre>";
        }
    }

    $stmt->close();
}

?>
'''
    
    with open(vulnerable_file, 'w') as f:
        f.write(fixed_content)
    
    print("\n  📋 FIXED CODE (After):")
    print("  " + "-"*50)
    print("  - Added rate limiting (max 3 attempts)")
    print("  - Account lockout for 5 minutes after failures")
    print("  - Random delay to prevent timing attacks")
    print("  - Prepared statements for SQL query")
    
    print("\n  ✅ Brute Force vulnerability FIXED!")
    return True

def fix_file_inclusion():
    """Fix File Inclusion vulnerability"""
    print("\n" + "="*60)
    print("🔧 FIXING: File Inclusion Vulnerability")
    print("="*60)
    
    vulnerable_file = os.path.join(DVWA_PATH, "vulnerabilities", "fi", "source", "low.php")
    
    if not os.path.exists(vulnerable_file):
        print(f"  ❌ File not found: {vulnerable_file}")
        return False
    
    print(f"  📁 Target file: {vulnerable_file}")
    
    # Backup original
    backup_file(vulnerable_file)
    
    print("\n  📋 VULNERABLE CODE (Before):")
    print("  " + "-"*50)
    print("  $file = $_GET['page'];")
    print("  (No validation - allows arbitrary file inclusion)")
    
    # The fix: Whitelist allowed files
    fixed_content = '''<?php
// FIXED VERSION - Whitelist allowed files only
// Fixed by RedShield Security Scanner on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''

// Define allowed pages (whitelist approach)
$allowed_pages = array(
    'file1.php',
    'file2.php',
    'file3.php',
    'include.php'
);

$file = isset($_GET['page']) ? $_GET['page'] : '';

// Only include if file is in whitelist
if (in_array($file, $allowed_pages)) {
    include($file);
} else {
    echo "<pre>Error: Invalid page requested.</pre>";
    echo "<pre>Allowed pages: " . implode(", ", $allowed_pages) . "</pre>";
}

?>
'''
    
    with open(vulnerable_file, 'w') as f:
        f.write(fixed_content)
    
    print("\n  📋 FIXED CODE (After):")
    print("  " + "-"*50)
    print("  $allowed_pages = ['file1.php', 'file2.php', ...];")
    print("  if (in_array($file, $allowed_pages)) { include($file); }")
    
    print("\n  ✅ File Inclusion vulnerability FIXED!")
    return True

def restore_all_vulnerabilities():
    """Restore all original vulnerable files from Git"""
    print("\n" + "="*60)
    print("🔄 RESTORING: All Original Vulnerable Files")
    print("="*60)
    
    import subprocess
    os.chdir(DVWA_PATH)
    result = subprocess.run(['git', 'checkout', '.'], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("  ✅ All files restored to original vulnerable state")
        return True
    else:
        print(f"  ❌ Restore failed: {result.stderr}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     🛡️  RedShield - DVWA Local Vulnerability Fixer 🛡️        ║
╠══════════════════════════════════════════════════════════════╣
║  This tool fixes vulnerabilities in YOUR LOCAL DVWA install  ║
║  demonstrating actual remediation with full server access.   ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    print(f"DVWA Path: {DVWA_PATH}")
    
    if not os.path.exists(DVWA_PATH):
        print(f"❌ DVWA not found at {DVWA_PATH}")
        return
    
    print("\nSelect option:")
    print("  1. Fix SQL Injection")
    print("  2. Fix Reflected XSS")
    print("  3. Fix Command Injection")
    print("  4. Fix Brute Force (Add rate limiting)")
    print("  5. Fix File Inclusion")
    print("  6. Fix ALL vulnerabilities")
    print("  7. RESTORE all to vulnerable state")
    print("  0. Exit")
    
    choice = input("\nEnter choice (0-7): ").strip()
    
    if choice == '1':
        fix_sql_injection()
    elif choice == '2':
        fix_xss_reflected()
    elif choice == '3':
        fix_command_injection()
    elif choice == '4':
        fix_brute_force()
    elif choice == '5':
        fix_file_inclusion()
    elif choice == '6':
        print("\n🔧 Fixing ALL vulnerabilities...")
        fix_sql_injection()
        fix_xss_reflected()
        fix_command_injection()
        fix_brute_force()
        fix_file_inclusion()
        print("\n" + "="*60)
        print("✅ ALL VULNERABILITIES FIXED!")
        print("="*60)
    elif choice == '7':
        restore_all_vulnerabilities()
    elif choice == '0':
        print("Goodbye!")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
