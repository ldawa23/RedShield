"""
RedShield Authentication Module

Handles user authentication for the CLI.
- Admin users can: scan, fix, view reports, manage users
- Normal users can: scan, view reports (cannot fix)
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path

SESSION_FILE = Path.home() / ".redshield_session"


def hash_password(password: str) -> str:
    """Hash a password securely with salt."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        salt, hashed = stored_hash.split(":")
        check_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return check_hash == hashed
    except:
        return False


def create_user(username: str, password: str, email: str, role: str = "user"):
    """Create a new user in the database."""
    try:
        from database.connection import get_session
        from database.models import User, UserRole
        
        session = get_session()
        
        existing = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing:
            session.close()
            return "Username or email already exists"
        
        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN if role == "admin" else UserRole.USER,
            is_active=True
        )
        
        session.add(user)
        session.commit()
        session.close()
        return True
        
    except Exception as e:
        return str(e)


def authenticate_user(username: str, password: str):
    """Authenticate a user with username and password."""
    try:
        from database.connection import get_session
        from database.models import User
        
        session = get_session()
        user = session.query(User).filter(User.username == username).first()
        
        if not user or not user.is_active:
            session.close()
            return None
        
        if not verify_password(password, user.hashed_password):
            session.close()
            return None
        
        user.last_login = datetime.utcnow()
        session.commit()
        
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role.value,
            'is_admin': user.role.value == 'admin'
        }
        
        session.close()
        return user_data
        
    except Exception as e:
        print(f"Auth error: {e}")
        return None


def save_session(user_data: dict):
    """Save user session to file."""
    session_data = {
        'user': user_data,
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }
    with open(SESSION_FILE, 'w') as f:
        json.dump(session_data, f)


def load_session():
    """Load and validate current session."""
    try:
        if not SESSION_FILE.exists():
            return None
        with open(SESSION_FILE, 'r') as f:
            session_data = json.load(f)
        expires_at = datetime.fromisoformat(session_data['expires_at'])
        if datetime.utcnow() > expires_at:
            clear_session()
            return None
        return session_data['user']
    except:
        return None


def clear_session():
    """Clear the current session (logout)."""
    try:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
    except:
        pass


def get_current_user():
    """Get the currently logged-in user."""
    return load_session()


def require_login(func):
    """Decorator to require login for a command."""
    import functools
    import click
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            click.echo(click.style("Error: You must be logged in.", fg='red'))
            click.echo("Run 'redshield login' or 'redshield register'")
            raise click.Abort()
        return func(*args, **kwargs)
    return wrapper


def require_admin(func):
    """Decorator to require admin role for a command."""
    import functools
    import click
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            click.echo(click.style("Error: You must be logged in.", fg='red'))
            raise click.Abort()
        if not user.get('is_admin'):
            click.echo(click.style("Error: Admin privileges required.", fg='red'))
            raise click.Abort()
        return func(*args, **kwargs)
    return wrapper


def get_user_count():
    """Get total number of users."""
    try:
        from database.connection import get_session
        from database.models import User
        session = get_session()
        count = session.query(User).count()
        session.close()
        return count
    except:
        return 0
