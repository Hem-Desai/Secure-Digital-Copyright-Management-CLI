import sqlite3
import os
import sys
import bcrypt
import time
import uuid
import getpass

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.user import User, UserRole

def init_db():
    # Create database directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    
    # Drop existing tables
    c.execute('DROP TABLE IF EXISTS users')
    
    # Create users table
    c.execute('''
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at REAL NOT NULL,
        artifacts TEXT,
        failed_login_attempts INTEGER DEFAULT 0,
        last_login_attempt REAL DEFAULT 0
    )
    ''')
    
    # Create default users
    default_users = [
        ('admin', UserRole.ADMIN),
        ('owner', UserRole.OWNER),
        ('viewer', UserRole.VIEWER)
    ]
    
    for username, role in default_users:
        print(f"\nCreating {role.value} user: {username}")
        while True:
            password = getpass.getpass(f"Enter password for {username}: ")
            if len(password) < 12:
                print("Password must be at least 12 characters long")
                continue
            if not any(c.isupper() for c in password):
                print("Password must contain at least one uppercase letter")
                continue
            if not any(c.islower() for c in password):
                print("Password must contain at least one lowercase letter")
                continue
            if not any(c.isdigit() for c in password):
                print("Password must contain at least one number")
                continue
            if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
                print("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
                continue
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match")
                continue
            break
        
        # Hash password
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)  # Increased rounds for better security
        password_hash = bcrypt.hashpw(password_bytes, salt)
        
        # Create user
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=password_hash.decode('utf-8'),
            role=role,
            created_at=time.time(),
            artifacts=[],
            failed_login_attempts=0,
            last_login_attempt=0
        )
        
        # Insert into database
        c.execute('''
        INSERT INTO users (id, username, password_hash, role, created_at, artifacts, 
                         failed_login_attempts, last_login_attempt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user.id,
            user.username,
            user.password_hash,
            user.role.value,
            user.created_at,
            ','.join(user.artifacts),
            user.failed_login_attempts,
            user.last_login_attempt
        ))
        
        print(f"Created {role.value} user: {username}")
    
    conn.commit()
    conn.close()
    print("\nDatabase initialized successfully!")

if __name__ == '__main__':
    init_db() 