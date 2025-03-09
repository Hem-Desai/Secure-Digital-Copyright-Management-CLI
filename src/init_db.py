import sqlite3
import os
import sys
import bcrypt
import time
import uuid
import getpass
import re

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.user import User, UserRole
from src.storage.db_storage import DATABASE_PATH

def validate_password(password: str) -> bool:
    """
    Validate password strength requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character from: !@#$%^&*(),.?":{}|<>
    - No common patterns or repeated characters
    """
    if len(password) < 12:
        return False
        
    if not re.search(r"[A-Z]", password):
        return False
        
    if not re.search(r"[a-z]", password):
        return False
        
    if not re.search(r"\d", password):
        return False
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
        
    # Check for common patterns and repeated characters
    common_patterns = [
        r"12345", r"qwerty", r"password", r"admin",
        r"([a-zA-Z0-9])\1{2,}",  # Repeated characters
        r"abc", r"123", r"admin", r"user", r"login",
        r"test", r"demo", r"guest", r"default"
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False
            
    return True

def init_db():
    # Create database directory if it doesn't exist
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # Drop existing tables
    c.execute('DROP TABLE IF EXISTS user_artifacts')
    c.execute('DROP TABLE IF EXISTS artifacts')
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('DROP TABLE IF EXISTS audit_log')
    
    # Create users table
    c.execute('''
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at REAL NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        last_login_attempt REAL DEFAULT 0,
        account_locked BOOLEAN DEFAULT 0,
        password_last_changed REAL NOT NULL
    )
    ''')
    
    # Create artifacts table
    c.execute('''
    CREATE TABLE artifacts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        content_type TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        created_at REAL NOT NULL,
        encryption_key_id TEXT NOT NULL,
        checksum TEXT NOT NULL,
        encrypted_content BLOB NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )
    ''')
    
    # Create user_artifacts table
    c.execute('''
    CREATE TABLE user_artifacts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
    )
    ''')
    
    # Create audit_log table
    c.execute('''
    CREATE TABLE audit_log (
        id TEXT PRIMARY KEY,
        timestamp REAL NOT NULL,
        user_id TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
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
            print("\nPassword requirements:")
            print("- Minimum 12 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter")
            print("- At least one number")
            print("- At least one special character (!@#$%^&*(),.?\":{}|<>)")
            print("- No common patterns (e.g., 12345, qwerty, password)")
            print("- No repeated characters (3 or more of the same character)")
            print("- No common words (e.g., admin, user, login, test)")
            
            password = getpass.getpass(f"\nEnter password for {username}: ")
            confirm = getpass.getpass("Confirm password: ")
            
            if password != confirm:
                print("\nPasswords do not match. Please try again.")
                continue
                
            if not validate_password(password):
                print("\nPassword does not meet complexity requirements. Please try again.")
                continue
                
            break
        
        # Hash password
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt)
        
        # Create user
        created_at = time.time()
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=password_hash.decode(),
            role=role,
            created_at=created_at,
            artifacts=[],
            failed_login_attempts=0,
            last_login_attempt=0,
            account_locked=False,
            password_last_changed=created_at
        )
        
        # Insert into database
        c.execute('''
        INSERT INTO users (id, username, password_hash, role, created_at, failed_login_attempts, 
                         last_login_attempt, account_locked, password_last_changed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user.id,
            user.username,
            user.password_hash,
            user.role.value,
            user.created_at,
            user.failed_login_attempts,
            user.last_login_attempt,
            user.account_locked,
            user.password_last_changed
        ))
        
        print(f"Created {role.value} user: {username}")
    
    conn.commit()
    conn.close()
    print("\nDatabase initialized successfully!")

if __name__ == '__main__':
    init_db() 