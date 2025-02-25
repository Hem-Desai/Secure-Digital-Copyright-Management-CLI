import sqlite3
from typing import Any, List, Optional, Dict
import json
from .storage_interface import StorageInterface
from datetime import datetime

class SQLiteStorage(StorageInterface):
    def __init__(self, db_path: str = "secure_dcm.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        """Initialize database tables"""
        try:
            print(f"Initializing database at {self.db_path}")
            with sqlite3.connect(self.db_path) as conn:
                # Enable foreign key support
                conn.execute("PRAGMA foreign_keys = ON")
                print("Enabled foreign key support")
                
                # Create artifacts table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS artifacts (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        content_type TEXT NOT NULL,
                        owner_id TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        modified_at REAL NOT NULL,
                        checksum TEXT NOT NULL,
                        encrypted_content BLOB NOT NULL,
                        encryption_key_id TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        FOREIGN KEY(owner_id) REFERENCES users(id)
                    )
                """)
                print("Created artifacts table")
                
                # Create users table with security fields
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash BLOB NOT NULL,
                        role TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        failed_login_attempts INTEGER DEFAULT 0,
                        last_login_attempt REAL DEFAULT 0,
                        account_locked BOOLEAN DEFAULT 0,
                        password_last_changed REAL NOT NULL,
                        UNIQUE(username)
                    )
                """)
                print("Created users table")
                
                # Create user_artifacts table for many-to-many relationship
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS user_artifacts (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        artifact_id TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id),
                        FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
                    )
                """)
                print("Created user_artifacts table")
                
        except sqlite3.Error as e:
            print(f"Database initialization error: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error during database initialization: {str(e)}")
            raise
            
    def create(self, data: Dict[str, Any]) -> str:
        """Create a new record"""
        try:
            table = data.pop("table")
            id = data.pop("id")
            
            placeholders = ",".join(["?"] * len(data))
            columns = ",".join(data.keys())
            values = [id] + list(data.values())
            
            print(f"Creating record in {table} with ID {id}")
            print(f"Columns: {columns}")
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"INSERT INTO {table} (id,{columns}) VALUES (?,{placeholders})",
                    values
                )
                conn.commit()
                print(f"Successfully created record in {table}")
            return id
            
        except sqlite3.Error as e:
            print(f"Database error in create: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error in create: {str(e)}")
            return None
        
    def read(self, id: str, table: str) -> Optional[Dict[str, Any]]:
        """Read a record"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"SELECT * FROM {table} WHERE id = ?", [id])
            row = cursor.fetchone()
            if row:
                return dict(zip([col[0] for col in cursor.description], row))
        return None
        
    def update(self, id: str, data: Dict[str, Any]) -> bool:
        """Update a record"""
        table = data.pop("table")
        updates = ",".join([f"{k}=?" for k in data.keys()])
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                f"UPDATE {table} SET {updates} WHERE id=?",
                list(data.values()) + [id]
            )
            return cursor.rowcount > 0
            
    def delete(self, id: str, table: str) -> bool:
        """Delete a record"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"DELETE FROM {table} WHERE id=?", [id])
            return cursor.rowcount > 0
            
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                [username]
            )
            row = cursor.fetchone()
            if row:
                return dict(zip([col[0] for col in cursor.description], row))
        return None
        
    def update_login_attempt(self, username: str, success: bool) -> None:
        """Update login attempt tracking"""
        with sqlite3.connect(self.db_path) as conn:
            if success:
                conn.execute("""
                    UPDATE users 
                    SET failed_login_attempts = 0,
                        account_locked = 0
                    WHERE username = ?
                """, [username])
            else:
                conn.execute("""
                    UPDATE users 
                    SET failed_login_attempts = failed_login_attempts + 1,
                        last_login_attempt = ?,
                        account_locked = CASE 
                            WHEN failed_login_attempts >= 5 THEN 1 
                            ELSE account_locked 
                        END
                    WHERE username = ?
                """, [datetime.now().timestamp(), username])
            
    def get_user_artifacts(self, user_id: str) -> List[str]:
        """Get list of artifact IDs owned by user"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT artifact_id FROM user_artifacts WHERE user_id = ?",
                [user_id]
            )
            return [row[0] for row in cursor.fetchall()]

    def list(self, table: str) -> List[Dict[str, Any]]:
        """List all records"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(f"SELECT * FROM {table}")
            return [dict(row) for row in cursor.fetchall()] 