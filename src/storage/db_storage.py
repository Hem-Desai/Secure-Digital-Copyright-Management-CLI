import sqlite3
from typing import Any, List, Optional, Dict
import json
from .storage_interface import StorageInterface

class SQLiteStorage(StorageInterface):
    def __init__(self, db_path: str = "secure_dcm.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
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
                    encryption_key_id TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    artifacts TEXT NOT NULL
                )
            """)
            
    def create(self, data: Dict[str, Any]) -> str:
        """Create a new record"""
        table = data.pop("table")
        id = data.pop("id")
        
        placeholders = ",".join(["?"] * len(data))
        columns = ",".join(data.keys())
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                f"INSERT INTO {table} (id,{columns}) VALUES (?,{placeholders})",
                [id] + list(data.values())
            )
        return id
    
    def read(self, id: str, table: str) -> Optional[Dict[str, Any]]:
        """Read a record by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
            
    def update(self, id: str, data: Dict[str, Any]) -> bool:
        """Update a record"""
        table = data.pop("table")
        set_clause = ",".join([f"{k}=?" for k in data.keys()])
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                f"UPDATE {table} SET {set_clause} WHERE id=?",
                list(data.values()) + [id]
            )
            return cursor.rowcount > 0
            
    def delete(self, id: str, table: str) -> bool:
        """Delete a record"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"DELETE FROM {table} WHERE id=?", (id,))
            return cursor.rowcount > 0
            
    def list(self, table: str) -> List[Dict[str, Any]]:
        """List all records"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(f"SELECT * FROM {table}")
            return [dict(row) for row in cursor.fetchall()] 