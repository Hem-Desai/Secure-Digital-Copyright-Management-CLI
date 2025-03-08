import sqlite3
import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib
from ..utils.logging import AuditLogger

class SQLiteStorage:
    # Define table schemas as class attribute
    _TABLE_SCHEMAS = {
        'users': {
            'columns': ['id', 'username', 'password_hash', 'role', 'created_at', 
                      'failed_login_attempts', 'last_login_attempt', 'account_locked',
                      'password_last_changed'],
            'query': '''CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at REAL NOT NULL,
                failed_login_attempts INTEGER DEFAULT 0,
                last_login_attempt REAL DEFAULT 0,
                account_locked BOOLEAN DEFAULT 0,
                password_last_changed REAL NOT NULL
            )'''
        },
        'artifacts': {
            'columns': ['id', 'name', 'content_type', 'owner_id', 'file_size',
                      'created_at', 'encryption_key_id', 'checksum', 'encrypted_content'],
            'query': '''CREATE TABLE IF NOT EXISTS artifacts (
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
            )'''
        },
        'user_artifacts': {
            'columns': ['id', 'user_id', 'artifact_id'],
            'query': '''CREATE TABLE IF NOT EXISTS user_artifacts (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
            )'''
        },
        'audit_log': {
            'columns': ['id', 'timestamp', 'user_id', 'action', 'details', 'ip_address'],
            'query': '''CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )'''
        }
    }

    # Define static queries as class attribute
    _STATIC_QUERIES = {
        'users': {
            'select_by_id': 'SELECT * FROM users WHERE id = ?',
            'select_by_username': 'SELECT * FROM users WHERE username = ?',
            'select_all': 'SELECT * FROM users',
            'delete': 'DELETE FROM users WHERE id = ?'
        },
        'artifacts': {
            'select_by_id': 'SELECT * FROM artifacts WHERE id = ?',
            'select_all': 'SELECT * FROM artifacts',
            'delete': 'DELETE FROM artifacts WHERE id = ?'
        },
        'user_artifacts': {
            'select_by_id': 'SELECT * FROM user_artifacts WHERE id = ?',
            'select_all': 'SELECT * FROM user_artifacts',
            'delete': 'DELETE FROM user_artifacts WHERE id = ?'
        },
        'audit_log': {
            'select_by_id': 'SELECT * FROM audit_log WHERE id = ?',
            'select_all': 'SELECT * FROM audit_log',
            'delete': 'DELETE FROM audit_log WHERE id = ?'
        }
    }

    def __init__(self, db_path: str = "data/users.db"):
        """Initialize database connection"""
        self.db_path = db_path
        self.logger = AuditLogger()
        self._ensure_db_exists()
        
    def _ensure_db_exists(self):
        """Ensure database directory and file exist"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        if not os.path.exists(self.db_path):
            self._init_db()
            
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for table_info in self._TABLE_SCHEMAS.values():
                cursor.execute(table_info['query'])
            conn.commit()
            
    def _validate_table_name(self, table: str) -> bool:
        """Validate table name against schema"""
        return table in self._TABLE_SCHEMAS
        
    def _validate_column_names(self, table: str, columns: List[str]) -> bool:
        """Validate column names against schema"""
        if table not in self._TABLE_SCHEMAS:
            return False
        valid_columns = set(self._TABLE_SCHEMAS[table]['columns'])
        return all(col in valid_columns for col in columns)
        
    def _build_insert_query(self, table: str, columns: List[str]) -> str:
        """Build INSERT query using static strings"""
        if not self._validate_table_name(table) or not self._validate_column_names(table, columns):
            raise ValueError("Invalid table or column names")
        placeholders = ','.join('?' * (len(columns) + 1))
        columns_str = ','.join(['id'] + columns)
        return f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders})"  # nosec
        
    def _build_update_query(self, table: str, columns: List[str]) -> str:
        """Build UPDATE query using static strings"""
        if not self._validate_table_name(table) or not self._validate_column_names(table, columns):
            raise ValueError("Invalid table or column names")
        set_clause = ','.join(f"{col} = ?" for col in columns)
        return f"UPDATE {table} SET {set_clause} WHERE id = ?"  # nosec
        
    def create(self, data: Dict[str, Any]) -> bool:
        """Create a new record using prepared statement"""
        try:
            table = data.pop("table", None)
            if not table or not self._validate_table_name(table):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid table name", "table": table})
                return False
                
            id = data.get("id")
            if not id:
                self.logger.log_system_event("security_violation", 
                    {"error": "Missing ID field"})
                return False
                
            columns = list(data.keys())
            if not self._validate_column_names(table, columns):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid column names", "columns": columns})
                return False
                
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = self._build_insert_query(table, columns)
                values = [id] + [data[col] for col in columns]
                cursor.execute(query, values)
                conn.commit()
                return True
                
        except (sqlite3.Error, ValueError) as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return False
            
    def read(self, id: str, table: str) -> Optional[Dict[str, Any]]:
        """Read a record using prepared statement"""
        try:
            if not self._validate_table_name(table):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid table name", "table": table})
                return None
                
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                query = self._STATIC_QUERIES[table]['select_by_id']
                cursor.execute(query, (id,))
                row = cursor.fetchone()
                return dict(row) if row else None
                
        except sqlite3.Error as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return None
            
    def update(self, data: Dict[str, Any]) -> bool:
        """Update a record using prepared statement"""
        try:
            table = data.pop("table", None)
            if not table or not self._validate_table_name(table):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid table name", "table": table})
                return False
                
            id = data.pop("id", None)
            if not id:
                self.logger.log_system_event("security_violation", 
                    {"error": "Missing ID field"})
                return False
                
            columns = list(data.keys())
            if not self._validate_column_names(table, columns):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid column names", "columns": list(data.keys())})
                return False
                
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = self._build_update_query(table, columns)
                values = list(data.values()) + [id]
                cursor.execute(query, values)
                conn.commit()
                return cursor.rowcount > 0
                
        except (sqlite3.Error, ValueError) as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return False
            
    def delete(self, id: str, table: str) -> bool:
        """Delete a record using prepared statement"""
        try:
            if not self._validate_table_name(table):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid table name", "table": table})
                return False
                
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = self._STATIC_QUERIES[table]['delete']
                cursor.execute(query, (id,))
                conn.commit()
                return cursor.rowcount > 0
                
        except sqlite3.Error as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return False
            
    def list(self, table: str) -> List[Dict[str, Any]]:
        """List all records from a table using prepared statement"""
        try:
            if not self._validate_table_name(table):
                self.logger.log_system_event("security_violation", 
                    {"error": "Invalid table name", "table": table})
                return []

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                if table == 'artifacts':
                    # For artifacts, select all fields
                    cursor.execute('''SELECT id, name, content_type, owner_id, file_size, 
                                    created_at, encryption_key_id, checksum, encrypted_content 
                                    FROM artifacts''')
                else:
                    # For other tables, use the standard select all query
                    query = self._STATIC_QUERIES[table]['select_all']
                    cursor.execute(query)
                    
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

        except sqlite3.Error as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return []
            
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username using prepared statement"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                query = self._STATIC_QUERIES['users']['select_by_username']
                cursor.execute(query, (username,))
                row = cursor.fetchone()
                return dict(row) if row else None
                
        except sqlite3.Error as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return None
            
    def get_user_artifacts(self, user_id: str) -> List[str]:
        """Get user's artifacts using parameterized query"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT artifact_id FROM user_artifacts WHERE user_id = ?",
                    (user_id,)
                )
                return [row[0] for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return []
            
    def update_login_attempt(self, username: str, success: bool) -> bool:
        """Update login attempt status using parameterized query"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if success:
                    cursor.execute("""
                        UPDATE users 
                        SET failed_login_attempts = 0,
                            last_login_attempt = ?,
                            account_locked = 0
                        WHERE username = ?
                    """, (datetime.now().timestamp(), username))
                else:
                    cursor.execute("""
                        UPDATE users 
                        SET failed_login_attempts = failed_login_attempts + 1,
                            last_login_attempt = ?,
                            account_locked = CASE 
                                WHEN failed_login_attempts >= 4 THEN 1 
                                ELSE account_locked 
                            END
                        WHERE username = ?
                    """, (datetime.now().timestamp(), username))
                conn.commit()
                return True
                
        except sqlite3.Error as e:
            self.logger.log_system_event("database_error", {"error": str(e)})
            return False 