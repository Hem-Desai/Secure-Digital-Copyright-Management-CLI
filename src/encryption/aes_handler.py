from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import uuid
import sqlite3
from typing import Dict, Tuple, Optional
from datetime import datetime
from ..storage.db_storage import DATABASE_PATH

from .encryption_strategy import EncryptionStrategy

class AESHandler(EncryptionStrategy):
    """Handles AES encryption/decryption of files"""
    
    def __init__(self):
        """Initialize encryption handler"""
        self._keys: Dict[str, bytes] = {}  # In-memory key storage
        self.db_path = DATABASE_PATH
        self._load_keys_from_db()
        
    def _load_keys_from_db(self):
        """Load encryption keys from database"""
        try:
            # Create encryption_keys table if it doesn't exist
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS encryption_keys (
                        id TEXT PRIMARY KEY,
                        key_data BLOB NOT NULL,
                        created_at REAL NOT NULL
                    )
                """)
                
            # Load existing keys
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id, key_data FROM encryption_keys")
                for key_id, key_data in cursor.fetchall():
                    self._keys[key_id] = key_data
                    
        except Exception as e:
            print(f"Error loading keys from database: {str(e)}")
        
    def generate_key(self) -> Tuple[str, bytes]:
        """Generate a new Fernet key with AES-256"""
        try:
            key = Fernet.generate_key()
            key_id = str(uuid.uuid4())
            
            # Store in memory
            self._keys[key_id] = key
            
            # Store in database
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO encryption_keys (id, key_data, created_at) VALUES (?, ?, ?)",
                        (key_id, key, datetime.now().timestamp())
                    )
            except Exception as e:
                print(f"Error storing key in database: {str(e)}")
                # Remove from memory if db storage fails
                self._keys.pop(key_id, None)
                raise
                
            print(f"Generated key {key_id} successfully")
            return key_id, key
        except Exception as e:
            print(f"Error generating key: {str(e)}")
            raise
        
    def encrypt(self, data: bytes, key_id: str) -> Optional[bytes]:
        """Encrypt data using the specified key"""
        try:
            if key_id not in self._keys:
                # Try to load from database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("SELECT key_data FROM encryption_keys WHERE id = ?", (key_id,))
                    result = cursor.fetchone()
                    if result:
                        self._keys[key_id] = result[0]
                    else:
                        print(f"Key {key_id} not found in key store")
                        return None
                
            key = self._keys[key_id]
            print(f"Retrieved key {key_id} from key store")
            
            f = Fernet(key)
            encrypted = f.encrypt(data)
            print(f"Successfully encrypted {len(data)} bytes of data")
            return encrypted
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return None
        
    def decrypt(self, encrypted_data: bytes, key_id: str) -> Optional[bytes]:
        """Decrypt data using the specified key"""
        try:
            if key_id not in self._keys:
                # Try to load from database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("SELECT key_data FROM encryption_keys WHERE id = ?", (key_id,))
                    result = cursor.fetchone()
                    if result:
                        self._keys[key_id] = result[0]
                    else:
                        print(f"Key {key_id} not found in key store")
                        return None
                
            key = self._keys[key_id]
            print(f"Retrieved key {key_id} from key store")
            
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_data)
            print(f"Successfully decrypted {len(encrypted_data)} bytes of data")
            return decrypted
            
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return None 