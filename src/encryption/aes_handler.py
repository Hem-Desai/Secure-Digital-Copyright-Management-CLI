from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import uuid
from typing import Dict, Tuple, Optional

from .encryption_strategy import EncryptionStrategy

class AESHandler(EncryptionStrategy):
    def __init__(self):
        self._keys: Dict[str, bytes] = {}
        
    def generate_key(self) -> Tuple[str, bytes]:
        """Generate a new Fernet key with AES-256"""
        try:
            key = Fernet.generate_key()
            key_id = str(uuid.uuid4())
            self._keys[key_id] = key
            print(f"Generated key {key_id} successfully")
            return key_id, key
        except Exception as e:
            print(f"Error generating key: {str(e)}")
            raise
        
    def encrypt(self, data: bytes, key_id: str) -> Optional[bytes]:
        """Encrypt data using the specified key"""
        try:
            if key_id not in self._keys:
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