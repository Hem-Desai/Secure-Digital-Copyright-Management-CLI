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
        key = Fernet.generate_key()
        key_id = str(uuid.uuid4())
        self._keys[key_id] = key
        return key_id, key
        
    def encrypt(self, data: bytes, key_id: str) -> Optional[bytes]:
        """Encrypt data using the specified key"""
        if key_id not in self._keys:
            return None
            
        f = Fernet(self._keys[key_id])
        return f.encrypt(data)
        
    def decrypt(self, encrypted_data: bytes, key_id: str) -> Optional[bytes]:
        """Decrypt data using the specified key"""
        if key_id not in self._keys:
            return None
            
        try:
            f = Fernet(self._keys[key_id])
            return f.decrypt(encrypted_data)
        except Exception:
            return None 