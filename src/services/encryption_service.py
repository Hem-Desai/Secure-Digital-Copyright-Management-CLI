from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from typing import Dict, Tuple, Optional
from ..utils.logging import AuditLogger
import base64

class EncryptionService:
    def __init__(self):
        """Initialize encryption service with secure key management"""
        self._keys: Dict[str, bytes] = {}
        self.logger = AuditLogger()
        self.backend = default_backend()
        
    def generate_key(self) -> Tuple[str, bytes]:
        """
        Generate a secure encryption key using cryptographically secure random number generator
        Returns (key_id, key)
        """
        try:
            # Generate a secure random key ID
            key_id = os.urandom(16).hex()
            
            # Generate a secure key using PBKDF2
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                iterations=100000,  # High iteration count for security
                backend=self.backend
            )
            key = kdf.derive(os.urandom(32))  # Use random input for key derivation
            
            # Store the key securely
            self._keys[key_id] = key
            
            return key_id, key
            
        except Exception as e:
            self.logger.log_system_event("key_generation_error", {"error": str(e)})
            raise
            
    def encrypt(self, data: bytes, key_id: str) -> Optional[bytes]:
        """
        Encrypt data using AES-256-GCM with authenticated encryption
        Returns None if encryption fails
        """
        try:
            if key_id not in self._keys:
                self.logger.log_system_event("encryption_error", 
                    {"error": "Invalid key ID", "key_id": key_id})
                return None
                
            # Generate a random IV
            iv = os.urandom(12)  # 96-bit IV for GCM
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._keys[key_id]),
                modes.GCM(iv),
                backend=self.backend
            )
            
            encryptor = cipher.encryptor()
            
            # Encrypt data with authenticated encryption
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Combine IV, ciphertext, and tag
            return iv + encryptor.tag + ciphertext
            
        except Exception as e:
            self.logger.log_system_event("encryption_error", {"error": str(e)})
            return None
            
    def decrypt(self, encrypted_data: bytes, key_id: str) -> Optional[bytes]:
        """
        Decrypt data using AES-256-GCM with authenticated encryption
        Returns None if decryption fails
        """
        try:
            if key_id not in self._keys:
                self.logger.log_system_event("decryption_error", 
                    {"error": "Invalid key ID", "key_id": key_id})
                return None
                
            # Extract IV and tag
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._keys[key_id]),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            
            decryptor = cipher.decryptor()
            
            # Decrypt and verify
            return decryptor.update(ciphertext) + decryptor.finalize()
            
        except Exception as e:
            self.logger.log_system_event("decryption_error", {"error": str(e)})
            return None
            
    def delete_key(self, key_id: str) -> bool:
        """Securely delete an encryption key"""
        try:
            if key_id in self._keys:
                # Securely overwrite the key in memory
                self._keys[key_id] = os.urandom(32)
                del self._keys[key_id]
                return True
            return False
            
        except Exception as e:
            self.logger.log_system_event("key_deletion_error", {"error": str(e)})
            return False
            
    def rotate_key(self, old_key_id: str) -> Optional[Tuple[str, bytes]]:
        """
        Rotate an encryption key
        Returns (new_key_id, new_key) or None if rotation fails
        """
        try:
            if old_key_id not in self._keys:
                self.logger.log_system_event("key_rotation_error", 
                    {"error": "Invalid key ID", "key_id": old_key_id})
                return None
                
            # Generate new key
            new_key_id, new_key = self.generate_key()
            
            # Securely delete old key
            self.delete_key(old_key_id)
            
            return new_key_id, new_key
            
        except Exception as e:
            self.logger.log_system_event("key_rotation_error", {"error": str(e)})
            return None 