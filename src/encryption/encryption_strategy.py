from abc import ABC, abstractmethod
from typing import Tuple, Optional

class EncryptionStrategy(ABC):
    """Abstract base class for encryption strategies"""
    
    @abstractmethod
    def generate_key(self) -> Tuple[str, bytes]:
        """Generate a new encryption key"""
        pass
    
    @abstractmethod
    def encrypt(self, data: bytes, key_id: str) -> Optional[bytes]:
        """Encrypt data using the specified key"""
        pass
    
    @abstractmethod
    def decrypt(self, encrypted_data: bytes, key_id: str) -> Optional[bytes]:
        """Decrypt data using the specified key"""
        pass 