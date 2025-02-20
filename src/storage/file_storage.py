import os
import shutil
from pathlib import Path
from typing import Optional, BinaryIO
from ..utils.checksum import generate_checksum

class FileStorage:
    def __init__(self, base_path: str = "secure_storage"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
    def _get_file_path(self, file_id: str) -> Path:
        """Get the full path for a file ID"""
        return self.base_path / file_id
        
    def save_file(self, file_id: str, content: bytes) -> bool:
        """Save encrypted content to file system"""
        try:
            file_path = self._get_file_path(file_id)
            with open(file_path, 'wb') as f:
                f.write(content)
            return True
        except Exception:
            return False
            
    def read_file(self, file_id: str) -> Optional[bytes]:
        """Read encrypted content from file system"""
        try:
            file_path = self._get_file_path(file_id)
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception:
            return None
            
    def delete_file(self, file_id: str) -> bool:
        """Delete file from file system"""
        try:
            file_path = self._get_file_path(file_id)
            if file_path.exists():
                file_path.unlink()
            return True
        except Exception:
            return False
            
    def get_checksum(self, file_id: str) -> Optional[str]:
        """Calculate checksum of stored file"""
        content = self.read_file(file_id)
        if content:
            return generate_checksum(content)
        return None 