from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum

class ContentType(Enum):
    LYRICS = "lyrics"
    SCORE = "score"
    AUDIO_MP3 = "audio/mp3"
    AUDIO_WAV = "audio/wav"
    VIDEO_MP4 = "video/mp4"
    VIDEO_AVI = "video/avi"
    DOCUMENT = "document"
    OTHER = "other"

    @classmethod
    def from_extension(cls, extension: str) -> 'ContentType':
        """Get content type from file extension"""
        extension = extension.lower().lstrip('.')
        mapping = {
            'mp3': cls.AUDIO_MP3,
            'wav': cls.AUDIO_WAV,
            'mp4': cls.VIDEO_MP4,
            'avi': cls.VIDEO_AVI,
            'txt': cls.LYRICS,
            'pdf': cls.SCORE,
            'doc': cls.DOCUMENT,
            'docx': cls.DOCUMENT
        }
        return mapping.get(extension, cls.OTHER)

@dataclass
class Artifact:
    id: str
    name: str
    content_type: str
    owner_id: str
    created_at: float
    modified_at: float
    checksum: str
    encrypted_content: bytes
    encryption_key_id: str
    file_size: int
    metadata: Dict[str, Any] = None  # For media-specific metadata
    
    @property
    def info(self) -> dict:
        """Return artifact metadata without sensitive content"""
        base_info = {
            'id': self.id,
            'name': self.name,
            'content_type': self.content_type,
            'owner_id': self.owner_id,
            'created_at': datetime.fromtimestamp(self.created_at).isoformat(),
            'modified_at': datetime.fromtimestamp(self.modified_at).isoformat(),
            'checksum': self.checksum,
            'file_size': self.file_size
        }
        
        # Add media-specific metadata if available
        if self.metadata:
            base_info['metadata'] = self.metadata
            
        return base_info 