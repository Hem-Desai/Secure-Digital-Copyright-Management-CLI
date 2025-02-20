from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Artifact:
    id: str
    name: str
    content_type: str  # e.g., 'lyrics', 'score', 'audio'
    owner_id: str
    created_at: float
    modified_at: float
    checksum: str
    encrypted_content: bytes
    encryption_key_id: str
    
    @property
    def metadata(self) -> dict:
        """Return artifact metadata without sensitive content"""
        return {
            'id': self.id,
            'name': self.name,
            'content_type': self.content_type,
            'owner_id': self.owner_id,
            'created_at': datetime.fromtimestamp(self.created_at).isoformat(),
            'modified_at': datetime.fromtimestamp(self.modified_at).isoformat(),
            'checksum': self.checksum
        } 