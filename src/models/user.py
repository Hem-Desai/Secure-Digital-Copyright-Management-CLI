from enum import Enum
from dataclasses import dataclass
from typing import List

class UserRole(Enum):
    ADMIN = "admin"
    OWNER = "owner"
    VIEWER = "viewer"

@dataclass
class User:
    id: str
    username: str
    password_hash: str
    role: UserRole
    created_at: float
    artifacts: List[str]  # List of artifact IDs owned by user
    
    def has_permission(self, action: str, resource: str) -> bool:
        """
        Check if user has permission to perform action on resource
        """
        if self.role == UserRole.ADMIN:
            return True
            
        if self.role == UserRole.OWNER:
            return (action in ['read', 'update', 'delete'] and 
                   resource in self.artifacts)
            
        if self.role == UserRole.VIEWER:
            return action == 'read'
            
        return False 