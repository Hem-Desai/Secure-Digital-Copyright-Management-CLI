from enum import Enum
from typing import Dict, List, Optional
from ..models.user import User, UserRole

class Permission(Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"

class RBACManager:
    def __init__(self):
        # Define permission matrix for each role
        self._permissions: Dict[UserRole, List[Permission]] = {
            UserRole.ADMIN: [
                Permission.CREATE, Permission.READ,
                Permission.UPDATE, Permission.DELETE,
                Permission.LIST
            ],
            UserRole.OWNER: [
                Permission.READ, Permission.UPDATE,
                Permission.DELETE, Permission.LIST
            ],
            UserRole.VIEWER: [Permission.READ, Permission.LIST]
        }
    
    def check_permission(self, user: User, permission: Permission, 
                        resource_id: Optional[str] = None) -> bool:
        """
        Check if user has the required permission
        If resource_id is provided, also check ownership for OWNER role
        """
        if user.role == UserRole.ADMIN:
            return True
            
        if permission not in self._permissions[user.role]:
            return False
            
        # For OWNER role, check resource ownership
        if (user.role == UserRole.OWNER and 
            resource_id is not None and 
            resource_id not in user.artifacts):
            return False
            
        return True 