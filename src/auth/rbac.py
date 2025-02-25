import bcrypt
from enum import Enum
from typing import Dict, List, Optional, Tuple
from ..models.user import User, UserRole
import re
from datetime import datetime

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
        
        # Initialize empty users dict - will be populated from database
        self._users = {}
        
    def _validate_password(self, password: str) -> bool:
        """
        Validate password complexity requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
        """
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True
    
    def _hash_password(self, password: str) -> bytes:
        """Hash password using bcrypt with salt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt)
    
    def create_user(self, username: str, password: str, role: UserRole) -> Optional[User]:
        """Create a new user with secure password"""
        if not self._validate_password(password):
            return None
            
        if username in self._users:
            return None
            
        user_id = f"{username}_{datetime.utcnow().timestamp()}"
        password_hash = self._hash_password(password)
        
        user = User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
        self._users[username] = user
        return user
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials using bcrypt"""
        user = self._users.get(username)
        if not user:
            return None
            
        try:
            if bcrypt.checkpw(password.encode(), user.password_hash):
                return user
        except Exception:
            pass
        return None
    
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

    def add_artifact_to_owner(self, user: User, artifact_id: str) -> bool:
        """Add artifact to owner's list of artifacts"""
        if user.role == UserRole.OWNER:
            if user.username in self._users:
                self._users[user.username].artifacts.append(artifact_id)
                return True
        return False 