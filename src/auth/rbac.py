import bcrypt
from enum import Enum
from typing import Dict, List, Optional, Tuple
from ..models.user import User, UserRole
from ..storage.db_storage import SQLiteStorage
import re
from datetime import datetime
import sqlite3
import uuid

class Permission(Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    UPLOAD = "upload"

class RBACManager:
    def __init__(self):
        # Define permission matrix for each role
        self._permissions: Dict[UserRole, List[Permission]] = {
            UserRole.ADMIN: [
                Permission.CREATE, Permission.READ,
                Permission.UPDATE, Permission.DELETE,
                Permission.LIST, Permission.UPLOAD
            ],
            UserRole.OWNER: [
                Permission.READ, Permission.UPDATE,
                Permission.DELETE, Permission.LIST,
                Permission.UPLOAD
            ],
            UserRole.VIEWER: [Permission.READ, Permission.LIST]
        }
        
        # Initialize database connection and load users
        self.db = SQLiteStorage()
        self._users = {}
        self._load_users_from_db()
        
    def _load_users_from_db(self):
        """Load users from database into memory"""
        users = self.db.list("users")
        for user_data in users:
            user = User(
                id=user_data["id"],
                username=user_data["username"],
                password_hash=user_data["password_hash"],
                role=UserRole(user_data["role"]),
                created_at=user_data["created_at"],
                artifacts=self.db.get_user_artifacts(user_data["id"]),
                failed_login_attempts=user_data.get("failed_login_attempts", 0),
                last_login_attempt=user_data.get("last_login_attempt", 0)
            )
            self._users[user.username] = user
        
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
            
        user_id = f"{username}_{datetime.now().timestamp()}"
        password_hash = self._hash_password(password)
        
        user = User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role,
            created_at=datetime.now().timestamp(),
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
        print(f"Checking permission {permission.value} for user {user.username} with role {user.role}")
        
        # Admin has all permissions
        if user.role == UserRole.ADMIN:
            print("User is admin, granting permission")
            return True
            
        # Check if role has the permission
        if permission not in self._permissions[user.role]:
            print(f"Role {user.role} does not have permission {permission.value}")
            return False
            
        # For OWNER role, check resource ownership if resource_id is provided
        if (user.role == UserRole.OWNER and 
            resource_id is not None and 
            permission not in [Permission.UPLOAD, Permission.LIST] and  # Skip ownership check for UPLOAD and LIST
            resource_id not in user.artifacts):
            print(f"User does not own resource {resource_id}")
            return False
            
        print("Permission granted")
        return True

    def add_artifact_to_owner(self, user_id: str, artifact_id: str) -> bool:
        """Add an artifact to a user's owned artifacts"""
        try:
            # Find user by ID
            user = None
            for u in self._users.values():
                if u.id == user_id:
                    user = u
                    break

            if not user or user.role != UserRole.OWNER:
                print(f"User {user_id} is not an owner or does not exist")
                return False

            # Generate a unique ID for the user_artifacts entry
            entry_id = str(uuid.uuid4())
            
            # Add entry to user_artifacts table
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO user_artifacts (id, user_id, artifact_id) VALUES (?, ?, ?)",
                    (entry_id, user_id, artifact_id)
                )
                conn.commit()
                
            # Add to in-memory cache
            if not hasattr(user, 'artifacts'):
                user.artifacts = []
            user.artifacts.append(artifact_id)
            return True
            
        except sqlite3.Error as e:
            print(f"Database error while adding artifact to owner: {str(e)}")
            return False
        except Exception as e:
            print(f"Error adding artifact to owner: {str(e)}")
            return False

    def remove_artifact_from_owner(self, user_id: str, artifact_id: str) -> bool:
        """Remove an artifact from a user's owned artifacts"""
        try:
            # Check if user exists and has OWNER role
            user = self._users.get(user_id)
            if not user or user.role != UserRole.OWNER:
                print(f"User {user_id} is not an owner or does not exist")
                return False

            # Remove entry from user_artifacts table
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM user_artifacts WHERE user_id = ? AND artifact_id = ?",
                    (user_id, artifact_id)
                )
                conn.commit()

            # Remove from in-memory cache
            if hasattr(user, 'artifacts') and artifact_id in user.artifacts:
                user.artifacts.remove(artifact_id)
            return True

        except sqlite3.Error as e:
            print(f"Database error while removing artifact from owner: {str(e)}")
            return False
        except Exception as e:
            print(f"Error removing artifact from owner: {str(e)}")
            return False 