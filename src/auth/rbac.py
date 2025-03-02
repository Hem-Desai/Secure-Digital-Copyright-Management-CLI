import bcrypt
from enum import Enum
from typing import Dict, List, Optional, Tuple
from ..models.user import User, UserRole
from ..storage.db_storage import SQLiteStorage
import re
from datetime import datetime
import sqlite3
import uuid
import os

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
        
        # Create default users if they don't exist
        self._create_default_users()
        
    def _create_default_users(self):
        """Create default users with secure passwords if they don't exist"""
        default_users = [
            ("admin", "Adm!nCtr1#2024", UserRole.ADMIN),
            ("owner", "Own3rSh!p$2024", UserRole.OWNER),
            ("viewer", "V!ewUs3r@2024", UserRole.VIEWER)
        ]
        
        for username, password, role in default_users:
            if not self.db.get_user_by_username(username):
                user = self.create_user(username, password, role)
                if user:
                    self.db.create({
                        "table": "users",
                        "id": user.id,
                        "username": user.username,
                        "password_hash": user.password_hash,
                        "role": user.role.value,
                        "created_at": user.created_at,
                        "password_last_changed": datetime.now().timestamp()
                    })

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
        
    def validate_password(self, password: str) -> bool:
        """
        Validate password strength requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character from: !@#$%^&*(),.?":{}|<>
        - No common patterns or repeated characters
        """
        if len(password) < 12:
            return False
            
        if not re.search(r"[A-Z]", password):
            return False
            
        if not re.search(r"[a-z]", password):
            return False
            
        if not re.search(r"\d", password):
            return False
            
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
            
        # Check for common patterns and repeated characters
        common_patterns = [
            r"12345", r"qwerty", r"password", r"admin",
            r"([a-zA-Z0-9])\1{2,}",  # Repeated characters
            r"abc", r"123", r"admin", r"user", r"login",
            r"test", r"demo", r"guest", r"default"
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                return False
                
        return True
        
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt with increased work factor (12 rounds)
        Uses constant-time comparison to prevent timing attacks
        """
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()
        
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash using constant-time comparison
        to prevent timing attacks
        """
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False
            
    def create_user(self, username: str, password: str, role: UserRole) -> Optional[User]:
        """Create a new user with secure password"""
        if not self.validate_password(password):
            return None
            
        # Generate secure user ID
        user_id = os.urandom(16).hex()
        
        # Hash password with increased security
        password_hash = self.hash_password(password)
        
        # Create user with current timestamp
        created_at = datetime.now().timestamp()
        
        return User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role,
            created_at=created_at
        )
        
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user and verify password"""
        user_data = self.db.get_user_by_username(username)
        if not user_data:
            return None
            
        # Check for account lockout
        if user_data.get("account_locked"):
            return None
            
        # Verify password with constant-time comparison
        if self.verify_password(password, user_data["password_hash"]):
            return User(
                id=user_data["id"],
                username=user_data["username"],
                password_hash=user_data["password_hash"],
                role=UserRole(user_data["role"]),
                created_at=user_data["created_at"]
            )
            
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