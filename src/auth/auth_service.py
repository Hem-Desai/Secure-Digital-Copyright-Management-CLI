from datetime import datetime
from typing import Optional, Tuple
import bcrypt
import time
import uuid
import os

from .jwt_handler import JWTHandler
from ..models.user import User, UserRole
from ..utils.logging import AuditLogger
from src.database.db import Database

class AuthService:
    def __init__(self, db: Database):
        self.jwt_handler = JWTHandler()
        self.logger = AuditLogger()
        self.db = db
        
    def create_user(self, username: str, password: str, role: UserRole) -> User:
        """Create a new user with hashed password"""
        # Hash password with increased security
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password_bytes, salt)
        
        # Create user
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=password_hash.decode('utf-8'),
            role=role,
            created_at=time.time(),
            artifacts=[],
            failed_login_attempts=0,
            last_login_attempt=0
        )
        
        # Save to database
        self.db.save_user(user)
        return user
        
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        user = self.db.get_user(username)
        if not user:
            # Use constant time comparison even for non-existent users
            bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())
            return None
            
        # Check password using constant-time comparison
        try:
            password_bytes = password.encode('utf-8')
            stored_hash = user.password_hash.encode('utf-8')
            
            if bcrypt.checkpw(password_bytes, stored_hash):
                # Reset failed attempts on success
                user.failed_login_attempts = 0
                user.last_login_attempt = time.time()
                self.db.update_user(user)
                return user
                
            # Track failed attempt
            user.failed_login_attempts += 1
            user.last_login_attempt = time.time()
            self.db.update_user(user)
            return None
            
        except Exception:
            # If any error occurs during verification, fail securely
            return None
        
    def login(self, username: str, password: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Authenticate user and return JWT token
        Returns (success, token)
        """
        user = self.authenticate(username, password)
        if user:
            token = self.jwt_handler.generate_token(user.id, user.role.value)
            self.logger.log_auth_attempt(user.id, True, ip_address)
            return True, token
            
        self.logger.log_auth_attempt(username, False, ip_address)
        return False, None
        
    def verify_token(self, token: str) -> Optional[User]:
        """Verify JWT token and return User object"""
        payload = self.jwt_handler.validate_token(token)
        if not payload:
            return None
            
        user_id = payload.get("user_id")
        if not user_id:
            return None
            
        return self.db.get_user_by_id(user_id) 