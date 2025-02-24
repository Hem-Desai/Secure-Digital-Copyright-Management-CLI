from datetime import datetime
from typing import Optional, Tuple
import hashlib
import os

from .jwt_handler import JWTHandler
from ..models.user import User, UserRole
from ..utils.logging import AuditLogger

class AuthService:
    def __init__(self):
        self.jwt_handler = JWTHandler()
        self.logger = AuditLogger()
        
    def login(self, username: str, password: str, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Authenticate user and return JWT token
        Returns (success, token)
        """
        # In production, verify against database
        # For demo, use hardcoded admin
        if username == "admin" and password == "admin":
            user_id = "admin"
            token = self.jwt_handler.generate_token(user_id, UserRole.ADMIN.value)
            self.logger.log_auth_attempt(user_id, True, ip_address)
            return True, token
            
        self.logger.log_auth_attempt(username, False, ip_address)
        return False, None
        
    def verify_token(self, token: str) -> Optional[User]:
        """Verify JWT token and return User object"""
        payload = self.jwt_handler.validate_token(token)
        if not payload:
            return None
            
        # In production, get user from database
        # For demo, return admin user
        if payload["user_id"] == "admin":
            return User(
                id="admin",
                username="admin",
                password_hash="admin",
                role=UserRole.ADMIN,
                created_at=0,
                artifacts=[]
            )
            
        return None 