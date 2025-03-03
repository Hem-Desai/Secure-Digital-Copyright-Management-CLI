import jwt
from datetime import datetime, timedelta
import os
from typing import Optional, Dict
from ..utils.logging import AuditLogger

class JWTHandler:
    def __init__(self):
        """Initialize JWT handler with secure key generation"""
        # Generate a secure random key for JWT signing
        self.secret_key = os.urandom(32).hex()
        self.logger = AuditLogger()
        
        # Set secure JWT configuration
        self.algorithm = 'HS256'
        self.token_expiry = timedelta(hours=1)  # Short-lived tokens
        self.refresh_token_expiry = timedelta(days=7)
        
    def generate_token(self, user_id: str, role: str) -> str:
        """Generate a secure JWT token with minimal claims"""
        try:
            payload = {
                'user_id': user_id,
                'role': role,
                'exp': datetime.utcnow() + self.token_expiry,
                'iat': datetime.utcnow(),
                'jti': os.urandom(16).hex()  # Unique token ID
            }
            
            return jwt.encode(
                payload,
                self.secret_key,
                algorithm=self.algorithm
            )
        except Exception as e:
            self.logger.log_system_event("token_generation_error", {"error": str(e)})
            raise
            
    def validate_token(self, token: str) -> Optional[Dict]:
        """
        Validate JWT token with security checks
        Returns None if token is invalid or expired
        """
        try:
            # Decode and verify token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require': ['exp', 'iat', 'user_id', 'role', 'jti']
                }
            )
            
            # Additional security checks
            if not all(k in payload for k in ['user_id', 'role', 'exp', 'iat', 'jti']):
                self.logger.log_system_event("token_validation_error", 
                    {"error": "Missing required claims"})
                return None
                
            # Check token age
            iat = datetime.fromtimestamp(payload['iat'])
            if datetime.utcnow() - iat > self.token_expiry:
                self.logger.log_system_event("token_validation_error", 
                    {"error": "Token too old"})
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            self.logger.log_system_event("token_validation_error", 
                {"error": "Token expired"})
            return None
            
        except jwt.InvalidTokenError as e:
            self.logger.log_system_event("token_validation_error", 
                {"error": str(e)})
            return None
            
        except Exception as e:
            self.logger.log_system_event("token_validation_error", 
                {"error": str(e)})
            return None
            
    def refresh_token(self, refresh_token: str) -> Optional[str]:
        """Generate a new access token using a valid refresh token"""
        try:
            # Validate refresh token
            payload = self.validate_token(refresh_token)
            if not payload:
                return None
                
            # Generate new access token
            return self.generate_token(
                payload['user_id'],
                payload['role']
            )
            
        except Exception as e:
            self.logger.log_system_event("token_refresh_error", {"error": str(e)})
            return None 