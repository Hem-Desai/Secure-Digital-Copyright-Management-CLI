import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
import os

class JWTHandler:
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.urandom(32).hex()
        self.algorithm = "HS256"
        self.token_expiry = timedelta(hours=1)
        
    def generate_token(self, user_id: str, role: str) -> str:
        """Generate a new JWT token"""
        payload = {
            "user_id": user_id,
            "role": role,
            "exp": datetime.utcnow() + self.token_expiry,
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate and decode a JWT token"""
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None 