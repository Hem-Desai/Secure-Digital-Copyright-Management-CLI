import logging
import json
from datetime import datetime
from typing import Any, Dict
import os
import sys

class AuditLogger:
    def __init__(self):
        """Initialize the audit logger"""
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            filename='logs/audit.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('audit')
        
    def log_system_event(self, event_type: str, details: dict):
        """Log a system event with details"""
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'details': details
            }
            self.logger.info(json.dumps(message))
        except Exception as e:
            # If logging fails, print to stderr but don't raise
            print(f"Error logging event: {e}", file=sys.stderr)
            
    def log_auth_attempt(self, user_id: str, success: bool, ip_address: str):
        """Log an authentication attempt"""
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'auth_attempt',
                'user_id': user_id,
                'success': success,
                'ip_address': ip_address
            }
            self.logger.info(json.dumps(message))
        except Exception as e:
            print(f"Error logging auth attempt: {e}", file=sys.stderr)
            
    def log_artifact_access(self, user_id: str, artifact_id: str, action: str):
        """Log artifact access"""
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'artifact_access',
                'user_id': user_id,
                'artifact_id': artifact_id,
                'action': action
            }
            self.logger.info(json.dumps(message))
        except Exception as e:
            print(f"Error logging artifact access: {e}", file=sys.stderr)

    def log_event(self, 
                  event_type: str, 
                  user_id: str, 
                  details: Dict[str, Any],
                  status: str = "success") -> None:
        """Log an audit event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "status": status,
            "details": details
        }
        self.logger.info(json.dumps(event))

    def log_error(self, error_type: str, error_msg: str, details: Dict[str, Any] = None) -> None:
        """Log an error event"""
        error = {
            "timestamp": datetime.now().isoformat(),
            "error_type": error_type,
            "error_message": error_msg,
            "details": details or {}
        }
        self.logger.error(json.dumps(error))

    def log_system(self, message: str, level: str = "info") -> None:
        """Log a system event"""
        if level.lower() == "error":
            self.logger.error(message)
        elif level.lower() == "warning":
            self.logger.warning(message)
        else:
            self.logger.info(message)

    def log_auth_attempt(self, 
                        user_id: str, 
                        success: bool, 
                        ip_address: str) -> None:
        """Log authentication attempts"""
        self.log_event(
            "authentication",
            user_id,
            {
                "ip_address": ip_address,
                "success": success
            },
            status="success" if success else "failure"
        ) 