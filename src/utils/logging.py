import logging
import json
from datetime import datetime
from typing import Any, Dict
import os

class AuditLogger:
    def __init__(self, log_dir: str = "logs"):
        # Create logs directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up system logger
        self.system_logger = logging.getLogger("system")
        self.system_logger.setLevel(logging.INFO)
        system_handler = logging.FileHandler(os.path.join(log_dir, "system.log"))
        system_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.system_logger.addHandler(system_handler)
        
        # Set up audit logger
        self.audit_logger = logging.getLogger("audit")
        self.audit_logger.setLevel(logging.INFO)
        audit_handler = logging.FileHandler(os.path.join(log_dir, "audit.log"))
        audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.audit_logger.addHandler(audit_handler)
        
        # Set up error logger
        self.error_logger = logging.getLogger("error")
        self.error_logger.setLevel(logging.ERROR)
        error_handler = logging.FileHandler(os.path.join(log_dir, "error.log"))
        error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.error_logger.addHandler(error_handler)

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
        self.audit_logger.info(json.dumps(event))

    def log_error(self, error_type: str, error_msg: str, details: Dict[str, Any] = None) -> None:
        """Log an error event"""
        error = {
            "timestamp": datetime.now().isoformat(),
            "error_type": error_type,
            "error_message": error_msg,
            "details": details or {}
        }
        self.error_logger.error(json.dumps(error))

    def log_system(self, message: str, level: str = "info") -> None:
        """Log a system event"""
        if level.lower() == "error":
            self.system_logger.error(message)
        elif level.lower() == "warning":
            self.system_logger.warning(message)
        else:
            self.system_logger.info(message)

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