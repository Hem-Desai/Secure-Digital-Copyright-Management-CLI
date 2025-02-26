import logging
import json
from datetime import datetime
from typing import Any, Dict

class AuditLogger:
    def __init__(self, log_file: str = "audit.log"):
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
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