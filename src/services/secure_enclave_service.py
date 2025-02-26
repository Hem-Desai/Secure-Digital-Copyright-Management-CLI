from typing import Optional, Tuple, Dict, Any
from datetime import datetime
from ..models.user import User, UserRole
from ..auth.rbac import RBACManager, Permission
from ..encryption.aes_handler import AESHandler
from ..storage.file_storage import FileStorage
from ..storage.db_storage import SQLiteStorage
from ..utils.logging import AuditLogger
from ..utils.checksum import generate_checksum
import os

# Design Pattern: Facade Pattern
# The SecureEnclaveService acts as a facade, providing a simplified interface
# to the complex subsystem of security, storage, and encryption operations.
class SecureEnclaveService:
    """
    Secure Enclave Service implements the Facade pattern to provide a unified
    interface for all security-related operations. It coordinates:
    - Authentication and Authorization (RBAC)
    - File Encryption/Decryption (AES-256)
    - Secure Storage (File System + Database)
    - Audit Logging
    - File Integrity Checks
    """
    def __init__(self):
        # Initialize components following Dependency Injection pattern
        self.rbac = RBACManager()
        self.file_encryption = AESHandler()
        self.file_storage = FileStorage()
        self.db = SQLiteStorage()
        self.logger = AuditLogger()
        
        # Ensure secure storage directory exists
        os.makedirs(self.file_storage.base_path, exist_ok=True)
        
    def _confirm_authorization(self, user: User, permission: Permission, 
                             resource_id: Optional[str] = None) -> bool:
        """
        Strategy Pattern: Authorization strategy implementation
        Handles permission checks and audit logging
        """
        authorized = self.rbac.check_permission(user, permission, resource_id)
        self.logger.log_event(
            "authorization_check",
            user.id,
            {
                "permission": permission.value,
                "resource": resource_id,
                "granted": authorized,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        return authorized
        
    def _confirm_file_path(self, artifact_id: str) -> bool:
        """
        Template Method Pattern: File path validation
        Ensures file paths are within secure storage and properly formatted
        """
        try:
            path = self.file_storage._get_file_path(artifact_id)
            # Security: Prevent path traversal attacks
            if not str(path).startswith(str(self.file_storage.base_path)):
                raise ValueError("Invalid file path - potential path traversal")
            # Security: Check path format
            if not path.is_absolute():
                raise ValueError("Invalid file path - must be absolute")
            return True
        except Exception as e:
            self.logger.log_event(
                "file_path_check",
                "system",
                {
                    "error": str(e),
                    "path": str(path) if 'path' in locals() else None,
                    "timestamp": datetime.utcnow().isoformat()
                },
                "failure"
            )
            return False
            
    def handle_upload_request(self, user: User, file_data: bytes, 
                            metadata: Dict[str, Any]) -> Optional[str]:
        """
        Command Pattern: Upload operation implementation
        Handles the complete upload workflow with security checks
        """
        try:
            # Security: Check file size limits
            if len(file_data) > 100 * 1024 * 1024:  # 100MB limit
                raise ValueError("File size exceeds limit")
                
            # Security: Validate metadata
            if not metadata.get("name") or not metadata.get("content_type"):
                raise ValueError("Invalid metadata")
                
            # Steps 1-3: Authentication and Authorization
            if not self._confirm_authorization(user, Permission.CREATE):
                return None
                
            # Step 4-5: Encryption
            key_id, encryption_key = self.file_encryption.generate_key()
            encrypted_data = self.file_encryption.encrypt(file_data, key_id)
            
            if not encrypted_data:
                raise Exception("Encryption failed")
                
            # Generate artifact ID and checksum
            artifact_id = f"artifact_{datetime.utcnow().timestamp()}"
            checksum = generate_checksum(file_data)
            
            # Step 6: Store encrypted file
            if not self.file_storage.save_file(artifact_id, encrypted_data):
                raise Exception("File storage failed")
                
            # Step 7: Confirm file path
            if not self._confirm_file_path(artifact_id):
                raise Exception("File path verification failed")
                
            # Step 8: Store metadata
            now = datetime.utcnow().timestamp()
            metadata_stored = self.db.create({
                "table": "artifacts",
                "id": artifact_id,
                "name": metadata.get("name", ""),
                "content_type": metadata.get("content_type", ""),
                "owner_id": user.id,
                "created_at": now,
                "modified_at": now,
                "checksum": checksum,
                "encrypted_content": encrypted_data,
                "encryption_key_id": key_id,
                "file_size": len(file_data)
            })
            
            if not metadata_stored:
                raise Exception("Failed to store metadata")
                
            # Update owner's artifacts list
            if user.role == UserRole.OWNER:
                if not self.rbac.add_artifact_to_owner(user, artifact_id):
                    raise Exception("Failed to update owner's artifacts")
                    
            # Step 9-11: Logging and confirmation
            self.logger.log_event(
                "upload_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "content_type": metadata.get("content_type"),
                    "file_size": len(file_data),
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            return artifact_id
            
        except Exception as e:
            self.logger.log_event(
                "upload_artifact",
                user.id,
                {
                    "error": str(e),
                    "metadata": metadata,
                    "timestamp": datetime.utcnow().isoformat()
                },
                "failure"
            )
            # Cleanup on failure (Template Method Pattern)
            if 'artifact_id' in locals():
                self.file_storage.delete_file(artifact_id)
            return None
            
    def handle_download_request(self, user: User, artifact_id: str) -> Optional[bytes]:
        """
        Command Pattern: Download operation implementation
        Handles the complete download workflow with security checks
        """
        try:
            # Steps 1-3: Authentication and Authorization
            if not self._confirm_authorization(user, Permission.READ, artifact_id):
                return None
                
            # Step 4: Get artifact metadata and encrypted file
            artifact = self.db.read(artifact_id, "artifacts")
            if not artifact:
                raise Exception("Artifact not found")
                
            if not self._confirm_file_path(artifact_id):
                raise Exception("File path verification failed")
                
            encrypted_data = self.file_storage.read_file(artifact_id)
            if not encrypted_data:
                raise Exception("Failed to read encrypted file")
                
            # Step 5: Decrypt file
            decrypted_data = self.file_encryption.decrypt(
                encrypted_data,
                artifact["encryption_key_id"]
            )
            
            if not decrypted_data:
                raise Exception("Decryption failed")
                
            # Step 6: Verify checksum
            if generate_checksum(decrypted_data) != artifact["checksum"]:
                raise Exception("File integrity check failed")
                
            # Steps 7-8: Logging and confirmation
            self.logger.log_event(
                "download_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "content_type": artifact["content_type"],
                    "file_size": len(decrypted_data),
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            return decrypted_data
            
        except Exception as e:
            self.logger.log_event(
                "download_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                },
                "failure"
            )
            return None 