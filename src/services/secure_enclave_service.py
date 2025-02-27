from typing import Optional, Tuple, Dict, Any, List
from datetime import datetime
from ..models.user import User, UserRole
from ..auth.rbac import RBACManager, Permission
from ..encryption.aes_handler import AESHandler
from ..storage.file_storage import FileStorage
from ..storage.db_storage import SQLiteStorage
from ..utils.logging import AuditLogger
from ..utils.checksum import generate_checksum
import os
import uuid
import hashlib
import sqlite3

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
                "timestamp": datetime.now().isoformat()
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
                    "timestamp": datetime.now().isoformat()
                },
                "failure"
            )
            return False
            
    def handle_upload_request(self, user: User, file_path: str, name: str, content_type: str, file_size: int) -> Optional[str]:
        """Handle upload request from a user"""
        try:
            print(f"Processing upload request for user {user.username} with role {user.role}")
            
            # Check authorization
            if not self.rbac.check_permission(user, Permission.UPLOAD):
                print(f"User {user.username} does not have upload permission")
                return None

            # Read and encrypt file
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                print(f"Successfully read file: {file_path}")
            except Exception as e:
                print(f"Error reading file {file_path}: {str(e)}")
                return None

            # Generate encryption key and encrypt content
            try:
                key_id, _ = self.file_encryption.generate_key()
                print(f"Generated encryption key: {key_id}")
                
                encrypted_content = self.file_encryption.encrypt(content, key_id)
                if not encrypted_content:
                    print("Failed to encrypt content - encryption returned None")
                    return None
                print("Successfully encrypted content")
            except Exception as e:
                print(f"Encryption error: {str(e)}")
                return None

            # Create artifact entry
            artifact_id = str(uuid.uuid4())
            print(f"Generated artifact ID: {artifact_id}")
            
            artifact = {
                'table': 'artifacts',
                'id': artifact_id,
                'name': name,
                'content_type': content_type,
                'owner_id': user.id,
                'created_at': datetime.now().timestamp(),
                'modified_at': datetime.now().timestamp(),
                'checksum': hashlib.sha256(content).hexdigest(),
                'encrypted_content': encrypted_content,
                'encryption_key_id': key_id,
                'file_size': file_size
            }

            # Store artifact
            try:
                self.db.create(artifact)
                print(f"Successfully stored artifact in database")
            except Exception as e:
                print(f"Database storage error: {str(e)}")
                return None

            # Add artifact to owner's list only if user is an owner
            if user.role == UserRole.OWNER:
                if not self.rbac.add_artifact_to_owner(user.id, artifact_id):
                    print(f"Failed to add artifact {artifact_id} to owner {user.id}")
                    # Cleanup: remove artifact from storage
                    try:
                        self.db.delete(artifact_id, 'artifacts')
                        print(f"Cleaned up artifact {artifact_id} from database")
                    except Exception as e:
                        print(f"Cleanup error for artifact {artifact_id}: {str(e)}")
                    return None

            print(f"Successfully completed upload process for artifact {artifact_id}")
            return artifact_id

        except Exception as e:
            print(f"Unexpected error in handle_upload_request: {str(e)}")
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
                    "timestamp": datetime.now().isoformat()
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
                    "timestamp": datetime.now().isoformat()
                },
                "failure"
            )
            return None

    def list_artifacts(self, user: User) -> List[Dict[str, Any]]:
        """List all artifacts the user has access to"""
        try:
            # Check if user has LIST permission
            if not self.rbac.check_permission(user, Permission.LIST):
                self.logger.log_event(
                    "list_artifacts",
                    user.id,
                    {"status": "denied"},
                    "failure"
                )
                return []

            # Get all artifacts from database
            artifacts = self.db.list("artifacts")

            # Filter based on user role
            if user.role == UserRole.OWNER:
                artifacts = [a for a in artifacts if a["owner_id"] == user.id]

            # Remove sensitive information for non-admin users
            if user.role != UserRole.ADMIN:
                for artifact in artifacts:
                    artifact.pop("encryption_key_id", None)
                    artifact.pop("encrypted_content", None)

            # Log successful listing
            self.logger.log_event(
                "list_artifacts",
                user.id,
                {"count": len(artifacts)}
            )

            return artifacts

        except Exception as e:
            self.logger.log_event(
                "list_artifacts",
                user.id,
                {"error": str(e)},
                "failure"
            )
            return []

    def read_artifact(self, user: User, artifact_id: str) -> Optional[bytes]:
        """Read and decrypt an artifact's content"""
        try:
            # Get artifact metadata
            artifact = self.db.read(artifact_id, "artifacts")
            if not artifact:
                print("Artifact not found")
                return None

            # Check permissions
            if not self.rbac.check_permission(user, Permission.READ, artifact_id):
                print("Permission denied")
                return None

            # Get encrypted content directly from database
            encrypted_content = artifact.get("encrypted_content")
            if not encrypted_content:
                print("No content found")
                return None

            # Get encryption key and decrypt
            key_id = artifact.get("encryption_key_id")
            if not key_id:
                print("No encryption key found")
                return None

            # Decrypt the content
            decrypted_content = self.file_encryption.decrypt(encrypted_content, key_id)
            if not decrypted_content:
                print("Decryption failed")
                return None

            # Verify checksum
            if generate_checksum(decrypted_content) != artifact["checksum"]:
                print("Checksum verification failed")
                return None

            # Log successful read
            self.logger.log_event(
                "read_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "content_type": artifact["content_type"],
                    "file_size": len(decrypted_content)
                }
            )

            return decrypted_content

        except Exception as e:
            print(f"Error reading artifact: {str(e)}")
            self.logger.log_event(
                "read_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "error": str(e)
                },
                "failure"
            )
            return None 