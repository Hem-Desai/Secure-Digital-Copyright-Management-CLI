import uuid
from datetime import datetime
from typing import Optional, Dict, List, BinaryIO, Any

from ..models.artifact import Artifact
from ..models.user import User, UserRole
from ..storage.db_storage import SQLiteStorage
from ..storage.file_storage import FileStorage
from ..encryption.aes_handler import AESHandler
from ..utils.checksum import generate_checksum
from ..utils.logging import AuditLogger
from ..auth.rbac import RBACManager, Permission
from .secure_enclave_service import SecureEnclaveService

class ArtifactService:
    def __init__(self):
        self.secure_enclave = SecureEnclaveService()
        
    def create_artifact(self, user: User, name: str, 
                       content_type: str, content: bytes) -> Optional[str]:
        """Create a new artifact using secure enclave"""
        try:
            metadata = {
                "name": name,
                "content_type": content_type
            }
            result = self.secure_enclave.handle_upload_request(user, content, metadata)
            if not result:
                print("Secure enclave failed to handle upload request")
            return result
        except Exception as e:
            print(f"Artifact creation error: {str(e)}")
            return None
        
    def read_artifact(self, user: User, artifact_id: str) -> Optional[bytes]:
        """Read an artifact's content using secure enclave"""
        return self.secure_enclave.handle_download_request(user, artifact_id)
        
    def update_artifact(self, user: User, artifact_id: str, 
                       content: bytes) -> bool:
        """Update an artifact's content securely"""
        try:
            # First verify permissions
            if not self.secure_enclave._confirm_authorization(
                user, Permission.UPDATE, artifact_id
            ):
                return False
                
            # Get existing artifact to preserve metadata
            artifact = self.secure_enclave.db.read(artifact_id, "artifacts")
            if not artifact:
                return False
                
            # Create new version with updated content
            metadata = {
                "name": artifact["name"],
                "content_type": artifact["content_type"]
            }
            
            # Upload new version
            new_artifact_id = self.secure_enclave.handle_upload_request(
                user, content, metadata
            )
            
            if not new_artifact_id:
                return False
                
            # Delete old version securely
            old_file_id = artifact_id
            if not self.secure_enclave.file_storage.delete_file(old_file_id):
                # Rollback if old version deletion fails
                self.secure_enclave.file_storage.delete_file(new_artifact_id)
                return False
                
            # Update database record
            success = self.secure_enclave.db.update(artifact_id, {
                "table": "artifacts",
                "modified_at": datetime.utcnow().timestamp(),
                "encrypted_content": content,
                "checksum": self.secure_enclave.generate_checksum(content),
                "file_size": len(content)
            })
            
            if not success:
                # Rollback on database update failure
                self.secure_enclave.file_storage.delete_file(new_artifact_id)
                return False
                
            return True
            
        except Exception as e:
            self.secure_enclave.logger.log_event(
                "update_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "error": str(e)
                },
                "failure"
            )
            return False
            
    def delete_artifact(self, user: User, artifact_id: str) -> bool:
        """Delete an artifact securely"""
        try:
            # Verify permissions
            if not self.secure_enclave._confirm_authorization(
                user, Permission.DELETE, artifact_id
            ):
                return False
                
            # Get artifact to verify existence
            artifact = self.secure_enclave.db.read(artifact_id, "artifacts")
            if not artifact:
                return False
                
            # Delete file first
            if not self.secure_enclave.file_storage.delete_file(artifact_id):
                return False
                
            # Delete database record
            if not self.secure_enclave.db.delete(artifact_id, "artifacts"):
                return False
                
            # Remove from owner's artifacts if applicable
            if user.role == UserRole.OWNER:
                self.secure_enclave.rbac.remove_artifact_from_owner(
                    user, artifact_id
                )
                
            # Log successful deletion
            self.secure_enclave.logger.log_event(
                "delete_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "content_type": artifact["content_type"]
                }
            )
            
            return True
            
        except Exception as e:
            self.secure_enclave.logger.log_event(
                "delete_artifact",
                user.id,
                {
                    "artifact_id": artifact_id,
                    "error": str(e)
                },
                "failure"
            )
            return False
            
    def list_artifacts(self, user: User) -> List[Dict[str, Any]]:
        """List all artifacts user has access to"""
        if not self.secure_enclave.rbac.check_permission(user, Permission.LIST):
            self.secure_enclave.logger.log_event(
                "list_artifacts", 
                user.id,
                {"status": "denied"}, 
                "failure"
            )
            return []
            
        try:
            artifacts = self.secure_enclave.db.list("artifacts")
            
            # Filter based on user role
            if user.role == UserRole.OWNER:
                artifacts = [a for a in artifacts if a["owner_id"] == user.id]
                
            # Remove sensitive information for non-admin users
            if user.role != UserRole.ADMIN:
                for artifact in artifacts:
                    artifact.pop("encryption_key_id", None)
                    artifact.pop("encrypted_content", None)
                
            self.secure_enclave.logger.log_event(
                "list_artifacts", 
                user.id,
                {"count": len(artifacts)}
            )
            return artifacts
            
        except Exception as e:
            self.secure_enclave.logger.log_event(
                "list_artifacts", 
                user.id,
                {"error": str(e)}, 
                "failure"
            )
            return [] 