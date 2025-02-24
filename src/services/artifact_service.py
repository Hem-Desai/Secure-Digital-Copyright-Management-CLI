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

class ArtifactService:
    def __init__(self):
        self.db = SQLiteStorage()
        self.file_storage = FileStorage()
        self.encryption = AESHandler()
        self.rbac = RBACManager()
        self.logger = AuditLogger()
        
    def create_artifact(self, user: User, name: str, 
                       content_type: str, content: bytes) -> Optional[str]:
        """Create a new artifact"""
        if not self.rbac.check_permission(user, Permission.CREATE):
            self.logger.log_event("create_artifact", user.id, 
                                {"status": "denied"}, "failure")
            return None
            
        try:
            # Generate IDs and encrypt content
            artifact_id = str(uuid.uuid4())
            key_id, _ = self.encryption.generate_key()
            encrypted_content = self.encryption.encrypt(content, key_id)
            
            # Calculate checksum of original content
            checksum = generate_checksum(content)
            
            # Create artifact record
            now = datetime.utcnow().timestamp()
            artifact = Artifact(
                id=artifact_id,
                name=name,
                content_type=content_type,
                owner_id=user.id,
                created_at=now,
                modified_at=now,
                checksum=checksum,
                encrypted_content=encrypted_content,
                encryption_key_id=key_id
            )
            
            # Save to storage
            self.file_storage.save_file(artifact_id, encrypted_content)
            self.db.create({
                "table": "artifacts",
                "id": artifact_id,
                **artifact.metadata
            })
            
            # Add artifact to owner's list if user is an owner
            if user.role == UserRole.OWNER:
                self.rbac.add_artifact_to_owner(user, artifact_id)
            
            self.logger.log_event("create_artifact", user.id, 
                                {"artifact_id": artifact_id})
            return artifact_id
            
        except Exception as e:
            self.logger.log_event("create_artifact", user.id,
                                {"error": str(e)}, "failure")
            return None
            
    def read_artifact(self, user: User, artifact_id: str) -> Optional[bytes]:
        """Read an artifact's content"""
        if not self.rbac.check_permission(user, Permission.READ, artifact_id):
            self.logger.log_event("read_artifact", user.id,
                                {"artifact_id": artifact_id}, "denied")
            return None
            
        try:
            # Get artifact metadata
            artifact_data = self.db.read(artifact_id, "artifacts")
            if not artifact_data:
                return None
                
            # Read and decrypt content
            encrypted_content = self.file_storage.read_file(artifact_id)
            if not encrypted_content:
                return None
                
            content = self.encryption.decrypt(
                encrypted_content,
                artifact_data["encryption_key_id"]
            )
            
            self.logger.log_event("read_artifact", user.id,
                                {"artifact_id": artifact_id})
            return content
            
        except Exception as e:
            self.logger.log_event("read_artifact", user.id,
                                {"error": str(e)}, "failure")
            return None
            
    def update_artifact(self, user: User, artifact_id: str, 
                       content: bytes) -> bool:
        """Update an artifact's content"""
        if not self.rbac.check_permission(user, Permission.UPDATE, artifact_id):
            self.logger.log_event("update_artifact", user.id,
                                {"artifact_id": artifact_id}, "denied")
            return False
            
        try:
            # Get existing artifact
            artifact_data = self.db.read(artifact_id, "artifacts")
            if not artifact_data:
                return False
                
            # Generate new encryption key and encrypt content
            key_id, _ = self.encryption.generate_key()
            encrypted_content = self.encryption.encrypt(content, key_id)
            checksum = generate_checksum(content)
            
            # Update storage
            self.file_storage.save_file(artifact_id, encrypted_content)
            success = self.db.update(artifact_id, {
                "table": "artifacts",
                "modified_at": datetime.utcnow().timestamp(),
                "checksum": checksum,
                "encryption_key_id": key_id
            })
            
            if success:
                self.logger.log_event("update_artifact", user.id,
                                    {"artifact_id": artifact_id})
            return success
            
        except Exception as e:
            self.logger.log_event("update_artifact", user.id,
                                {"error": str(e)}, "failure")
            return False
            
    def delete_artifact(self, user: User, artifact_id: str) -> bool:
        """Delete an artifact"""
        if not self.rbac.check_permission(user, Permission.DELETE, artifact_id):
            self.logger.log_event("delete_artifact", user.id,
                                {"artifact_id": artifact_id}, "denied")
            return False
            
        try:
            # Delete from both storages
            self.file_storage.delete_file(artifact_id)
            success = self.db.delete(artifact_id, "artifacts")
            
            if success:
                self.logger.log_event("delete_artifact", user.id,
                                    {"artifact_id": artifact_id})
            return success
            
        except Exception as e:
            self.logger.log_event("delete_artifact", user.id,
                                {"error": str(e)}, "failure")
            return False
            
    def list_artifacts(self, user: User) -> List[Dict[str, Any]]:
        """List all artifacts user has access to"""
        if not self.rbac.check_permission(user, Permission.LIST):
            self.logger.log_event("list_artifacts", user.id,
                                {"status": "denied"}, "failure")
            return []
            
        try:
            artifacts = self.db.list("artifacts")
            
            # Filter based on user role
            if user.role == UserRole.OWNER:
                artifacts = [a for a in artifacts if a["owner_id"] == user.id]
                
            self.logger.log_event("list_artifacts", user.id,
                                {"count": len(artifacts)})
            return artifacts
            
        except Exception as e:
            self.logger.log_event("list_artifacts", user.id,
                                {"error": str(e)}, "failure")
            return [] 