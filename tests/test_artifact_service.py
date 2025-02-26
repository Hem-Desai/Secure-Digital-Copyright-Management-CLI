import unittest
from datetime import datetime
import os
import tempfile
import shutil
from src.models.user import User, UserRole
from src.services.artifact_service import ArtifactService
from src.services.secure_enclave_service import SecureEnclaveService

class TestArtifactService(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Initialize services
        self.artifact_service = ArtifactService()
        self.secure_enclave = SecureEnclaveService()
        
        # Create test users
        self.admin_user = User(
            id="admin_test",
            username="admin",
            password_hash=b"test_hash",
            role=UserRole.ADMIN,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
        self.owner_user = User(
            id="owner_test",
            username="owner",
            password_hash=b"test_hash",
            role=UserRole.OWNER,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
        self.viewer_user = User(
            id="viewer_test",
            username="viewer",
            password_hash=b"test_hash",
            role=UserRole.VIEWER,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
        # Create test file
        self.test_content = b"Test file content"
        self.test_file = os.path.join(self.test_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)
            
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        
    def test_create_artifact(self):
        """Test artifact creation"""
        # Admin creating artifact
        artifact_id = self.artifact_service.create_artifact(
            self.admin_user,
            "test_artifact",
            "text/plain",
            self.test_content
        )
        self.assertIsNotNone(artifact_id)
        
        # Owner creating artifact
        owner_artifact_id = self.artifact_service.create_artifact(
            self.owner_user,
            "owner_artifact",
            "text/plain",
            self.test_content
        )
        self.assertIsNotNone(owner_artifact_id)
        self.assertIn(owner_artifact_id, self.owner_user.artifacts)
        
        # Viewer should not be able to create
        viewer_artifact_id = self.artifact_service.create_artifact(
            self.viewer_user,
            "viewer_artifact",
            "text/plain",
            self.test_content
        )
        self.assertIsNone(viewer_artifact_id)
        
    def test_read_artifact(self):
        """Test artifact reading"""
        # Create test artifact
        artifact_id = self.artifact_service.create_artifact(
            self.admin_user,
            "test_artifact",
            "text/plain",
            self.test_content
        )
        
        # Admin reading
        admin_content = self.artifact_service.read_artifact(
            self.admin_user,
            artifact_id
        )
        self.assertEqual(admin_content, self.test_content)
        
        # Owner reading
        owner_content = self.artifact_service.read_artifact(
            self.owner_user,
            artifact_id
        )
        self.assertEqual(owner_content, self.test_content)
        
        # Viewer reading
        viewer_content = self.artifact_service.read_artifact(
            self.viewer_user,
            artifact_id
        )
        self.assertEqual(viewer_content, self.test_content)
        
    def test_update_artifact(self):
        """Test artifact updating"""
        # Create test artifact
        artifact_id = self.artifact_service.create_artifact(
            self.owner_user,
            "test_artifact",
            "text/plain",
            self.test_content
        )
        
        new_content = b"Updated content"
        
        # Owner updating own artifact
        success = self.artifact_service.update_artifact(
            self.owner_user,
            artifact_id,
            new_content
        )
        self.assertTrue(success)
        
        # Verify update
        updated_content = self.artifact_service.read_artifact(
            self.owner_user,
            artifact_id
        )
        self.assertEqual(updated_content, new_content)
        
        # Admin updating any artifact
        admin_content = b"Admin updated"
        success = self.artifact_service.update_artifact(
            self.admin_user,
            artifact_id,
            admin_content
        )
        self.assertTrue(success)
        
        # Viewer cannot update
        viewer_success = self.artifact_service.update_artifact(
            self.viewer_user,
            artifact_id,
            b"Viewer attempt"
        )
        self.assertFalse(viewer_success)
        
    def test_delete_artifact(self):
        """Test artifact deletion"""
        # Create test artifact
        artifact_id = self.artifact_service.create_artifact(
            self.owner_user,
            "test_artifact",
            "text/plain",
            self.test_content
        )
        
        # Viewer cannot delete
        viewer_success = self.artifact_service.delete_artifact(
            self.viewer_user,
            artifact_id
        )
        self.assertFalse(viewer_success)
        
        # Owner can delete own artifact
        owner_success = self.artifact_service.delete_artifact(
            self.owner_user,
            artifact_id
        )
        self.assertTrue(owner_success)
        
        # Verify deletion
        content = self.artifact_service.read_artifact(
            self.admin_user,
            artifact_id
        )
        self.assertIsNone(content)
        
    def test_list_artifacts(self):
        """Test artifact listing"""
        # Create test artifacts
        artifact1 = self.artifact_service.create_artifact(
            self.owner_user,
            "owner_artifact",
            "text/plain",
            self.test_content
        )
        
        artifact2 = self.artifact_service.create_artifact(
            self.admin_user,
            "admin_artifact",
            "text/plain",
            self.test_content
        )
        
        # Admin sees all artifacts
        admin_list = self.artifact_service.list_artifacts(self.admin_user)
        self.assertEqual(len(admin_list), 2)
        
        # Owner sees own artifacts
        owner_list = self.artifact_service.list_artifacts(self.owner_user)
        self.assertEqual(len(owner_list), 1)
        self.assertEqual(owner_list[0]["id"], artifact1)
        
        # Viewer sees all but with limited info
        viewer_list = self.artifact_service.list_artifacts(self.viewer_user)
        self.assertEqual(len(viewer_list), 2)
        self.assertNotIn("encryption_key_id", viewer_list[0])
        self.assertNotIn("encrypted_content", viewer_list[0]) 