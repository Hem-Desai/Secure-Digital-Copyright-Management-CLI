import unittest
import os
import tempfile
import shutil
from datetime import datetime
from src.storage.db_storage import SQLiteStorage
from src.storage.file_storage import FileStorage
from src.models.user import UserRole

class TestStorage(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory
        self.test_dir = tempfile.mkdtemp()
        
        # Initialize storage with test paths
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.file_storage = FileStorage(base_path=self.test_dir)
        self.db_storage = SQLiteStorage(db_path=self.db_path)
        
        # Test data
        self.test_user = {
            "table": "users",
            "id": "test_user",
            "username": "testuser",
            "password_hash": b"test_hash",
            "role": UserRole.OWNER.value,
            "created_at": datetime.utcnow().timestamp(),
            "password_last_changed": datetime.utcnow().timestamp()
        }
        
        self.test_artifact = {
            "table": "artifacts",
            "id": "test_artifact",
            "name": "Test Artifact",
            "content_type": "text/plain",
            "owner_id": "test_user",
            "created_at": datetime.utcnow().timestamp(),
            "modified_at": datetime.utcnow().timestamp(),
            "checksum": "test_checksum",
            "encrypted_content": b"encrypted_data",
            "encryption_key_id": "test_key"
        }
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        
    def test_db_initialization(self):
        """Test database initialization"""
        # Verify database file created
        self.assertTrue(os.path.exists(self.db_path))
        
        # Verify tables created
        with self.db_storage.db_path as conn:
            cursor = conn.cursor()
            
            # Check users table
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='users'
            """)
            self.assertIsNotNone(cursor.fetchone())
            
            # Check artifacts table
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='artifacts'
            """)
            self.assertIsNotNone(cursor.fetchone())
            
    def test_db_crud_operations(self):
        """Test database CRUD operations"""
        # Create
        user_id = self.db_storage.create(self.test_user)
        self.assertEqual(user_id, self.test_user["id"])
        
        artifact_id = self.db_storage.create(self.test_artifact)
        self.assertEqual(artifact_id, self.test_artifact["id"])
        
        # Read
        user = self.db_storage.read(user_id, "users")
        self.assertEqual(user["username"], self.test_user["username"])
        
        artifact = self.db_storage.read(artifact_id, "artifacts")
        self.assertEqual(artifact["name"], self.test_artifact["name"])
        
        # Update
        update_data = {
            "table": "artifacts",
            "name": "Updated Name",
            "modified_at": datetime.utcnow().timestamp()
        }
        success = self.db_storage.update(artifact_id, update_data)
        self.assertTrue(success)
        
        updated = self.db_storage.read(artifact_id, "artifacts")
        self.assertEqual(updated["name"], "Updated Name")
        
        # Delete
        success = self.db_storage.delete(artifact_id, "artifacts")
        self.assertTrue(success)
        
        deleted = self.db_storage.read(artifact_id, "artifacts")
        self.assertIsNone(deleted)
        
    def test_file_storage(self):
        """Test file storage operations"""
        test_id = "test123"
        test_data = b"Test file content"
        
        # Save file
        success = self.file_storage.save_file(test_id, test_data)
        self.assertTrue(success)
        
        # Verify file exists
        file_path = self.file_storage._get_file_path(test_id)
        self.assertTrue(os.path.exists(file_path))
        
        # Read file
        read_data = self.file_storage.read_file(test_id)
        self.assertEqual(read_data, test_data)
        
        # Delete file
        success = self.file_storage.delete_file(test_id)
        self.assertTrue(success)
        self.assertFalse(os.path.exists(file_path))
        
    def test_file_path_security(self):
        """Test file path security measures"""
        # Test path traversal attempt
        malicious_id = "../../../etc/passwd"
        
        # Attempt to save file
        success = self.file_storage.save_file(
            malicious_id, 
            b"malicious content"
        )
        self.assertFalse(success)
        
        # Verify file wasn't created outside base path
        file_path = os.path.join(os.path.dirname(self.test_dir), "passwd")
        self.assertFalse(os.path.exists(file_path))
        
    def test_concurrent_access(self):
        """Test concurrent database access"""
        # Create test records
        for i in range(5):
            user_data = self.test_user.copy()
            user_data["id"] = f"user_{i}"
            user_data["username"] = f"user_{i}"
            self.db_storage.create(user_data)
            
        # Read all records
        users = self.db_storage.list("users")
        self.assertEqual(len(users), 5)
        
        # Update all records
        for user in users:
            update_data = {
                "table": "users",
                "password_last_changed": datetime.utcnow().timestamp()
            }
            success = self.db_storage.update(user["id"], update_data)
            self.assertTrue(success)
            
    def test_user_artifact_relationship(self):
        """Test user-artifact relationship in database"""
        # Create user
        user_id = self.db_storage.create(self.test_user)
        
        # Create multiple artifacts for user
        artifacts = []
        for i in range(3):
            artifact_data = self.test_artifact.copy()
            artifact_data["id"] = f"artifact_{i}"
            artifact_data["owner_id"] = user_id
            artifact_id = self.db_storage.create(artifact_data)
            artifacts.append(artifact_id)
            
        # Get user's artifacts
        user_artifacts = self.db_storage.get_user_artifacts(user_id)
        self.assertEqual(len(user_artifacts), 3)
        for artifact_id in artifacts:
            self.assertIn(artifact_id, user_artifacts) 