import unittest
from datetime import datetime
from src.models.user import User, UserRole
from src.auth.rbac import RBACManager, Permission
import bcrypt

class TestRBAC(unittest.TestCase):
    def setUp(self):
        """Set up test cases with different user roles"""
        self.rbac = RBACManager()
        
        # Create test users
        self.admin = User(
            id="admin_test",
            username="admin",
            password_hash=bcrypt.hashpw("Admin123!".encode(), bcrypt.gensalt()),
            role=UserRole.ADMIN,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
        self.owner = User(
            id="owner_test",
            username="owner",
            password_hash=bcrypt.hashpw("Owner123!".encode(), bcrypt.gensalt()),
            role=UserRole.OWNER,
            created_at=datetime.utcnow().timestamp(),
            artifacts=["artifact1", "artifact2"]
        )
        
        self.viewer = User(
            id="viewer_test",
            username="viewer",
            password_hash=bcrypt.hashpw("Viewer123!".encode(), bcrypt.gensalt()),
            role=UserRole.VIEWER,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
    def test_password_validation(self):
        """Test password complexity requirements"""
        # Valid passwords
        self.assertTrue(self.rbac._validate_password("ValidPass123!"))
        self.assertTrue(self.rbac._validate_password("Complex@Pass999"))
        
        # Invalid passwords
        self.assertFalse(self.rbac._validate_password("short1!"))  # Too short
        self.assertFalse(self.rbac._validate_password("nouppercase123!"))  # No uppercase
        self.assertFalse(self.rbac._validate_password("NOLOWERCASE123!"))  # No lowercase
        self.assertFalse(self.rbac._validate_password("NoNumbers!"))  # No numbers
        self.assertFalse(self.rbac._validate_password("NoSpecial123"))  # No special chars
        
    def test_user_creation(self):
        """Test user creation with different roles"""
        # Test valid user creation
        new_user = self.rbac.create_user("newuser", "NewUser123!", UserRole.OWNER)
        self.assertIsNotNone(new_user)
        self.assertEqual(new_user.username, "newuser")
        self.assertEqual(new_user.role, UserRole.OWNER)
        
        # Test duplicate username
        duplicate = self.rbac.create_user("newuser", "Different123!", UserRole.VIEWER)
        self.assertIsNone(duplicate)
        
        # Test weak password
        weak_pass = self.rbac.create_user("weakuser", "weak", UserRole.VIEWER)
        self.assertIsNone(weak_pass)
        
    def test_authentication(self):
        """Test user authentication"""
        # Create a test user with known password
        password = "TestPass123!"
        user = self.rbac.create_user("testauth", password, UserRole.VIEWER)
        
        # Test successful authentication
        auth_user = self.rbac.authenticate("testauth", password)
        self.assertIsNotNone(auth_user)
        self.assertEqual(auth_user.username, "testauth")
        
        # Test failed authentication
        self.assertIsNone(self.rbac.authenticate("testauth", "wrongpass"))
        self.assertIsNone(self.rbac.authenticate("nonexistent", password))
        
    def test_admin_permissions(self):
        """Test admin role permissions"""
        # Admin should have all permissions
        for permission in Permission:
            self.assertTrue(
                self.rbac.check_permission(self.admin, permission)
            )
            
        # Admin should have access to all resources
        self.assertTrue(
            self.rbac.check_permission(self.admin, Permission.READ, "any_artifact")
        )
        
    def test_owner_permissions(self):
        """Test owner role permissions"""
        # Test owned artifact access
        self.assertTrue(
            self.rbac.check_permission(self.owner, Permission.READ, "artifact1")
        )
        self.assertTrue(
            self.rbac.check_permission(self.owner, Permission.UPDATE, "artifact1")
        )
        self.assertTrue(
            self.rbac.check_permission(self.owner, Permission.DELETE, "artifact1")
        )
        
        # Test non-owned artifact access
        self.assertFalse(
            self.rbac.check_permission(self.owner, Permission.READ, "other_artifact")
        )
        self.assertFalse(
            self.rbac.check_permission(self.owner, Permission.UPDATE, "other_artifact")
        )
        
        # Test general permissions
        self.assertTrue(
            self.rbac.check_permission(self.owner, Permission.LIST)
        )
        self.assertFalse(
            self.rbac.check_permission(self.owner, Permission.CREATE)
        )
        
    def test_viewer_permissions(self):
        """Test viewer role permissions"""
        # Viewers can only read and list
        self.assertTrue(
            self.rbac.check_permission(self.viewer, Permission.READ, "any_artifact")
        )
        self.assertTrue(
            self.rbac.check_permission(self.viewer, Permission.LIST)
        )
        
        # Viewers cannot modify
        self.assertFalse(
            self.rbac.check_permission(self.viewer, Permission.CREATE)
        )
        self.assertFalse(
            self.rbac.check_permission(self.viewer, Permission.UPDATE, "any_artifact")
        )
        self.assertFalse(
            self.rbac.check_permission(self.viewer, Permission.DELETE, "any_artifact")
        )
        
    def test_artifact_ownership(self):
        """Test artifact ownership management"""
        # Add new artifact to owner
        self.assertTrue(
            self.rbac.add_artifact_to_owner(self.owner, "new_artifact")
        )
        self.assertIn("new_artifact", self.owner.artifacts)
        
        # Try to add artifact to non-owner (should fail)
        self.assertFalse(
            self.rbac.add_artifact_to_owner(self.viewer, "new_artifact")
        ) 