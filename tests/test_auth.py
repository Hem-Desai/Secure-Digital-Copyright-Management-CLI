import unittest
from datetime import datetime
from src.models.user import User, UserRole
from src.auth.rbac import RBACManager, Permission

class TestRBAC(unittest.TestCase):
    def setUp(self):
        self.rbac = RBACManager()
        self.admin = User(
            id="admin",
            username="admin",
            password_hash="hash",
            role=UserRole.ADMIN,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        self.owner = User(
            id="owner",
            username="owner",
            password_hash="hash",
            role=UserRole.OWNER,
            created_at=datetime.utcnow().timestamp(),
            artifacts=["artifact1"]
        )
        self.viewer = User(
            id="viewer",
            username="viewer",
            password_hash="hash",
            role=UserRole.VIEWER,
            created_at=datetime.utcnow().timestamp(),
            artifacts=[]
        )
        
    def test_admin_permissions(self):
        """Test that admin has all permissions"""
        for permission in Permission:
            self.assertTrue(
                self.rbac.check_permission(self.admin, permission)
            )
            
    def test_owner_permissions(self):
        """Test owner permissions"""
        # Can read own artifacts
        self.assertTrue(
            self.rbac.check_permission(
                self.owner, 
                Permission.READ, 
                "artifact1"
            )
        )
        # Cannot read other artifacts
        self.assertFalse(
            self.rbac.check_permission(
                self.owner,
                Permission.READ,
                "artifact2"
            )
        )
        
    def test_viewer_permissions(self):
        """Test viewer permissions"""
        self.assertTrue(
            self.rbac.check_permission(self.viewer, Permission.READ)
        )
        self.assertFalse(
            self.rbac.check_permission(self.viewer, Permission.CREATE)
        ) 