from datetime import datetime
import bcrypt
from src.storage.db_storage import SQLiteStorage
from src.models.user import UserRole

def init_database():
    """Initialize database with default users"""
    db = SQLiteStorage()
    
    # Create default admin user
    admin_password = "Admin123!"
    admin_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt())
    
    admin_user = {
        "table": "users",
        "id": "admin_default",
        "username": "admin",
        "password_hash": admin_hash,
        "role": UserRole.ADMIN.value,
        "created_at": datetime.utcnow().timestamp(),
        "password_last_changed": datetime.utcnow().timestamp(),
        "failed_login_attempts": 0,
        "last_login_attempt": 0,
        "account_locked": False
    }
    
    # Create default owner user
    owner_password = "Owner123!"
    owner_hash = bcrypt.hashpw(owner_password.encode(), bcrypt.gensalt())
    
    owner_user = {
        "table": "users",
        "id": "owner_default",
        "username": "owner",
        "password_hash": owner_hash,
        "role": UserRole.OWNER.value,
        "created_at": datetime.utcnow().timestamp(),
        "password_last_changed": datetime.utcnow().timestamp(),
        "failed_login_attempts": 0,
        "last_login_attempt": 0,
        "account_locked": False
    }
    
    # Create default viewer user
    viewer_password = "Viewer123!"
    viewer_hash = bcrypt.hashpw(viewer_password.encode(), bcrypt.gensalt())
    
    viewer_user = {
        "table": "users",
        "id": "viewer_default",
        "username": "viewer",
        "password_hash": viewer_hash,
        "role": UserRole.VIEWER.value,
        "created_at": datetime.utcnow().timestamp(),
        "password_last_changed": datetime.utcnow().timestamp(),
        "failed_login_attempts": 0,
        "last_login_attempt": 0,
        "account_locked": False
    }
    
    # Create users in database
    try:
        db.create(admin_user)
        print("Created admin user")
        db.create(owner_user)
        print("Created owner user")
        db.create(viewer_user)
        print("Created viewer user")
        print("\nDefault users created successfully!")
        print("\nDefault Credentials:")
        print("-------------------")
        print("Admin User:")
        print(f"Username: admin")
        print(f"Password: {admin_password}")
        print("\nOwner User:")
        print(f"Username: owner")
        print(f"Password: {owner_password}")
        print("\nViewer User:")
        print(f"Username: viewer")
        print(f"Password: {viewer_password}")
    except Exception as e:
        print(f"Error creating default users: {e}")

if __name__ == "__main__":
    init_database() 