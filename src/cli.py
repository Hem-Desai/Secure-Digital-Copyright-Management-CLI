import click
import getpass
import sys
import json
from typing import Optional
from pathlib import Path
import os
from datetime import datetime, timedelta
from src.models.user import User, UserRole
from src.services.artifact_service import ArtifactService
from src.utils.logging import AuditLogger
from src.auth.rbac import RBACManager
from src.storage.db_storage import SQLiteStorage
from src.services.secure_enclave_service import SecureEnclaveService
from src.models.content_type import ContentType

# Constants
SESSION_FILE = ".session"

class CLI:
    def __init__(self):
        self.db = SQLiteStorage()
        self.rbac_manager = RBACManager()
        self.logger = AuditLogger()
        self.secure_enclave = SecureEnclaveService()
        self.current_user: Optional[User] = None
        self._load_session()
        
    def _load_session(self):
        """Load user session if exists"""
        try:
            if os.path.exists(SESSION_FILE):
                with open(SESSION_FILE, 'r') as f:
                    session_data = json.load(f)
                    if session_data.get("user_id"):  # Changed from username to user_id
                        user_data = self.db.read(session_data["user_id"], "users")  # Changed from get_user_by_username
                        if user_data:
                            self.current_user = User(
                                id=user_data["id"],
                                username=user_data["username"],
                                password_hash=user_data["password_hash"],
                                role=UserRole(user_data["role"]),
                                created_at=user_data["created_at"],
                                artifacts=self.db.get_user_artifacts(user_data["id"]),
                                failed_login_attempts=user_data.get("failed_login_attempts", 0),
                                last_login_attempt=user_data.get("last_login_attempt", 0)
                            )
        except Exception as e:
            print(f"Error loading session: {str(e)}")
            
    def _save_session(self, user_id: str):  # Changed from username to user_id
        """Save user session"""
        try:
            with open(SESSION_FILE, "w") as f:
                json.dump({"user_id": user_id}, f)  # Changed from username to user_id
        except Exception as e:
            print(f"Error saving session: {str(e)}")
            
    def _clear_session(self):
        """Clear user session"""
        try:
            if os.path.exists(SESSION_FILE):
                os.remove(SESSION_FILE)
        except Exception as e:
            print(f"Error clearing session: {str(e)}")
            
    def login(self) -> bool:
        """Handle user login with rate limiting"""
        print("\nSecure Digital Copyright Management System")
        print("----------------------------------------")
        
        username = input("Username: ").strip()
        if not username:
            print("Username cannot be empty")
            return False
            
        # Check if user exists and isn't locked
        user_data = self.db.get_user_by_username(username)
        if not user_data:
            print("Invalid username or password")
            return False
            
        # Check for account lockout
        if user_data.get("account_locked"):
            print("Account is locked due to too many failed attempts.")
            print("Please contact your administrator.")
            return False
            
        # Check rate limiting
        last_attempt = user_data.get("last_login_attempt", 0)
        if datetime.now().timestamp() - last_attempt < 30:  # 30 second delay between attempts
            print("Please wait before trying again")
            return False
            
        password = getpass.getpass("Password: ")
        if not password:
            print("Password cannot be empty")
            return False
            
        # Attempt authentication
        user = self.rbac_manager.authenticate(username, password)
        if user:
            self.current_user = user
            self.db.update_login_attempt(username, True)
            self.logger.log_auth_attempt(username, True, "127.0.0.1")
            self._save_session(user.id)
            print(f"\nWelcome {username}! You are logged in as: {user.role.value}")
            return True
            
        # Handle failed login
        self.db.update_login_attempt(username, False)
        self.logger.log_auth_attempt(username, False, "127.0.0.1")
        print("Invalid username or password")
        return False
        
    def require_auth(self):
        """Check if user is authenticated"""
        if not self.current_user:
            print("Please login first")
            sys.exit(1)
            
    def create_user(self, username: str, password: str, role: UserRole) -> bool:
        """Create a new user with secure password"""
        self.require_auth()
        if self.current_user.role != UserRole.ADMIN:
            print("Only administrators can create new users")
            return False
            
        user = self.rbac_manager.create_user(username, password, role)
        if not user:
            print("Failed to create user. Password must meet complexity requirements:")
            print("- Minimum 8 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter")
            print("- At least one number")
            print("- At least one special character")
            return False
            
        # Store user in database
        self.db.create({
            "table": "users",
            "id": user.id,
            "username": user.username,
            "password_hash": user.password_hash,
            "role": user.role.value,
            "created_at": user.created_at,
            "password_last_changed": datetime.now().timestamp()
        })
        
        print(f"User {username} created successfully with role {role.value}")
        return True

    def login_with_credentials(self, username: str, password: str) -> bool:
        """Handle user login with rate limiting"""
        if not username or not password:
            print("Username and password cannot be empty")
            return False
        
        # Check if user exists and isn't locked
        user_data = self.db.get_user_by_username(username)
        if not user_data:
            print("Invalid username or password")
            return False
        
        # Check for account lockout
        if user_data.get("account_locked"):
            print("Account is locked due to too many failed attempts.")
            print("Please contact your administrator.")
            return False
        
        # Check rate limiting
        last_attempt = user_data.get("last_login_attempt", 0)
        if datetime.now().timestamp() - last_attempt < 30:  # 30 second delay between attempts
            print("Please wait before trying again")
            return False
        
        # Attempt authentication
        user = self.rbac_manager.authenticate(username, password)
        if user:
            self.current_user = user
            self.db.update_login_attempt(username, True)
            self.logger.log_auth_attempt(username, True, "127.0.0.1")
            self._save_session(user.id)
            print(f"\nWelcome {username}! You are logged in as: {user.role.value}")
            return True
        
        # Handle failed login
        self.db.update_login_attempt(username, False)
        self.logger.log_auth_attempt(username, False, "127.0.0.1")
        print("Invalid username or password")
        return False

    def logout(self) -> None:
        """Logout current user"""
        if self.current_user:
            self._clear_session()
            self.current_user = None
            print("Logged out successfully")
        else:
            print("No user is currently logged in")

@click.group()
@click.pass_context
def main(ctx):
    """Secure Digital Copyright Management System"""
    ctx.obj = CLI()

@main.command()
@click.argument("username")
@click.pass_obj
def login(cli: CLI, username: str):
    """Login to the system"""
    password = getpass.getpass("Password: ")
    if cli.login_with_credentials(username, password):
        print("Login successful")
    else:
        sys.exit(1)

@main.command()
@click.argument("username")
@click.argument("role", type=click.Choice(["admin", "owner", "viewer"]))
@click.pass_obj
def create_user(cli: CLI, username: str, role: str):
    """Create a new user (admin only)"""
    cli.require_auth()
    
    if cli.current_user.role != UserRole.ADMIN:
        print("Only administrators can create new users")
        sys.exit(1)
        
    password = getpass.getpass("Enter password for new user: ")
    confirm = getpass.getpass("Confirm password: ")
    
    if password != confirm:
        print("Passwords do not match")
        sys.exit(1)
        
    role_enum = UserRole(role.lower())
    user = cli.rbac_manager.create_user(username, password, role_enum)
    if not user:
        print("Failed to create user. Password must meet complexity requirements:")
        print("- Minimum 8 characters")
        print("- At least one uppercase letter")
        print("- At least one lowercase letter")
        print("- At least one number")
        print("- At least one special character")
        sys.exit(1)
        
    # Store user in database
    cli.db.create({
        "table": "users",
        "id": user.id,
        "username": user.username,
        "password_hash": user.password_hash,
        "role": user.role.value,
        "created_at": user.created_at,
        "password_last_changed": datetime.now().timestamp()
    })
    
    print(f"User {username} created successfully with role {role}")

@main.command()
@click.argument('file')
@click.option('--name', help='Name of the artifact')
@click.option('--type', 'content_type', help='Content type of the artifact')
@click.pass_obj
def upload(cli: CLI, file: str, name: str = None, content_type: str = None):
    """Upload a file to the system"""
    try:
        # Validate file exists
        if not os.path.exists(file):
            click.echo(f"Error: File {file} does not exist")
            sys.exit(1)

        # Check authentication
        cli.require_auth()

        # Use filename as name if not provided
        if not name:
            name = os.path.basename(file)

        # Get file extension and determine content type
        _, ext = os.path.splitext(file)
        if not content_type:
            content_type = ContentType.from_extension(ext.lstrip('.')).value

        # Get file size
        file_size = os.path.getsize(file)
        
        # Validate file size (e.g., limit to 100MB)
        max_size = 100 * 1024 * 1024  # 100MB in bytes
        if file_size > max_size:
            click.echo(f"\nError: File size ({file_size / 1024 / 1024:.1f}MB) exceeds maximum allowed size (100MB)")
            sys.exit(1)

        click.echo("\nProcessing upload request...")
        click.echo(f"File size: {file_size / 1024 / 1024:.1f}MB")
        click.echo(f"Content type: {content_type}")
        
        # Upload file
        artifact_id = cli.secure_enclave.handle_upload_request(
            user=cli.current_user,
            file_path=file,
            name=name,
            content_type=content_type,
            file_size=file_size
        )

        if artifact_id:
            click.echo("\nSuccess! File uploaded successfully.")
            click.echo(f"Artifact ID: {artifact_id}")
            click.echo(f"Name: {name}")
            click.echo(f"Type: {content_type}")
            click.echo(f"Size: {file_size / 1024 / 1024:.1f}MB")
        else:
            click.echo("\nError: Failed to upload file.")
            click.echo("Please check your permissions and try again.")
            sys.exit(1)

    except Exception as e:
        click.echo(f"\nError: {str(e)}")
        sys.exit(1)

@main.command()
@click.argument('artifact_id')
@click.argument('output', type=click.Path())
@click.pass_obj
def download(cli: CLI, artifact_id: str, output: str):
    """Download and decrypt an artifact"""
    cli.require_auth()
    
    try:
        print("\nProcessing download request...")
        print("1. Authenticating and checking permissions...")
        
        print("2. Retrieving encrypted file...")
        content = cli.artifact_service.read_artifact(
            cli.current_user,
            artifact_id
        )
        
        if content:
            print("3. Decrypting and verifying file...")
            with open(output, 'wb') as f:
                f.write(content)
                
            print("4. Saving file...")
            file_size = len(content) / 1024  # KB
            print(f"\nSuccess! File saved to: {output}")
            print(f"Size: {file_size:.1f} KB")
        else:
            print("\nError: Failed to read artifact")
            print("Please check your permissions and artifact ID.")
            sys.exit(1)
            
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

@main.command()
@click.pass_obj
def list(cli: CLI):
    """List available artifacts"""
    cli.require_auth()
    
    print("\nRetrieving artifact list...")
    artifacts = cli.artifact_service.list_artifacts(cli.current_user)
    
    if not artifacts:
        print("No artifacts found")
        return
        
    print(f"\nFound {len(artifacts)} artifact(s):")
    for artifact in artifacts:
        print(f"\nID: {artifact['id']}")
        print(f"Name: {artifact['name']}")
        print(f"Type: {artifact['content_type']}")
        print(f"Created: {artifact['created_at']}")
        if cli.current_user.role in [UserRole.ADMIN, UserRole.OWNER]:
            print(f"Owner ID: {artifact['owner_id']}")
            print(f"Checksum: {artifact['checksum']}")

@main.command()
@click.pass_obj
def whoami(cli: CLI):
    """Show current user information"""
    cli.require_auth()
    user = cli.current_user
    print(f"\nCurrent user information:")
    print(f"Username: {user.username}")
    print(f"Role: {user.role.value}")
    print(f"User ID: {user.id}")
    if user.role == UserRole.OWNER:
        artifacts = cli.db.get_user_artifacts(user.id)
        print(f"Owned artifacts: {len(artifacts)}")
        if artifacts:
            print("\nOwned artifact IDs:")
            for artifact_id in artifacts:
                print(f"- {artifact_id}")

@main.command()
@click.pass_obj
def logout(cli: CLI):
    """Logout from the system"""
    cli.logout()

def get_current_user() -> Optional[User]:
    """Get the current logged in user"""
    try:
        # Check if session file exists
        if not os.path.exists(SESSION_FILE):
            return None

        # Read session file
        with open(SESSION_FILE, 'r') as f:
            session_data = json.load(f)

        # Check if session is valid
        if not session_data or 'user_id' not in session_data:
            return None

        # Get user from database
        storage = SQLiteStorage()
        user_data = storage.get(session_data['user_id'], 'users')
        
        if not user_data:
            return None

        # Create user object
        return User(
            id=user_data['id'],
            username=user_data['username'],
            role=UserRole(user_data['role']),
            created_at=user_data['created_at'],
            password_last_changed=user_data['password_last_changed']
        )

    except Exception as e:
        print(f"Error getting current user: {str(e)}")
        return None

if __name__ == "__main__":
    main() 