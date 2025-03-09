import click
import getpass
import sys
import json
from typing import Optional
from pathlib import Path
import os
import signal
import atexit
from datetime import datetime, timedelta
from src.models.user import User, UserRole
from src.services.artifact_service import ArtifactService
from src.utils.logging import AuditLogger
from src.auth.rbac import RBACManager
from src.storage.db_storage import SQLiteStorage
from src.services.secure_enclave_service import SecureEnclaveService
from src.models.content_type import ContentType
import sqlite3

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
        
        # Register cleanup handlers
        atexit.register(self._cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _cleanup(self):
        """Cleanup function to be called on program exit"""
        if self.current_user:
            print("\nLogging out due to program termination...")
            self.logout()
            
    def _signal_handler(self, signum, frame):
        """Handle termination signals"""
        print("\nReceived termination signal. Cleaning up...")
        self._cleanup()
        sys.exit(0)
        
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
                        else:
                            self.current_user = None
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
            
        try:
            password = getpass.getpass("Password: ")
        except:
            # Fallback to regular input if getpass fails
            password = input("Password: ")
            
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
            print("Failed to create user. Password must meet the following requirements:")
            print("- Minimum 12 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter")
            print("- At least one number")
            print("- At least one special character (!@#$%^&*(),.?\":{}|<>)")
            print("- No common patterns (e.g., 12345, qwerty, password)")
            print("- No repeated characters (3 or more of the same character)")
            print("- No common words (e.g., admin, user, login, test)")
            return False
            
        # Store user in database
        user_data = {
            "table": "users",
            "id": user.id,
            "username": user.username,
            "password_hash": user.password_hash,
            "role": user.role.value,
            "created_at": user.created_at,
            "failed_login_attempts": 0,
            "last_login_attempt": 0,
            "account_locked": False,
            "password_last_changed": datetime.now().timestamp()
        }
        
        try:
            if self.db.create(user_data):
                print(f"User {username} created successfully with role {role.value}")
                return True
            else:
                print("Failed to create user in database")
                return False
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            return False

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

    def show_main_menu(self):
        """Display main menu and handle user input"""
        while True:
            print("\nDigital Copyright Management System")
            print("==================================")
            if not self.current_user:
                print("1. Login")
                print("2. Exit")
                try:
                    choice = input("Enter your choice (1-2): ")
                    if choice == "1":
                        if self.login():  # Call login directly
                            self.show_user_menu()
                    elif choice == "2":
                        print("Goodbye!")
                        break
                    else:
                        print("Invalid choice. Please try again.")
                except Exception as e:
                    print(f"Error: {e}")
            else:
                self.show_user_menu()

    def show_user_menu(self):
        """Display user menu based on role"""
        while True:
            print(f"\nWelcome {self.current_user.username}!")
            print("\nAvailable Actions:")
            
            menu_options = []
            option_number = 1
            
            # Admin-specific options
            if self.current_user.role == UserRole.ADMIN:
                menu_options.append((str(option_number), "Create new user"))
                option_number += 1
                menu_options.append((str(option_number), "Manage users"))
                option_number += 1
            
            # Owner/Admin options
            if self.current_user.role in [UserRole.ADMIN, UserRole.OWNER]:
                menu_options.append((str(option_number), "Upload artifact"))
                option_number += 1
                menu_options.append((str(option_number), "Download artifact"))
                option_number += 1
                menu_options.append((str(option_number), "Delete artifact"))
                option_number += 1
            
            # Common options for all roles
            menu_options.append((str(option_number), "List artifacts"))
            option_number += 1
            menu_options.append((str(option_number), "Show my info"))
            option_number += 1
            menu_options.append((str(option_number), "Logout"))
            
            # Display menu options
            for option, text in menu_options:
                print(f"{option}. {text}")
            
            try:
                choice = input(f"\nEnter your choice (1-{len(menu_options)}): ")
                if choice not in [opt[0] for opt in menu_options]:
                    print("Invalid choice. Please try again.")
                    continue
                
                selected_action = menu_options[int(choice)-1][1]
                
                if selected_action == "Create new user":
                    self.create_user_menu()
                elif selected_action == "Manage users":
                    self.manage_users_menu()
                elif selected_action == "Upload artifact":
                    self.upload_artifact()
                elif selected_action == "Download artifact":
                    self.download_artifact()
                elif selected_action == "Delete artifact":
                    self.delete_artifact_menu()
                elif selected_action == "List artifacts":
                    self.list_artifacts()
                elif selected_action == "Show my info":
                    self.show_user_info()
                elif selected_action == "Logout":
                    self.logout()
                    break
            except Exception as e:
                print(f"Error: {e}")

    def create_user_menu(self):
        """Handle user creation interactively"""
        print("\nCreate New User")
        print("==============")
        
        # Get username
        username = input("Enter username: ")
        if not username:
            print("Username cannot be empty")
            return
            
        # Check if username already exists
        if self.db.get_user_by_username(username):
            print("Username already exists")
            return
            
        # Show password requirements
        print("\nPassword must meet the following requirements:")
        print("- Minimum 12 characters")
        print("- At least one uppercase letter")
        print("- At least one lowercase letter")
        print("- At least one number")
        print("- At least one special character (!@#$%^&*(),.?\":{}|<>)")
        print("- No common patterns (e.g., 12345, qwerty, password)")
        print("- No repeated characters (3 or more of the same character)")
        print("- No common words (e.g., admin, user, login, test)")
        
        # Get and confirm password
        password = getpass.getpass("\nEnter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match")
            return
            
        # Validate password complexity
        if not self.rbac_manager._validate_password(password):
            print("Password does not meet complexity requirements")
            return
        
        # Get role
        if self.current_user and self.current_user.role == UserRole.ADMIN:
            print("\nSelect role:")
            print("1. Admin")
            print("2. Owner")
            print("3. Viewer")
            role_choice = input("Enter role (1-3): ")
            role_map = {"1": UserRole.ADMIN, "2": UserRole.OWNER, "3": UserRole.VIEWER}
            role = role_map.get(role_choice)
            
            if not role:
                print("Invalid role selected")
                return
        else:
            role = UserRole.OWNER

        # Create user
        if self.create_user(username, password, role):
            print(f"\nUser {username} created successfully with role {role.value}!")
        else:
            print("Failed to create user. Please try again.")

    def login_menu(self):
        """Handle login interactively"""
        print("\nUser Login")
        print("==========")
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        if self.login_with_credentials(username, password):
            print(f"Welcome {username}!")
        else:
            print("Login failed. Please check your credentials.")

    def upload_artifact(self):
        """Handle artifact upload"""
        if not self.current_user:
            print("Please login first")
            return

        print("\nUpload Artifact")
        print("==============")
        print("\nYou can upload files from any location on your system.")
        print("Examples:")
        print("  Windows: C:\\Users\\YourName\\Documents\\file.txt")
        print("  Linux/Mac: /home/username/documents/file.txt")
        print("\nNote: Use forward slashes (/) or escaped backslashes (\\\\) in the path")
        file_path = input("\nEnter file path: ")
        name = input("Enter artifact name: ")
        
        print("\nSelect content type:")
        print("1. Lyrics")
        print("2. Musical Score")
        print("3. Audio (MP3)")
        print("4. Audio (WAV)")
        print("5. Video (MP4)")
        print("6. Video (AVI)")
        print("7. Document")
        
        type_map = {
            "1": ContentType.LYRICS,
            "2": ContentType.SCORE,
            "3": ContentType.AUDIO_MP3,
            "4": ContentType.AUDIO_WAV,
            "5": ContentType.VIDEO_MP4,
            "6": ContentType.VIDEO_AVI,
            "7": ContentType.DOCUMENT
        }
        
        type_choice = input("Enter content type (1-7): ")
        content_type = type_map.get(type_choice)
        
        if not content_type:
            print("Invalid content type selected.")
            return

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                file_size = len(content)
                
            artifact_id = self.secure_enclave.handle_upload_request(
                user=self.current_user,
                file_path=file_path,
                name=name,
                content_type=content_type.value,
                file_size=file_size
            )
            
            if artifact_id:
                print(f"Artifact uploaded successfully! ID: {artifact_id}")
            else:
                print("Failed to upload artifact.")
        except FileNotFoundError:
            print("File not found. Please check the path and try again.")
        except Exception as e:
            print(f"Error uploading file: {e}")

    def download_artifact(self):
        """Handle artifact download"""
        if not self.current_user:
            print("Please login first")
            return

        # Check if user has download permissions
        if self.current_user.role == UserRole.VIEWER:
            print("Error: Viewers do not have permission to download artifacts")
            return

        print("\nDownload Artifact")
        print("================")
        artifact_id = input("Enter artifact ID: ")
        
        # First get the artifact to get its name
        artifact = self.db.read(artifact_id, "artifacts")
        if not artifact:
            print("Artifact not found")
            return
            
        # Get default filename from artifact name
        default_filename = artifact["name"]
        print(f"\nOriginal filename: {default_filename}")
        
        # Get output directory
        print("\nEnter the directory where you want to save the file")
        print("Example: C:\\Users\\YourName\\Downloads")
        output_dir = input("Save to directory: ").strip()
        
        if not os.path.isdir(output_dir):
            print("Invalid directory path or directory doesn't exist")
            return
            
        # Get output filename, default to original name
        print("\nEnter the filename to save as (press Enter to use original name)")
        output_filename = input(f"Filename [{default_filename}]: ").strip()
        if not output_filename:
            output_filename = default_filename
            
        # Combine directory and filename
        output_path = os.path.join(output_dir, output_filename)
        
        # Confirm if file exists
        if os.path.exists(output_path):
            confirm = input(f"\nFile {output_filename} already exists. Overwrite? (y/N): ")
            if confirm.lower() != 'y':
                print("Download cancelled")
                return
        
        content = self.secure_enclave.handle_download_request(self.current_user, artifact_id)
        if content:
            try:
                with open(output_path, 'wb') as f:
                    f.write(content)
                print(f"\nArtifact downloaded successfully to:")
                print(output_path)
            except Exception as e:
                print(f"Error saving file: {e}")
                print("\nPlease ensure you have write permissions to the directory")
                print("and that the filename is valid for your operating system.")
        else:
            print("Failed to download artifact. Check permissions and artifact ID.")

    def delete_artifact_menu(self):
        """Handle artifact deletion interactively"""
        if not self.current_user:
            print("Please login first")
            return

        if self.current_user.role not in [UserRole.ADMIN, UserRole.OWNER]:
            print("Permission denied: Only admins and owners can delete artifacts")
            return

        print("\nDelete Artifact")
        print("==============")
        
        # List available artifacts first
        artifacts = self.secure_enclave.list_artifacts(self.current_user)
        if not artifacts:
            print("No artifacts available to delete")
            return
            
        print("\nAvailable artifacts:")
        for artifact in artifacts:
            if self.current_user.role == UserRole.ADMIN:
                print(f"ID: {artifact['id']} | Name: {artifact['name']} | Owner: {artifact['owner_id']}")
            elif self.current_user.role == UserRole.OWNER and artifact['owner_id'] == self.current_user.id:
                print(f"ID: {artifact['id']} | Name: {artifact['name']}")
        
        artifact_id = input("\nEnter artifact ID to delete: ")
        
        # Verify artifact exists
        artifact = next((a for a in artifacts if a['id'] == artifact_id), None)
        if not artifact:
            print("Invalid artifact ID")
            return
            
        # Check ownership for OWNER role
        if self.current_user.role == UserRole.OWNER and artifact['owner_id'] != self.current_user.id:
            print("Permission denied: You can only delete your own artifacts")
            return
            
        # Confirm deletion
        confirm = input(f"\nAre you sure you want to delete artifact '{artifact['name']}'? (y/N): ")
        if confirm.lower() != 'y':
            print("Deletion cancelled")
            return
            
        if self.secure_enclave.delete_artifact(self.current_user, artifact_id):
            print("Artifact deleted successfully!")
        else:
            print("Failed to delete artifact. Please try again.")

    def show_user_info(self):
        """Display current user information"""
        if not self.current_user:
            print("No user logged in.")
            return
            
        print("\nUser Information")
        print("===============")
        print(f"Username: {self.current_user.username}")
        print(f"Role: {self.current_user.role.value}")
        
        # Get artifacts based on user role
        artifacts = []
        if self.current_user.role == UserRole.ADMIN:
            artifacts = self.secure_enclave.list_artifacts(self.current_user)
            print(f"Total artifacts in system: {len(artifacts)}")
        elif self.current_user.role == UserRole.OWNER:
            artifacts = self.secure_enclave.list_artifacts(self.current_user)
            print(f"Your artifacts: {len(artifacts)}")
            if artifacts:
                print("\nArtifact Details:")
                for artifact in artifacts:
                    print(f"- {artifact['name']} ({artifact['content_type']}, {artifact['file_size']} bytes)")
        else:  # Viewer
            artifacts = self.secure_enclave.list_artifacts(self.current_user)
            print(f"Viewable artifacts: {len(artifacts)}")
            
        # Show additional user info
        user_data = self.db.get_user_by_username(self.current_user.username)
        if user_data:
            status = "LOCKED" if user_data.get("account_locked") else "ACTIVE"
            print(f"\nAccount Status: {status}")
            print(f"Failed login attempts: {user_data.get('failed_login_attempts', 0)}")
            last_changed = datetime.fromtimestamp(user_data.get('password_last_changed', 0))
            print(f"Last password change: {last_changed.strftime('%Y-%m-%d %H:%M:%S')}")

    def list_artifacts(self):
        """List available artifacts"""
        if not self.current_user:
            print("Please login first.")
            return
            
        print("\nAvailable Artifacts")
        print("==================")
        artifacts = self.secure_enclave.list_artifacts(self.current_user)
        
        if not artifacts:
            print("No artifacts found.")
            return
            
        # Calculate column widths
        id_width = max(len("ID"), max(len(str(a["id"])) for a in artifacts))
        name_width = max(len("Name"), max(len(str(a["name"])) for a in artifacts))
        type_width = max(len("Type"), max(len(str(a["content_type"])) for a in artifacts))
        size_width = max(len("Size (bytes)"), max(len(str(a["file_size"])) for a in artifacts))
        owner_width = 0
        if self.current_user.role == UserRole.ADMIN:
            owner_width = max(len("Owner"), max(len(str(a["owner_id"])) for a in artifacts))
        
        # Print header
        header = f"| {'ID':<{id_width}} | {'Name':<{name_width}} | {'Type':<{type_width}} | {'Size (bytes)':<{size_width}} |"
        if self.current_user.role == UserRole.ADMIN:
            header += f" {'Owner':<{owner_width}} |"
        print("\n" + "=" * len(header))
        print(header)
        print("=" * len(header))
        
        # Print artifacts
        for artifact in artifacts:
            row = f"| {str(artifact['id']):<{id_width}} | {str(artifact['name']):<{name_width}} | {str(artifact['content_type']):<{type_width}} | {str(artifact['file_size']):<{size_width}} |"
            if self.current_user.role == UserRole.ADMIN:
                row += f" {str(artifact['owner_id']):<{owner_width}} |"
            print(row)
        
        print("=" * len(header))
        print(f"\nTotal artifacts: {len(artifacts)}")

    def manage_users_menu(self):
        """Handle user management operations"""
        if not self.current_user or self.current_user.role != UserRole.ADMIN:
            print("Only administrators can manage users")
            return

        while True:
            print("\nManage Users")
            print("============")
            print("1. List all users")
            print("2. Reset user password")
            print("3. Lock/Unlock user")
            print("4. Delete user")
            print("5. Back to main menu")

            choice = input("\nEnter your choice (1-5): ")

            if choice == "1":
                self._list_users()
            elif choice == "2":
                self._reset_user_password()
            elif choice == "3":
                self._toggle_user_lock()
            elif choice == "4":
                self._delete_user()
            elif choice == "5":
                break
            else:
                print("Invalid choice. Please try again.")

    def _list_users(self):
        """List all users in the system"""
        users = self.db.list("users")
        if not users:
            print("\nNo users found")
            return

        print("\nUser List:")
        print("==========")
        for user in users:
            status = "LOCKED" if user["account_locked"] else "ACTIVE"
            print(f"\nUsername: {user['username']}")
            print(f"Role: {user['role']}")
            print(f"Status: {status}")
            print(f"Failed login attempts: {user['failed_login_attempts']}")
            print(f"Last password change: {datetime.fromtimestamp(user['password_last_changed']).strftime('%Y-%m-%d %H:%M:%S')}")

    def _reset_user_password(self):
        """Reset a user's password"""
        username = input("\nEnter username to reset password: ")
        user_data = self.db.get_user_by_username(username)
        
        if not user_data:
            print("User not found")
            return
            
        print("\nNew password must meet the following requirements:")
        print("- Minimum 12 characters")
        print("- At least one uppercase letter")
        print("- At least one lowercase letter")
        print("- At least one number")
        print("- At least one special character (!@#$%^&*(),.?\":{}|<>)")
        print("- No common patterns (e.g., 12345, qwerty, password)")
        print("- No repeated characters (3 or more of the same character)")
        print("- No common words (e.g., admin, user, login, test)")
        
        new_password = getpass.getpass("\nEnter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("Passwords do not match")
            return
            
        # Validate password complexity
        if not self.rbac_manager._validate_password(new_password):
            print("Password does not meet complexity requirements")
            return
            
        # Hash new password
        new_hash = self.rbac_manager.hash_password(new_password)
        
        # Update password in database
        success = self.db.update({
            "table": "users",
            "id": user_data["id"],
            "password_hash": new_hash,
            "password_last_changed": datetime.now().timestamp(),
            "failed_login_attempts": 0,
            "account_locked": False
        })
        
        if success:
            print(f"\nPassword reset successful for user {username}")
            self.logger.log_event(
                "password_reset",
                self.current_user.id,
                {"target_user": username}
            )
        else:
            print("Failed to reset password")

    def _toggle_user_lock(self):
        """Lock or unlock a user account"""
        username = input("\nEnter username to toggle lock status: ")
        user_data = self.db.get_user_by_username(username)
        
        if not user_data:
            print("User not found")
            return
            
        if user_data["role"] == "admin":
            print("Cannot lock/unlock admin accounts")
            return
            
        new_status = not user_data["account_locked"]
        success = self.db.update({
            "table": "users",
            "id": user_data["id"],
            "account_locked": new_status,
            "failed_login_attempts": 0 if not new_status else user_data["failed_login_attempts"]
        })
        
        if success:
            status = "locked" if new_status else "unlocked"
            print(f"\nUser {username} has been {status}")
            self.logger.log_event(
                "account_status_change",
                self.current_user.id,
                {"target_user": username, "new_status": status}
            )
        else:
            print("Failed to update user status")

    def _delete_user(self):
        """Delete a user from the system"""
        username = input("\nEnter username to delete: ")
        user_data = self.db.get_user_by_username(username)
        
        if not user_data:
            print("User not found")
            return
            
        if user_data["role"] == "admin":
            print("Cannot delete admin accounts")
            return
            
        confirm = input(f"\nAre you sure you want to delete user {username}? (y/N): ")
        if confirm.lower() != 'y':
            print("Deletion cancelled")
            return
            
        # Delete user's artifacts first
        artifacts = self.db.list("artifacts")
        for artifact in artifacts:
            if artifact["owner_id"] == user_data["id"]:
                self.db.delete(artifact["id"], "artifacts")
                
        # Delete user's entries in user_artifacts
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_artifacts WHERE user_id = ?", (user_data["id"],))
            
        # Finally delete the user
        success = self.db.delete(user_data["id"], "users")
        
        if success:
            print(f"\nUser {username} has been deleted")
            self.logger.log_event(
                "user_deletion",
                self.current_user.id,
                {"target_user": username}
            )
        else:
            print("Failed to delete user")

@click.group()
@click.pass_context
def main(ctx):
    """Secure Digital Copyright Management System"""
    try:
        cli = CLI()
        cli.show_main_menu()
    except KeyboardInterrupt:
        print("\nProgram terminated by user. Cleaning up...")
        if cli:
            cli._cleanup()
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        if cli:
            cli._cleanup()
    finally:
        sys.exit(0)

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
        content = cli.secure_enclave.read_artifact(
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
    artifacts = cli.secure_enclave.list_artifacts(cli.current_user)
    
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