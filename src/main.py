from typing import Optional
import os
import json
import getpass
from .models.user import User, UserRole
from .auth.rbac import RBACManager
from .services.secure_enclave_service import SecureEnclaveService
from .storage.db_storage import SQLiteStorage
from .models.content_type import ContentType

SESSION_FILE = ".session"

class DCMSystem:
    def __init__(self):
        self.db = SQLiteStorage()
        self.rbac = RBACManager()
        self.secure_enclave = SecureEnclaveService()
        self.current_user = None
        # Clear any existing session on startup
        self._clear_session()

    def _load_session(self):
        """Load user session if exists"""
        try:
            if os.path.exists(SESSION_FILE):
                with open(SESSION_FILE, 'r') as f:
                    session_data = json.load(f)
                    if session_data.get("user_id"):
                        user_data = self.db.read(session_data["user_id"], "users")
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
            print(f"Error loading session: {e}")
            self.current_user = None

    def _save_session(self, user_id: str):
        """Save user session"""
        try:
            with open(SESSION_FILE, 'w') as f:
                json.dump({"user_id": user_id}, f)
        except Exception as e:
            print(f"Error saving session: {e}")

    def _clear_session(self):
        """Clear user session"""
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
        self.current_user = None

    def create_user(self, username: str, password: str, role: UserRole) -> bool:
        """Create a new user"""
        user = self.rbac.create_user(username, password, role)
        if user:
            user_data = {
                "table": "users",
                "id": user.id,
                "username": user.username,
                "password_hash": user.password_hash,
                "role": user.role.value,
                "created_at": user.created_at,
                "password_last_changed": user.created_at
            }
            return bool(self.db.create(user_data))
        return False

    def login(self, username: str, password: str) -> bool:
        """Login with username and password"""
        user = self.rbac.authenticate(username, password)
        if user:
            self.current_user = user
            self._save_session(user.id)
            return True
        return False

    def logout(self):
        """Logout current user"""
        if self.current_user:
            self._clear_session()
            print("Logged out successfully")
        else:
            print("No user is currently logged in")

    def create_user_menu(self):
        """Handle user creation"""
        print("\nCreate New User")
        print("==============")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        
        if self.current_user and self.current_user.role == UserRole.ADMIN:
            print("\nSelect role:")
            print("1. Admin")
            print("2. Owner")
            print("3. Viewer")
            role_choice = input("Enter role (1-3): ")
            role_map = {"1": UserRole.ADMIN, "2": UserRole.OWNER, "3": UserRole.VIEWER}
            role = role_map.get(role_choice)
        else:
            role = UserRole.OWNER

        if not role:
            print("Invalid role selected.")
            return

        if self.create_user(username, password, role):
            print(f"User {username} created successfully!")
        else:
            print("Failed to create user. Please check requirements and try again.")

    def login_menu(self):
        """Handle login"""
        print("\nUser Login")
        print("==========")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        
        if self.login(username, password):
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
        file_path = input("Enter file path: ")
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

        print("\nDownload Artifact")
        print("================")
        artifact_id = input("Enter artifact ID: ")
        output_path = input("Enter output path: ")
        
        content = self.secure_enclave.handle_download_request(self.current_user, artifact_id)
        if content:
            try:
                with open(output_path, 'wb') as f:
                    f.write(content)
                print(f"Artifact downloaded successfully to {output_path}")
            except Exception as e:
                print(f"Error saving file: {e}")
        else:
            print("Failed to download artifact. Check permissions and artifact ID.")

    def list_artifacts(self):
        """List available artifacts"""
        if not self.current_user:
            print("Please login first")
            return
            
        print("\nAvailable Artifacts")
        print("==================")
        
        try:
            # Get artifacts from artifact service instead of secure enclave
            artifacts = self.secure_enclave.db.list("artifacts")
            
            # Filter based on user role
            if self.current_user.role == UserRole.OWNER:
                artifacts = [a for a in artifacts if a["owner_id"] == self.current_user.id]
            
            if not artifacts:
                print("\nNo artifacts available.")
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
            
        except Exception as e:
            print(f"Error listing artifacts: {e}")
            print("Please try again later.")

    def show_user_info(self):
        """Display current user information"""
        if not self.current_user:
            print("No user logged in.")
            return
            
        print("\nUser Information")
        print("===============")
        print(f"Username: {self.current_user.username}")
        print(f"Role: {self.current_user.role.value}")
        if self.current_user.role == UserRole.OWNER:
            print(f"Owned artifacts: {len(self.current_user.artifacts)}")

    def delete_artifact(self):
        """Handle artifact deletion"""
        if not self.current_user:
            print("Please login first")
            return

        if self.current_user.role not in [UserRole.ADMIN, UserRole.OWNER]:
            print("Permission denied")
            return

        print("\nDelete Artifact")
        print("==============")
        artifact_id = input("Enter artifact ID: ")
        
        if self.secure_enclave.delete_artifact(self.current_user, artifact_id):
            print("Artifact deleted successfully!")
        else:
            print("Failed to delete artifact. Check permissions and artifact ID.")

def main():
    system = DCMSystem()
    
    while True:
        if not system.current_user:
            print("\nDigital Copyright Management System")
            print("==================================")
            print("1. Create new account")
            print("2. Login")
            print("3. Exit")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == "1":
                system.create_user_menu()
            elif choice == "2":
                system.login_menu()
            elif choice == "3":
                print("\nGoodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            print(f"\nWelcome {system.current_user.username}!")
            print("1. Upload artifact")
            print("2. Download artifact")
            print("3. List artifacts")
            print("4. Show my info")
            if system.current_user.role == UserRole.ADMIN:
                print("5. Create user")
            if system.current_user.role in [UserRole.ADMIN, UserRole.OWNER]:
                print("6. Delete artifact")
            print("7. Logout")
            print("8. Exit")
            
            choice = input("\nEnter your choice: ")
            
            if choice == "1":
                system.upload_artifact()
            elif choice == "2":
                system.download_artifact()
            elif choice == "3":
                system.list_artifacts()
            elif choice == "4":
                system.show_user_info()
            elif choice == "5" and system.current_user.role == UserRole.ADMIN:
                system.create_user_menu()
            elif choice == "6" and system.current_user.role in [UserRole.ADMIN, UserRole.OWNER]:
                system.delete_artifact()
            elif choice == "7":
                system.logout()
            elif choice == "8":
                print("\nGoodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 