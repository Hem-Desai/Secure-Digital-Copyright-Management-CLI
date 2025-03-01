# Secure Digital Copyright Management CLI - Code Documentation

## Project Overview

This project implements a secure digital copyright management (DCM) system as a command-line interface (CLI) application. The system provides a robust platform for content creators to protect their digital assets while managing access rights for viewers. It features strong encryption, role-based access control, and comprehensive audit logging to ensure content security and tracking.

## Core Components

### 1. Command Line Interface (`src/cli.py`)

The CLI module serves as the primary interface between users and the system. It provides an intuitive command-line interface that handles user authentication, content management, and rights administration. The module implements rate limiting for security, session management for user convenience, and comprehensive input validation to prevent security vulnerabilities.

Key features:

- Secure user authentication with rate limiting and account lockout
- Interactive menus for different user roles
- Session management for persistent login
- Comprehensive input validation and error handling
- Audit logging of all user actions

````python
class CLI:
    def __init__(self):
        self.db = SQLiteStorage()
        self.rbac_manager = RBACManager()
        self.logger = AuditLogger()
        self.secure_enclave = SecureEnclaveService()
        self.current_user: Optional[User] = None
        self._load_session()

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

        password = getpass.getpass("Password: ")
        # ... authentication logic ...

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
                        self.login_menu()
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

            # Common options for all roles
            menu_options.append((str(option_number), "Download artifact"))
            option_number += 1
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
        """Handle user creation (Admin only)"""
        if self.current_user.role != UserRole.ADMIN:
            print("Error: Only administrators can create new users")
            return

        print("\nCreate New User")
        print("==============")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")

        print("\nSelect role:")
        print("1. Owner")
        print("2. Viewer")
        role_choice = input("Enter role (1-2): ")
        role_map = {"1": UserRole.OWNER, "2": UserRole.VIEWER}
        role = role_map.get(role_choice)

        if not role:
            print("Invalid role selected.")
            return

        if self.create_user(username, password, role):
            print(f"User {username} created successfully!")
        else:
            print("Failed to create user. Please check requirements and try again.")

### 2. Main Application Logic (`src/main.py`)

The core business logic module acts as the central orchestrator for the entire system. It coordinates between different components like authentication, storage, and encryption services while maintaining the application's state. This module implements the primary business rules and ensures that all operations follow the security policies.

Key responsibilities:

- System initialization and configuration
- User session management
- Content upload/download workflow
- Access control enforcement
- Error handling and recovery
- System state management

```python
class DCMSystem:
    def __init__(self):
        self.db = SQLiteStorage()
        self.rbac = RBACManager()
        self.secure_enclave = SecureEnclaveService()
        self.current_user = None
        self._clear_session()

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

    def upload_artifact(self):
        """Handle artifact upload"""
        if not self.current_user:
            print("Please login first")
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
            # ... upload handling ...
        except Exception as e:
            print(f"Error uploading file: {e}")
````

### 3. Authentication System (`src/auth/rbac.py`)

The Role-Based Access Control (RBAC) system provides a sophisticated authentication and authorization framework. It implements secure password handling, role management, and permission verification. The system supports multiple user roles (Admin, Owner, Viewer) with different privilege levels and ensures secure access to protected resources.

Key features:

- Secure password hashing and verification
- Role-based permission management
- Account lockout protection
- Session token management
- Password policy enforcement
- Audit logging of authentication attempts

```python
class RBACManager:
    def __init__(self):
        self.db = SQLiteStorage()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user and return User object if successful"""
        user_data = self.db.get_user_by_username(username)
        if not user_data:
            return None

        if self.verify_password(password, user_data["password_hash"]):
            return User(
                id=user_data["id"],
                username=user_data["username"],
                password_hash=user_data["password_hash"],
                role=UserRole(user_data["role"]),
                created_at=user_data["created_at"]
            )
        return None
```

### 4. Encryption Module (`src/encryption/secure_storage.py`)

The encryption module handles all cryptographic operations in the system. It implements industry-standard encryption algorithms to protect content and manages key distribution. The module uses the Fernet symmetric encryption for file content and RSA asymmetric encryption for key exchange and digital signatures.

Key security features:

- Symmetric encryption for file content
- Asymmetric encryption for key exchange
- Secure key generation and storage
- Digital signatures for content verification
- Key rotation and management
- Secure deletion of sensitive data

```python
class SecureStorage:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_file(self, file_path: str) -> bytes:
        """Encrypt file content"""
        with open(file_path, 'rb') as file:
            file_data = file.read()
        return self.cipher_suite.encrypt(file_data)

    def decrypt_file(self, encrypted_data: bytes) -> bytes:
        """Decrypt file content"""
        return self.cipher_suite.decrypt(encrypted_data)
```

### 5. Storage Management (`src/storage/db_storage.py`)

The storage management module provides a secure and efficient way to store both encrypted content and metadata. It implements a SQLite database backend with proper security measures and transaction management. The module handles data persistence, retrieval, and maintains referential integrity while ensuring secure access to stored content.

Key capabilities:

- Secure file storage and retrieval
- Transactional database operations
- Metadata management
- Access control integration
- Backup and recovery features
- Storage optimization

```python
class SQLiteStorage:
    def __init__(self):
        self.db_path = "secure_dcm.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def create(self, data: dict) -> str:
        """Create a new record"""
        table = data.pop("table")
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"

        try:
            with self.conn:
                cursor = self.conn.execute(query, list(data.values()))
                return cursor.lastrowid
        except Exception as e:
            print(f"Database error: {e}")
            return None
```

### 6. Models (`src/models/`)

The models module defines the core data structures and business objects used throughout the application. It implements proper data validation, type checking, and ensures data integrity. The models serve as the foundation for the system's domain logic and provide a clear structure for managing different types of content and user roles.

Key models:

- User model with role-based permissions
- Content types for different media formats
- Artifact metadata management
- Access control policies
- Audit log structures

```python
class User:
    def __init__(self, id: str, username: str, password_hash: str,
                 role: UserRole, created_at: float,
                 artifacts: List[Dict] = None,
                 failed_login_attempts: int = 0,
                 last_login_attempt: float = 0):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.created_at = created_at
        self.artifacts = artifacts or []
        self.failed_login_attempts = failed_login_attempts
        self.last_login_attempt = last_login_attempt

class ContentType(Enum):
    LYRICS = "lyrics"
    SCORE = "score"
    AUDIO_MP3 = "audio/mp3"
    AUDIO_WAV = "audio/wav"
    VIDEO_MP4 = "video/mp4"
    VIDEO_AVI = "video/avi"
    DOCUMENT = "document"
```

### 7. Services (`src/services/`)

The services layer implements the core business logic for different features of the system. Each service is responsible for a specific domain of functionality and ensures proper coordination between different components. The services maintain separation of concerns and implement proper error handling and logging.

Key services:

- Artifact management service
- User management service
- Rights management service
- Audit service
- Encryption service
- Storage service

```python
class ArtifactService:
    def __init__(self):
        self.storage = SecureStorage()
        self.db = SQLiteStorage()

    def create_artifact(self, owner_id: str, name: str,
                       content_type: str, file_path: str) -> str:
        """Create a new artifact"""
        # Encrypt the file
        encrypted_content = self.storage.encrypt_file(file_path)

        # Store metadata in database
        artifact_data = {
            "table": "artifacts",
            "owner_id": owner_id,
            "name": name,
            "content_type": content_type,
            "created_at": time.time(),
            "encrypted_content": encrypted_content
        }

        return self.db.create(artifact_data)
```

## Configuration Files

### Requirements (`requirements.txt`)

The requirements file lists all Python dependencies needed to run the system. Each dependency is pinned to a specific version to ensure consistency across different environments and prevent compatibility issues.

```
click==8.1.3
cryptography==41.0.1
pytest==7.3.1
python-dotenv==1.0.0
bcrypt==4.0.1
sqlite3==3.35.0
```

### Pre-commit Configuration (`.pre-commit-config.yaml`)

The pre-commit configuration ensures code quality and consistency by running automated checks before each commit. It helps maintain code standards and prevents common issues from being committed to the repository.

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
```

### Flake8 Configuration (`.flake8`)

The Flake8 configuration defines Python code style rules and formatting standards. It ensures consistent code style across the project and helps maintain code readability.

```ini
[flake8]
max-line-length = 100
exclude = .git,__pycache__,.venv
per-file-ignores =
    __init__.py:F401
```

## Testing

### Test Directory (`tests/`)

The test suite provides comprehensive coverage of the system's functionality. It includes unit tests, integration tests, and security tests to ensure the system works as expected and maintains its security guarantees.

Key test categories:

- Unit tests for individual components
- Integration tests for component interaction
- Security tests for vulnerability checking
- Performance tests for system optimization
- Edge case handling tests

```python
def test_user_authentication():
    """Test user authentication process"""
    rbac = RBACManager()
    user = rbac.authenticate("testuser", "password123")
    assert user is not None
    assert user.username == "testuser"
    assert user.role == UserRole.VIEWER

def test_file_encryption():
    """Test file encryption and decryption"""
    storage = SecureStorage()
    test_data = b"Test content"
    encrypted = storage.encrypt_file(test_data)
    decrypted = storage.decrypt_file(encrypted)
    assert decrypted == test_data
```

## Security Features

The system implements multiple layers of security to protect content and ensure proper access control:

1. **Encryption Implementation**

- Symmetric encryption for efficient file handling
- Asymmetric encryption for secure key exchange
- Digital signatures for content authenticity
- Secure key management and rotation

```python
def encrypt_file(self, file_data: bytes) -> bytes:
    """Encrypt file content using Fernet symmetric encryption"""
    return self.cipher_suite.encrypt(file_data)

def generate_key_pair(self):
    """Generate asymmetric key pair for digital signatures"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key
```

2. **Access Control Implementation**

- Role-based access control
- Fine-grained permissions
- Resource-level access checks
- Audit logging of access attempts

```python
def check_permission(self, user: User, artifact_id: str) -> bool:
    """Check if user has permission to access artifact"""
    if user.role == UserRole.ADMIN:
        return True

    artifact = self.db.read(artifact_id, "artifacts")
    if not artifact:
        return False

    if user.role == UserRole.OWNER:
        return artifact["owner_id"] == user.id

    return artifact["is_public"]
```

## Getting Started

Detailed steps to set up and run the system in a development environment:

1. **Setup**

- Virtual environment creation
- Dependency installation
- Environment configuration

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

2. **Database Initialization**

- Schema creation
- Initial data setup
- Security configuration

```bash
python src/init_db.py
```

3. **Running the Application**

- Application startup
- Initial configuration
- User setup

```bash
python main.py
```

## Contributing

Guidelines for contributing to the project:

1. Fork the repository
2. Create a feature branch
3. Make your changes following the coding standards
4. Add tests for new functionality
5. Submit a pull request with a clear description

## License

[Insert License Information]
