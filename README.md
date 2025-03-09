# Secure Digital Copyright Management System

A secure CLI-based application for managing digital copyright artifacts with role-based access control, encryption, and support for various media file types.

## Features

- **Role-Based Access Control (RBAC)**

  - Admin: Full system access and user management
  - Owner: Manage owned artifacts
  - Viewer: Read-only access

- **Security Features**

  - AES-256 encryption for all stored files
  - Bcrypt password hashing with high work factor (12 rounds)
  - Secure password requirements enforcement:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character (!@#$%^&\*(),.?":{}|<>)
    - No common patterns (e.g., 12345, qwerty, password)
    - No repeated characters (3 or more of the same character)
    - No common words (e.g., admin, user, login, test)
  - File integrity verification with checksums
  - Rate limiting for login attempts (30-second delay between attempts)
  - Account lockout after multiple failed attempts
  - Comprehensive audit logging
  - Path traversal protection
  - Secure file size validation
  - Automatic session cleanup on program termination
  - Signal handling for graceful shutdown

- **User Management Features (Admin Only)**

  - List all users with detailed information:
    - Username and role
    - Account status (active/locked)
    - Failed login attempts count
    - Last password change timestamp
  - Reset user passwords with complexity validation
  - Lock/unlock user accounts (except admin accounts)
  - Delete users with automatic artifact cleanup
  - Create new users with role assignment

- **Media File Support**
  - Audio: MP3, WAV
  - Video: MP4, AVI
  - Documents: PDF, DOC, DOCX
  - Text: Lyrics, musical scores
  - File size limit: 100MB
  - Automatic content type detection
  - Media metadata preservation

## Installation

1. Clone the repository:

```bash
git clone [repository-url]
cd [repository-name]
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Initialize the database and set up secure passwords:

```bash
python src/init_db.py
```

During initialization, you'll be prompted to create secure passwords for the default users. Passwords must meet these requirements:

- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&\*(),.?":{}|<>)
- No common patterns or repeated characters

## Default Users

The system comes with three default user roles:

1. Admin User

   - Username: admin
   - Full system access
   - Create during initialization

2. Owner User

   - Username: owner
   - Can manage own artifacts
   - Create during initialization

3. Viewer User
   - Username: viewer
   - Read-only access
   - Create during initialization

## Usage

Run the application:

```bash
python main.py
```

### Main Menu

When you start the application, you'll see:

```
Digital Copyright Management System
==================================
1. Login
2. Exit
```

### User Menu

After logging in, you'll see options based on your role:

```
Welcome [username]!

Available Actions:
1. Create new user (Admin only)
2. Manage users (Admin only)
3. Upload artifact (Admin/Owner)
4. Download artifact (Admin/Owner)
5. Delete artifact (Admin/Owner)
6. List artifacts
7. Show my info
8. Logout
```

### User Management (Admin Only)

1. **List Users**

   ```
   User List:
   ==========
   Username: admin
   Role: admin
   Status: ACTIVE
   Failed login attempts: 0
   Last password change: 2024-03-14 15:30:00
   ```

2. **Reset User Password**

   - Enter username to reset
   - Provide new password meeting complexity requirements
   - Automatically unlocks account and resets failed attempts

3. **Lock/Unlock User**

   - Toggle account lock status
   - Cannot lock admin accounts
   - Automatically manages failed login attempts

4. **Delete User**
   - Remove user from system
   - Automatically deletes user's artifacts
   - Cannot delete admin accounts

### Artifact Management

1. **Upload Artifact**

   - Select from supported file types
   - Automatic ID generation
   - File size validation
   - Content type detection

2. **List Artifacts**
   Shows a formatted table with:

```
===============================================================
| ID                 | Name          | Type       | Size (bytes) |
===============================================================
| 123e4567-e89b-12d3| My Song       | audio/mp3  | 1048576     |
| 987fcdeb-51a2-3c4d| Lyrics Doc    | lyrics     | 2048        |
===============================================================
Total artifacts: 2
```

Admin users see additional owner information.

3. **Download Artifact**

   - Secure decryption
   - Integrity verification
   - Permission validation

4. **Delete Artifact**
   - Available to Admin and Owner roles
   - Permission checks
   - Secure cleanup

## Security Best Practices

1. Password Security:

   - Never share or store passwords in plain text
   - Use unique, strong passwords for each account
   - Change passwords regularly
   - Use password manager for secure storage

2. System Security:

   - Keep the system and dependencies updated
   - Monitor audit logs regularly
   - Backup database securely
   - Use secure communication channels

3. File Security:
   - Verify file integrity after transfers
   - Scan uploads for malware
   - Maintain secure backups
   - Follow least privilege principle

## Design Patterns Used

1. **Facade Pattern** (SecureEnclaveService)

   - Simplifies complex security and storage operations
   - Provides unified interface for all security operations

2. **Strategy Pattern** (Authorization)

   - Flexible permission checking implementation
   - Allows for different authorization strategies

3. **Command Pattern** (Upload/Download operations)

   - Encapsulates file operation requests
   - Provides uniform interface for different operations

4. **Template Method Pattern** (File operations)

   - Defines skeleton of operations
   - Allows for customization of specific steps

5. **Dependency Injection**
   - Loose coupling between components
   - Easier testing and maintenance

## Testing

Run the test suite with coverage reporting:

```bash
python -m tests.run_tests
```

This will:

- Run all unit tests
- Generate coverage reports
- Create detailed HTML coverage report

Run security checks:

```bash
bandit -r src/
```

Run type checking:

```bash
mypy src/
```

## File Type Support

The system supports various file types with appropriate handling:

1. **Audio Files**

   - MP3 (.mp3)
   - WAV (.wav)
   - Automatic metadata extraction
   - Content validation

2. **Video Files**

   - MP4 (.mp4)
   - AVI (.avi)
   - Size validation
   - Format verification

3. **Documents**

   - PDF (.pdf)
   - DOC (.doc)
   - DOCX (.docx)
   - Text validation

4. **Copyright Materials**
   - Lyrics (.txt)
   - Musical scores (.pdf)
   - Metadata preservation

## Error Handling

The system provides comprehensive error handling:

1. **Upload Errors**

   - File size validation
   - Format verification
   - Permission checks
   - Encryption failures

2. **Download Errors**

   - File integrity checks
   - Decryption verification
   - Permission validation

3. **User Errors**
   - Invalid credentials
   - Permission denied
   - Rate limiting
   - Account lockout

## Artifact IDs

- Automatically generated using UUID v4
- Guaranteed uniqueness across the system
- Used for all artifact operations (download, delete, etc.)
- Shown in the artifact listing table

## Contributing

Guidelines for contributing to the project:

1. Fork the repository
2. Create a feature branch
3. Make your changes following the coding standards
4. Add tests for new functionality
5. Submit a pull request with a clear description
