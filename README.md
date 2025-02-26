# Secure Digital Copyright Management System

A secure CLI-based application for managing digital copyright artifacts with role-based access control, encryption, and support for various media file types.

## Features

- **Role-Based Access Control (RBAC)**

  - Admin: Full system access
  - Owner: Manage owned artifacts
  - Viewer: Read-only access

- **Security Features**

  - AES-256 encryption for all stored files
  - Bcrypt password hashing
  - File integrity verification with checksums
  - Rate limiting for login attempts
  - Account lockout protection
  - Comprehensive audit logging
  - Path traversal protection
  - Secure file size validation

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

4. Initialize the database with default users:

```bash
python -m src.init_db
```

## Usage

1. Start by logging in:

```bash
python -m src.cli login USERNAME
```

2. Available commands:

- Create new user (admin only):

```bash
python -m src.cli create-user USERNAME ROLE
# ROLE can be: admin, owner, or viewer
```

- Upload media file:

```bash
python -m src.cli upload FILE --name NAME --type TYPE
# Examples:
python -m src.cli upload song.mp3 --name "My Song" --type audio/mp3
python -m src.cli upload video.mp4 --name "Music Video" --type video/mp4
python -m src.cli upload lyrics.txt --name "Song Lyrics" --type lyrics
```

- Download artifact:

```bash
python -m src.cli download ARTIFACT_ID OUTPUT_PATH
```

- List artifacts:

```bash
python -m src.cli list
```

- Show current user info:

```bash
python -m src.cli whoami
```

- Logout:

```bash
python -m src.cli logout
```

## Security Best Practices

1. Use strong passwords following the complexity requirements:

   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number
   - At least one special character

2. Regular password changes are recommended

3. Keep your encryption keys secure

4. Monitor audit logs for suspicious activity

5. Ensure proper file permissions on the host system

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

## License

[Your License]
