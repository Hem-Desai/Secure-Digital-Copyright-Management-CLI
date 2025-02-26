# Secure Digital Copyright Management System

A secure CLI-based application for managing digital copyright artifacts with role-based access control and encryption.

## Features

- **Role-Based Access Control (RBAC)**

  - Admin: Full system access
  - Owner: Manage owned artifacts
  - Viewer: Read-only access

- **Security Features**

  - AES-256 encryption for all stored files
  - Bcrypt password hashing
  - File integrity verification
  - Rate limiting for login attempts
  - Account lockout protection
  - Comprehensive audit logging
  - Path traversal protection

- **File Management**
  - Upload artifacts (MP3s, lyrics, scores, etc.)
  - Download with decryption
  - Update existing artifacts
  - Delete with secure cleanup
  - List available artifacts

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

## Usage

1. Start the application:

```bash
python -m src.cli
```

2. Available commands:

- Login:

```bash
python -m src.cli login
```

- Create new user (admin only):

```bash
python -m src.cli create-user USERNAME ROLE
# ROLE can be: admin, owner, or viewer
```

- Upload artifact:

```bash
python -m src.cli upload FILE --name NAME --type TYPE
# TYPE can be: lyrics, score, audio, video
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

## Design Patterns Used

1. **Facade Pattern** (SecureEnclaveService)

   - Simplifies complex security and storage operations

2. **Strategy Pattern** (Authorization)

   - Flexible permission checking implementation

3. **Command Pattern** (Upload/Download operations)

   - Encapsulates request processing

4. **Template Method Pattern** (File operations)

   - Defines skeleton of operations

5. **Dependency Injection**
   - Loose coupling between components

## Testing

Run the test suite:

```bash
pytest tests/
```

Run security checks:

```bash
bandit -r src/
```

Run type checking:

```bash
mypy src/
```

## License

[Your License]
