````markdown:README.md
# Secure Digital Copyright Management CLI

A secure command-line interface (CLI) application for managing copyrighted digital content (lyrics, scores, audio files) with encryption, access control, and comprehensive audit logging.

## Features

- 🔐 Secure storage of digital artifacts (lyrics, scores, audio files)
- 🔒 AES-256 encryption for all stored content
- 👥 Role-based access control (Admin, Owner, Viewer)
- ✅ File integrity verification via checksums
- 📝 Comprehensive audit logging
- 🔑 JWT-based authentication

## Project Structure
```bash
secure-dcm/
├── src/
│   ├── __init__.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_handler.py    # JWT authentication
│   │   └── rbac.py          # Role-based access control
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── storage_interface.py
│   │   ├── file_storage.py   # File system storage
│   │   └── db_storage.py     # SQLite storage
│   ├── encryption/
│   │   ├── __init__.py
│   │   ├── encryption_strategy.py
│   │   └── aes_handler.py    # AES-256 encryption
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py          # User model
│   │   └── artifact.py      # Artifact model
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logging.py       # Audit logging
│   │   └── checksum.py      # File integrity
│   └── cli.py               # CLI interface
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_storage.py
│   └── test_encryption.py
├── requirements.txt         # Dependencies
├── README.md
└── main.py                 # Entry point
````

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Git (for cloning the repository)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd secure-dcm
```

2. Create and activate a virtual environment:

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

Linux/Mac:

```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Initial Setup

The system will automatically create these directories on first run:

- `secure_storage/` - For encrypted files
- `audit.log` - For system logs
- `secure_dcm.db` - SQLite database

## Usage

### Basic Commands

1. **Start by logging in**:

```bash
python main.py login
# Use credentials:
# Username: admin
# Password: admin
```

2. **Upload a file**:

```bash
python main.py upload path/to/file.txt --name "My File" --type lyrics
```

Supported types: `lyrics`, `score`, `audio`

3. **Download a file**:

```bash
python main.py download <artifact_id> output_file.txt
```

4. **List all artifacts**:

```bash
python main.py list
```

### Command Details

#### Upload Command

```bash
python main.py upload [OPTIONS] FILE
Options:
  --name TEXT          Name of the artifact (required)
  --type [lyrics|score|audio]  Type of content (required)
```

Example:

```bash
python main.py upload lyrics.txt --name "Song Lyrics" --type lyrics
```

#### Download Command

```bash
python main.py download ARTIFACT_ID OUTPUT_PATH
```

Example:

```bash
python main.py download abc123xyz downloaded_lyrics.txt
```

## Access Control

The system implements three user roles:

1. **Admin**

   - Full access to all operations
   - Can create, read, update, and delete any artifact

2. **Owner**

   - Can manage their own artifacts
   - Can read, update, and delete owned artifacts
   - Cannot access others' artifacts

3. **Viewer**
   - Read-only access
   - Can list and download artifacts
   - Cannot modify any content

## Security Features

### Encryption

- AES-256 encryption for all stored content
- Secure key management
- Encrypted file storage

### Authentication

- JWT-based token authentication
- Secure password handling
- Session management

### File Integrity

- SHA-256 checksum verification
- Automatic validation on file operations
- Tamper detection

## Logging

The system maintains comprehensive audit logs in `audit.log`:

- Authentication attempts
- File operations
- Access control violations
- System errors

View logs:

```bash
# Last 10 entries
tail -n 10 audit.log

# Real-time monitoring
tail -f audit.log
```

## Troubleshooting

### Common Issues

1. **Import Errors**

   ```bash
   # Windows (PowerShell)
   $env:PYTHONPATH = "path\to\secure-dcm"

   # Linux/Mac
   export PYTHONPATH=/path/to/secure-dcm
   ```

2. **Permission Denied**

   - Verify login status
   - Check file permissions
   - Ensure database is writable

3. **Storage Issues**
   - Verify `secure_storage/` exists
   - Check disk space
   - Confirm write permissions

### Error Messages

1. "Please login first"

   - Run `python main.py login`
   - Use admin credentials

2. "Failed to create artifact"

   - Verify file exists
   - Check file permissions
   - Ensure sufficient storage

3. "Permission denied"
   - Verify user role
   - Check artifact ownership
   - Confirm required permissions

## Development

### Running Tests

```bash
# All tests
python -m unittest discover tests

# Specific test
python -m unittest tests.test_auth
```

### Security Testing

```bash
pip install bandit
bandit -r src/
```

## Maintenance

### Regular Tasks

1. Monitor `audit.log`
2. Backup `secure_storage/`
3. Check database integrity
4. Update dependencies

### Database Maintenance

```bash
# Backup
sqlite3 secure_dcm.db ".backup 'backup.db'"

# Check integrity
sqlite3 secure_dcm.db "PRAGMA integrity_check;"
```

## License

Copyright (c) 2024. All rights reserved.

## Support

For support:

1. Check troubleshooting section
2. Review error logs
3. Create an issue in the repository
