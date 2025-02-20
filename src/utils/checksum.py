import hashlib
from typing import Union, BinaryIO

def generate_checksum(data: Union[bytes, str, BinaryIO]) -> str:
    """Generate SHA-256 checksum for the given data"""
    sha256 = hashlib.sha256()
    
    if isinstance(data, bytes):
        sha256.update(data)
    elif isinstance(data, str):
        sha256.update(data.encode())
    else:  # file-like object
        for chunk in iter(lambda: data.read(4096), b''):
            sha256.update(chunk)
            
    return sha256.hexdigest()

def verify_checksum(data: Union[bytes, str, BinaryIO], expected_checksum: str) -> bool:
    """Verify if data matches the expected checksum"""
    actual_checksum = generate_checksum(data)
    return actual_checksum == expected_checksum 