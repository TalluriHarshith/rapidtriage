"""
RapidTriage Forensic Hasher
SHA-256 calculation and verification for endpoint evidence integrity.
"""

import hashlib
from pathlib import Path
from typing import Union

def compute_sha256(data: Union[bytes, str]) -> str:
    """Computes SHA-256 hash of bytes or string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def compute_file_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Computes SHA-256 hash of a file on disk reading in chunks."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")
    
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def verify_hash(actual_hash: str, expected_hash: str) -> bool:
    """Case-insensitive comparison of SHA-256 hashes."""
    return actual_hash.strip().lower() == expected_hash.strip().lower()
