"""
Malicious File Analyzer - Hashing Module
Owner: Member 1 (Team Lead)

Calculates MD5 and SHA-256 cryptographic hashes for uploaded files.
Streams files in chunks to handle arbitrary file sizes efficiently.
"""

import hashlib
from typing import Dict, Union
import os


def compute_hashes(file_input: Union[str, bytes]) -> Dict[str, str]:
    """
    Computes MD5 and SHA-256 cryptographic fingerprints.
    
    :param file_input: File path (str) or raw bytes (bytes).
    :return: Dictionary containing 'md5' and 'sha256' hex strings.
    """
    md5_hasher = hashlib.md5()
    sha256_hasher = hashlib.sha256()

    if isinstance(file_input, bytes):
        md5_hasher.update(file_input)
        sha256_hasher.update(file_input)
    elif isinstance(file_input, str):
        if not os.path.exists(file_input):
            raise FileNotFoundError(f"File not found: {file_input}")
        
        with open(file_input, "rb") as f:
            while chunk := f.read(65536):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
    else:
        raise TypeError("file_input must be a file path (str) or bytes")

    return {
        "md5": md5_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest()
    }
