"""
Malicious File Analyzer - File Signature Detection Module
Owner: Member 1 (Team Lead)

Inspects magic bytes/headers to detect the actual file format and detects
dangerous file extension mismatches (e.g., PE executable masquerading as a PDF).
"""

import os
from typing import Dict, Optional, Union, Tuple

SIGNATURE_DATABASE = [
    {
        "type": "Windows PE Executable",
        "sig": "MZ",
        "magic": b"MZ",
        "offset": 0,
        "valid_extensions": [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"]
    },
    {
        "type": "PDF Document",
        "sig": "%PDF",
        "magic": b"%PDF",
        "offset": 0,
        "valid_extensions": [".pdf"]
    },
    {
        "type": "ZIP Archive",
        "sig": "PK..",
        "magic": b"PK\x03\x04",
        "offset": 0,
        "valid_extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]
    },
    {
        "type": "ELF Executable (Linux)",
        "sig": "ELF",
        "magic": b"\x7fELF",
        "offset": 0,
        "valid_extensions": [".elf", ".bin", ""]
    },
    {
        "type": "PNG Image",
        "sig": "PNG",
        "magic": b"\x89PNG\r\n\x1a\n",
        "offset": 0,
        "valid_extensions": [".png"]
    },
    {
        "type": "JPEG Image",
        "sig": "JFIF/JPEG",
        "magic": b"\xff\xd8\xff",
        "offset": 0,
        "valid_extensions": [".jpg", ".jpeg"]
    },
    {
        "type": "GIF Image",
        "sig": "GIF89a",
        "magic": b"GIF89a",
        "offset": 0,
        "valid_extensions": [".gif"]
    },
    {
        "type": "GIF Image",
        "sig": "GIF87a",
        "magic": b"GIF87a",
        "offset": 0,
        "valid_extensions": [".gif"]
    },
    {
        "type": "7-Zip Archive",
        "sig": "7z",
        "magic": b"7z\xbc\xaf\x27\x1c",
        "offset": 0,
        "valid_extensions": [".7z"]
    },
    {
        "type": "RAR Archive",
        "sig": "Rar!",
        "magic": b"Rar!\x1a\x07",
        "offset": 0,
        "valid_extensions": [".rar"]
    },
]


def detect_signature(
    file_input: Union[str, bytes],
    original_filename: str = ""
) -> Dict[str, Optional[Union[str, bool]]]:
    """
    Detects file format by magic bytes and checks for extension mismatch.

    :param file_input: File path (str) or raw bytes (bytes).
    :param original_filename: Original filename if available (used for mismatch detection).
    :return: Dictionary containing 'signature', 'detectedType', 'isMismatch', 'warning'.
    """
    if isinstance(file_input, bytes):
        header = file_input[:64]
    elif isinstance(file_input, str):
        if not os.path.exists(file_input):
            raise FileNotFoundError(f"File not found: {file_input}")
        with open(file_input, "rb") as f:
            header = f.read(64)
    else:
        raise TypeError("file_input must be a file path (str) or bytes")

    detected_type = "Unknown / Binary"
    signature_str = "UNKNOWN"
    valid_extensions = []

    for entry in SIGNATURE_DATABASE:
        magic = entry["magic"]
        offset = entry.get("offset", 0)
        if len(header) >= offset + len(magic) and header[offset:offset + len(magic)] == magic:
            detected_type = entry["type"]
            signature_str = entry["sig"]
            valid_extensions = entry["valid_extensions"]
            break

    # If unknown binary, check if it's plain text
    if detected_type == "Unknown / Binary" and len(header) > 0:
        try:
            header.decode("utf-8")
            detected_type = "Plain Text / Script"
            signature_str = "TEXT"
            valid_extensions = [".txt", ".sh", ".py", ".bat", ".ps1", ".json", ".xml", ".csv", ".log", ".md"]
        except UnicodeDecodeError:
            pass

    # Check for extension mismatch
    is_mismatch = False
    warning = None

    if original_filename:
        _, ext = os.path.splitext(original_filename.lower())
        if valid_extensions and ext:
            if ext not in valid_extensions:
                is_mismatch = True
                warning = f"File extension '{ext}' does not match detected type '{detected_type}'"

    return {
        "signature": signature_str,
        "detectedType": detected_type,
        "fileType": detected_type,
        "isMismatch": is_mismatch,
        "warning": warning
    }
