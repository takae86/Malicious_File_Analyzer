"""
Malicious File Analyzer - File Metadata Module
Owner: Member 1 (Team Lead)

Collects filesystem metadata for analyzed files, including size, timestamps,
and original filename details.
"""

import os
import time
from typing import Dict, Any


def get_file_metadata(file_path: str, original_filename: str = "") -> Dict[str, Any]:
    """
    Extracts filesystem metadata for an uploaded file.

    :param file_path: Path to the file on disk.
    :param original_filename: User-provided original filename.
    :return: Dictionary containing file size, name, extension, and timestamps.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    stats = os.stat(file_path)
    display_name = original_filename if original_filename else os.path.basename(file_path)
    _, extension = os.path.splitext(display_name)

    return {
        "fileName": display_name,
        "fileSize": stats.st_size,
        "fileExtension": extension.lower(),
        "createdTime": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_ctime)),
        "modifiedTime": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stats.st_mtime))
    }
