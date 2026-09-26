"""
Validation module for Malicious File Analyzer file-processing component.
Handles request validation, file validation, file-size limits, and filename sanitization.
"""

import os
import re

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB default limit


class ValidationError(Exception):
    """Base exception for file processing validation errors."""
    pass


class InvalidRequestError(ValidationError):
    """Raised when an incoming upload request is malformed or empty."""
    pass


class OversizedFileError(ValidationError):
    """Raised when a file exceeds the maximum allowed file size."""
    pass


class InvalidFilenameError(ValidationError):
    """Raised when a filename is invalid or unsafe."""
    pass


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal, null-byte injection, and safe disk storage.
    Treats input as untrusted.
    """
    if not filename or not isinstance(filename, str):
        raise InvalidFilenameError("Filename must be a non-empty string.")

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Extract basename to prevent directory traversal (/ and \)
    filename = os.path.basename(filename)
    filename = filename.split("\\")[-1]

    # Remove leading dots or slashes
    filename = filename.lstrip(".\\/")

    # Fallback/clean character stripping
    filename = re.sub(r'[^\w\.\-\_]', '_', filename)

    if not filename or filename.strip() == "":
        raise InvalidFilenameError("Sanitized filename resulted in an empty string.")

    return filename


def validate_file_size(file_size: int, max_size: int = DEFAULT_MAX_FILE_SIZE) -> bool:
    """
    Validate that the file size is positive and within max limits.
    """
    if file_size is None:
        raise ValidationError("File size must be provided.")

    if not isinstance(file_size, int) or file_size < 0:
        raise ValidationError("Invalid file size specified.")

    if file_size == 0:
        raise ValidationError("Uploaded file is empty (0 bytes).")

    if file_size > max_size:
        raise OversizedFileError(
            f"File size ({file_size} bytes) exceeds maximum allowed size ({max_size} bytes)."
        )

    return True


def validate_request(files) -> list:
    """
    Validate incoming upload request structure.
    `files` can be a single file object/dict or a list/tuple of file objects/dicts.
    Returns a normalized list of validated file items.
    """
    if files is None:
        raise InvalidRequestError("Upload request is missing file payload.")

    if isinstance(files, (list, tuple)):
        if len(files) == 0:
            raise InvalidRequestError("Upload request contains an empty file list.")
        file_list = list(files)
    else:
        file_list = [files]

    return file_list


def validate_file(file_item, max_size: int = DEFAULT_MAX_FILE_SIZE) -> dict:
    """
    Validate a single file item (supports dict, Werkzeug/FastAPI File objects, or custom file representations).
    Extracts filename, content/size, and returns a dictionary with validated attributes.
    """
    if file_item is None:
        raise InvalidRequestError("File payload is empty or invalid.")

    filename = None
    file_size = None
    stream_or_bytes = None

    # Handle standard Python dict representation
    if isinstance(file_item, dict):
        filename = file_item.get("filename") or file_item.get("fileName") or file_item.get("name")
        stream_or_bytes = file_item.get("content") or file_item.get("stream") or file_item.get("data")
        file_size = file_item.get("size") or file_item.get("fileSize")
        if file_size is None and isinstance(stream_or_bytes, (bytes, bytearray)):
            file_size = len(stream_or_bytes)

    # Handle Flask/Werkzeug FileStorage or FastAPI UploadFile objects
    elif hasattr(file_item, "filename"):
        filename = file_item.filename
        if hasattr(file_item, "content_length") and file_item.content_length:
            file_size = file_item.content_length
        elif hasattr(file_item, "size") and file_item.size:
            file_size = file_item.size
        
        # If content stream is available
        if hasattr(file_item, "stream"):
            stream_or_bytes = file_item.stream
        elif hasattr(file_item, "file"):
            stream_or_bytes = file_item.file
        elif hasattr(file_item, "read"):
            stream_or_bytes = file_item

    # Handle raw bytes or file-like object directly
    elif isinstance(file_item, (bytes, bytearray)):
        filename = "unnamed_file.bin"
        stream_or_bytes = file_item
        file_size = len(file_item)

    if not filename:
        raise InvalidFilenameError("File payload missing filename.")

    sanitized_name = sanitize_filename(filename)

    # If stream_or_bytes is bytes, calculate length if not set
    if file_size is None and isinstance(stream_or_bytes, (bytes, bytearray)):
        file_size = len(stream_or_bytes)
    
    # If stream has seek/tell capabilities to measure size
    if file_size is None and hasattr(stream_or_bytes, "seek") and hasattr(stream_or_bytes, "tell"):
        curr_pos = stream_or_bytes.tell()
        stream_or_bytes.seek(0, os.SEEK_END)
        file_size = stream_or_bytes.tell()
        stream_or_bytes.seek(curr_pos, os.SEEK_SET)

    if file_size is None:
        raise ValidationError(f"Could not determine file size for '{sanitized_name}'.")

    validate_file_size(file_size, max_size=max_size)

    return {
        "fileName": sanitized_name,
        "originalName": filename,
        "fileSize": file_size,
        "content": stream_or_bytes,
    }
