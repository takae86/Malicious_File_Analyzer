"""
File manager module for Malicious File Analyzer file-processing component.
Handles unique analysis ID generation, temporary working location creation, safe storage, and directory cleanup.
"""

import os
import shutil
import tempfile
import uuid
from typing import Optional, List


def generate_analysis_id() -> str:
    """
    Generate a unique analysis ID string.
    Follows CONTRACT.md format (e.g., A10234 or A-UUID format).
    """
    short_uuid = uuid.uuid4().hex[:8].upper()
    return f"A{short_uuid}"


class FileManager:
    """
    Manages working directories and temporary file storage for file analysis.
    """

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_dir = os.path.abspath(base_dir)
        else:
            self.base_dir = os.path.join(tempfile.gettempdir(), "malicious_file_analyzer")
        os.makedirs(self.base_dir, exist_ok=True)

    def create_working_location(self, analysis_id: str) -> str:
        """
        Create a dedicated working directory for a given analysis ID.
        """
        if not analysis_id or not isinstance(analysis_id, str):
            raise ValueError("Invalid analysis_id specified.")

        location = os.path.join(self.base_dir, analysis_id)
        os.makedirs(location, exist_ok=True)
        return location

    def save_file(self, content, analysis_id: str, filename: str) -> str:
        """
        Save file content (bytes, bytearray, stream, or file-like object) securely
        in the working location for the specified analysis ID.
        Never sets executable permissions.
        """
        working_dir = self.create_working_location(analysis_id)
        target_path = os.path.abspath(os.path.join(working_dir, filename))

        # Ensure target_path resides inside working_dir (prevent directory traversal)
        if not target_path.startswith(working_dir):
            raise PermissionError("Access denied: File path outside working directory.")

        if isinstance(content, (bytes, bytearray)):
            with open(target_path, "wb") as f:
                f.write(content)
        elif hasattr(content, "read"):
            with open(target_path, "wb") as f:
                if hasattr(content, "seek"):
                    try:
                        content.seek(0)
                    except (AttributeError, OSError):
                        pass
                shutil.copyfileobj(content, f)
        else:
            raise ValueError("Unsupported content type for file saving.")

        # Strip executable permissions on POSIX operating systems if applicable
        try:
            os.chmod(target_path, 0o600)
        except Exception:
            pass

        return target_path

    def get_working_dir(self, analysis_id: str) -> str:
        """
        Get absolute path of the working directory for an analysis ID.
        """
        return os.path.join(self.base_dir, analysis_id)

    def get_file_path(self, analysis_id: str, filename: str) -> Optional[str]:
        """
        Get absolute path to stored file if it exists.
        """
        path = os.path.join(self.base_dir, analysis_id, filename)
        if os.path.exists(path):
            return os.path.abspath(path)
        return None

    def list_files(self, analysis_id: str) -> List[str]:
        """
        List all file names stored under the given analysis ID.
        """
        working_dir = self.get_working_dir(analysis_id)
        if not os.path.exists(working_dir):
            return []
        return os.listdir(working_dir)

    def cleanup(self, analysis_id: Optional[str] = None) -> bool:
        """
        Remove temporary directory for a specific analysis ID, or clean all if None.
        """
        try:
            if analysis_id:
                working_dir = self.get_working_dir(analysis_id)
                if os.path.exists(working_dir):
                    shutil.rmtree(working_dir, ignore_errors=True)
            else:
                if os.path.exists(self.base_dir):
                    shutil.rmtree(self.base_dir, ignore_errors=True)
                    os.makedirs(self.base_dir, exist_ok=True)
            return True
        except Exception:
            return False
