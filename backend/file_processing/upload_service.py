"""
Upload service module for Malicious File Analyzer file-processing component.
Orchestrates the full flow:
Receive File -> Validate Request -> Validate File -> Generate Analysis ID -> Create Working Location -> Store/Prepare File -> Pass to Analysis Pipeline.
"""

from typing import Callable, List, Optional, Union, Dict, Any
from backend.file_processing.validation import (
    validate_request,
    validate_file,
    ValidationError,
    InvalidRequestError,
)
from backend.file_processing.file_manager import (
    FileManager,
    generate_analysis_id,
)


class UploadService:
    """
    High-level service coordinating file uploads, validation, storage, and pipeline dispatch.
    """

    def __init__(self, file_manager: Optional[FileManager] = None, max_file_size: Optional[int] = None):
        self.file_manager = file_manager or FileManager()
        self.max_file_size = max_file_size

    def process_file(
        self,
        file_input: Any,
        pipeline_callback: Optional[Callable[[str, str], Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process a single file upload through the standard flow:
        Receive File -> Validate Request -> Validate File -> Generate Analysis ID
        -> Create Working Location -> Store/Prepare File -> Pass to Analysis Pipeline.

        Returns a dictionary conforming to CONTRACT.md specifications:
        {
            "analysisId": "A...",
            "fileName": "...",
            "fileSize": ...,
            "status": "QUEUED" | "PROCESSING" | "COMPLETED" | "FAILED",
            "filePath": "..."
        }
        """
        # Step 1 & 2: Validate Request & File
        validated_data = validate_file(file_input, max_size=self.max_file_size) if self.max_file_size else validate_file(file_input)

        # Step 3: Generate Analysis ID
        analysis_id = generate_analysis_id()

        # Step 4: Create Working Location & Step 5: Store/Prepare File
        filename = validated_data["fileName"]
        content = validated_data["content"]

        stored_file_path = self.file_manager.save_file(
            content=content,
            analysis_id=analysis_id,
            filename=filename,
        )

        response_payload = {
            "analysisId": analysis_id,
            "fileName": filename,
            "fileSize": validated_data["fileSize"],
            "filePath": stored_file_path,
            "status": "QUEUED",
        }

        # Step 6: Pass File to Analysis Pipeline (if pipeline callback is provided)
        if pipeline_callback and callable(pipeline_callback):
            try:
                pipeline_callback(stored_file_path, analysis_id)
                response_payload["status"] = "QUEUED"
            except Exception as pipeline_err:
                response_payload["status"] = "FAILED"
                response_payload["error"] = str(pipeline_err)

        return response_payload

    def process_multiple_files(
        self,
        files_input: Any,
        pipeline_callback: Optional[Callable[[str, str], Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Process multiple file uploads in batch.
        """
        file_list = validate_request(files_input)
        results = []

        for item in file_list:
            res = self.process_file(item, pipeline_callback=pipeline_callback)
            results.append(res)

        return results

    def cleanup_analysis(self, analysis_id: str) -> bool:
        """
        Cleanup temporary working directory for an analysis ID.
        """
        return self.file_manager.cleanup(analysis_id)
