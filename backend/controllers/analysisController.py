"""
Analysis controller module for Malicious File Analyzer.
Handles request validation, service invocation, and standardized API response delivery.
"""

from typing import List, Dict, Any, Union
from fastapi import UploadFile, status
from fastapi.responses import JSONResponse

from backend.services.analysisService import analysis_service


def _format_success(message: str, data: Any, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    """Helper to return standardized API success response according to CONTRACT.md."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": True,
            "message": message,
            "data": data,
        },
    )


def _format_error(message: str, status_code: int = status.HTTP_400_BAD_REQUEST) -> JSONResponse:
    """Helper to return standardized API error response according to CONTRACT.md."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "message": message,
        },
    )


async def health_controller() -> JSONResponse:
    """Handle GET /api/health request."""
    return _format_success(
        message="Service is running and healthy",
        data={"status": "UP"},
    )


async def analyze_files_controller(files: List[UploadFile]) -> JSONResponse:
    """
    Handle POST /api/analyze request supporting single and multi-file uploads.

    :param files: List of UploadFile objects submitted from the frontend/client
    :return: JSONResponse with analyzed file data
    """
    if not files:
        return _format_error("No files provided for analysis", status_code=status.HTTP_400_BAD_REQUEST)

    results: List[Dict[str, Any]] = []

    try:
        for file in files:
            # Validate file existence
            if not file or not file.filename:
                continue

            # Read content bytes asynchronously
            file_bytes = await file.read()

            # Execute static analysis pipeline
            analysis_result = analysis_service.analyze_file(
                filename=file.filename,
                data=file_bytes,
            )
            results.append(analysis_result)

        if not results:
            return _format_error("Unable to analyze file: No valid file content received", status_code=status.HTTP_400_BAD_REQUEST)

        # Single file upload returns single object in data; multi returns array
        data_payload: Union[Dict[str, Any], List[Dict[str, Any]]] = (
            results[0] if len(results) == 1 else results
        )

        return _format_success(
            message="Analysis completed successfully",
            data=data_payload,
            status_code=status.HTTP_200_OK,
        )

    except Exception as exc:
        return _format_error(
            f"Unable to analyze file: {str(exc)}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


async def get_analysis_controller(analysis_id: str) -> JSONResponse:
    """
    Handle GET /api/analysis/:id request.

    :param analysis_id: Unique analysis ID
    :return: JSONResponse containing analysis result or not found error
    """
    if not analysis_id:
        return _format_error("Analysis ID is required", status_code=status.HTTP_400_BAD_REQUEST)

    result = analysis_service.get_analysis(analysis_id)
    if not result:
        return _format_error(
            f"Analysis with ID '{analysis_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return _format_success(
        message="Analysis retrieved successfully",
        data=result,
        status_code=status.HTTP_200_OK,
    )


async def get_all_analyses_controller() -> JSONResponse:
    """
    Handle GET /api/analyses request.

    :return: JSONResponse containing list of all completed analyses
    """
    results = analysis_service.get_all_analyses()
    return _format_success(
        message="Analyses retrieved successfully",
        data=results,
        status_code=status.HTTP_200_OK,
    )
