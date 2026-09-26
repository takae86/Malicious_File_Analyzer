"""
Report controller module for Malicious File Analyzer.
Handles report retrieval and formatting responses for analyzed files.
"""

from fastapi import status
from fastapi.responses import JSONResponse

from backend.services.analysisService import analysis_service


def _format_success(message: str, data: dict, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    """Helper to return standardized API success response according to CONTRACT.md."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": True,
            "message": message,
            "data": data,
        },
    )


def _format_error(message: str, status_code: int = status.HTTP_404_NOT_FOUND) -> JSONResponse:
    """Helper to return standardized API error response according to CONTRACT.md."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "message": message,
        },
    )


async def get_report_controller(analysis_id: str) -> JSONResponse:
    """
    Handle GET /api/analysis/:id/report request.

    :param analysis_id: Unique analysis ID
    :return: JSONResponse containing detailed report or not found error
    """
    if not analysis_id:
        return _format_error("Analysis ID is required", status_code=status.HTTP_400_BAD_REQUEST)

    report = analysis_service.generate_report(analysis_id)
    if not report:
        return _format_error(
            f"Unable to generate report: Analysis '{analysis_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return _format_success(
        message="Report generated successfully",
        data=report,
        status_code=status.HTTP_200_OK,
    )
