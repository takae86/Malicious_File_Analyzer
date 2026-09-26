"""
Report routes for Malicious File Analyzer.
Provides endpoints for retrieving detailed analysis reports.
"""

from fastapi import APIRouter, Path

from backend.controllers.reportController import get_report_controller

router = APIRouter(prefix="/api", tags=["Reports"])


@router.get("/analysis/{analysis_id}/report", summary="Get Detailed Report")
async def get_analysis_report(
    analysis_id: str = Path(..., description="Unique ID of the analysis for the report")
):
    """Retrieves a comprehensive structured report for an analyzed file."""
    return await get_report_controller(analysis_id=analysis_id)
