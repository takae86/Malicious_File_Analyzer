"""
Analysis routes for Malicious File Analyzer.
Provides endpoints for health check, file upload & analysis, and result retrieval.
"""

from typing import List
from fastapi import APIRouter, File, UploadFile, Path

from backend.controllers.analysisController import (
    health_controller,
    analyze_files_controller,
    get_analysis_controller,
    get_all_analyses_controller,
)

router = APIRouter(prefix="/api", tags=["Analysis"])


@router.get("/health", summary="Service Health Check")
async def health_check():
    """Health check endpoint to verify backend service status."""
    return await health_controller()


@router.post("/analyze", summary="Upload and Analyze File(s)")
async def analyze_file(
    files: List[UploadFile] = File(..., description="Single or multiple files to analyze")
):
    """
    Receives one or more uploaded files, executes static analysis pipeline,
    and returns threat metrics and risk assessments.
    """
    return await analyze_files_controller(files=files)


@router.get("/analysis/{analysis_id}", summary="Get Analysis by ID")
async def get_analysis(
    analysis_id: str = Path(..., description="Unique ID of the completed analysis")
):
    """Retrieves an existing analysis result by its unique analysis ID."""
    return await get_analysis_controller(analysis_id=analysis_id)


@router.get("/analyses", summary="List All Analyses")
async def get_all_analyses():
    """Retrieves all past file analysis records in the current session."""
    return await get_all_analyses_controller()
