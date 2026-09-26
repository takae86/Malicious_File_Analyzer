"""
Routes package for Malicious File Analyzer.
Exports analysis and report routers for the FastAPI application.
"""

from .analysisRoutes import router as analysis_router
from .reportRoutes import router as report_router

__all__ = [
    "analysis_router",
    "report_router",
]
