"""
Malicious File Analyzer - Application Server Entry Point
Runs the FastAPI backend on port 5000 according to CONTRACT.md Section 8.
"""
import os
import sys

# Ensure repository root is on sys.path so 'backend' package resolves cleanly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routes.analysisRoutes import router as analysis_router
from backend.routes.reportRoutes import router as report_router

app = FastAPI(
    title="Malicious File Analyzer API",
    description="Web-based static file analysis and heuristic triage platform",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes (analysisRoutes already has prefix="/api", reportRoutes has prefix="/api")
app.include_router(analysis_router)
app.include_router(report_router)


if __name__ == "__main__":
    import uvicorn
    print("Starting Malicious File Analyzer backend on http://localhost:5000 ...")
    uvicorn.run("backend.app:app", host="0.0.0.0", port=5000, reload=True)
