"""
Integration and Unit tests for API endpoints and controllers (Role 4).
Validates routes, status codes, and standardized response schemas according to CONTRACT.md.
"""

import unittest
import asyncio
import io
from fastapi import FastAPI, UploadFile
from starlette.datastructures import Headers

from backend.routes.analysisRoutes import router as analysis_router
from backend.routes.reportRoutes import router as report_router
from backend.services.analysisService import analysis_service
from backend.controllers.analysisController import (
    health_controller,
    analyze_files_controller,
    get_analysis_controller,
    get_all_analyses_controller,
)
from backend.controllers.reportController import get_report_controller


class TestApiEndpoints(unittest.TestCase):
    """Test suite for backend API routes and controllers."""

    def setUp(self):
        self.app = FastAPI(title="Malicious File Analyzer Test API")
        self.app.include_router(analysis_router)
        self.app.include_router(report_router)

    def _run_async(self, coro):
        """Helper to run asynchronous controller functions synchronously in tests."""
        return asyncio.run(coro)

    def _create_mock_upload_file(self, filename: str, content: bytes) -> UploadFile:
        """Create a mock FastAPI UploadFile instance for testing."""
        file_obj = io.BytesIO(content)
        headers = Headers({"content-type": "application/octet-stream"})
        return UploadFile(file=file_obj, filename=filename, headers=headers)

    def test_health_endpoint(self):
        """Test GET /api/health returns success and healthy status."""
        response = self._run_async(health_controller())
        self.assertEqual(response.status_code, 200)

        import json
        body = json.loads(response.body.decode("utf-8"))
        self.assertTrue(body.get("success"))
        self.assertIn("data", body)
        self.assertEqual(body["data"].get("status"), "UP")

    def test_single_file_analyze(self):
        """Test POST /api/analyze with a single valid sample file."""
        sample_content = b"MZ\x90\x00\x03\x00\x00\x00This is a test executable binary string content"
        upload_file = self._create_mock_upload_file("sample.exe", sample_content)

        response = self._run_async(analyze_files_controller([upload_file]))
        self.assertEqual(response.status_code, 200)

        import json
        body = json.loads(response.body.decode("utf-8"))
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("message"), "Analysis completed successfully")
        
        data = body.get("data", {})
        # Verify required contract keys in analysis result
        required_keys = [
            "fileName", "fileSize", "fileType", "signature",
            "md5", "sha256", "entropy", "strings", "pe", "indicators", "risk"
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Missing required contract key: {key}")

        self.assertEqual(data["fileName"], "sample.exe")
        self.assertIn(data["risk"], {"LOW", "MEDIUM", "HIGH"})

    def test_multi_file_analyze(self):
        """Test POST /api/analyze with multiple uploaded files simultaneously."""
        file1 = self._create_mock_upload_file("doc.pdf", b"%PDF-1.4 sample pdf stream")
        file2 = self._create_mock_upload_file("archive.zip", b"PK\x03\x04 dummy zip payload")

        response = self._run_async(analyze_files_controller([file1, file2]))
        self.assertEqual(response.status_code, 200)

        import json
        body = json.loads(response.body.decode("utf-8"))
        self.assertTrue(body.get("success"))
        self.assertIsInstance(body.get("data"), list)
        self.assertEqual(len(body["data"]), 2)

    def test_empty_upload_error(self):
        """Test POST /api/analyze with empty file list returns structured error."""
        response = self._run_async(analyze_files_controller([]))
        self.assertEqual(response.status_code, 400)

        import json
        body = json.loads(response.body.decode("utf-8"))
        self.assertFalse(body.get("success"))
        self.assertIn("message", body)

    def test_get_analysis_by_id(self):
        """Test GET /api/analysis/{id} returns existing analysis data."""
        # First analyze a file to populate store
        sample = self._create_mock_upload_file("test_get.exe", b"MZ\x00\x00 test binary")
        post_resp = self._run_async(analyze_files_controller([sample]))
        import json
        post_body = json.loads(post_resp.body.decode("utf-8"))
        analysis_id = post_body["data"]["analysisId"]

        # Retrieve by ID
        get_resp = self._run_async(get_analysis_controller(analysis_id))
        self.assertEqual(get_resp.status_code, 200)

        get_body = json.loads(get_resp.body.decode("utf-8"))
        self.assertTrue(get_body.get("success"))
        self.assertEqual(get_body["data"]["analysisId"], analysis_id)

    def test_get_invalid_analysis_id(self):
        """Test GET /api/analysis/{id} with non-existent ID returns 404 error format."""
        response = self._run_async(get_analysis_controller("NON_EXISTENT_ID_9999"))
        self.assertEqual(response.status_code, 404)

        import json
        body = json.loads(response.body.decode("utf-8"))
        self.assertFalse(body.get("success"))
        self.assertIn("message", body)

    def test_get_all_analyses(self):
        """Test GET /api/analyses returns list of all performed analyses."""
        response = self._run_async(get_all_analyses_controller())
        self.assertEqual(response.status_code, 200)

        import json
        body = json.loads(response.body.decode("utf-8"))
        self.assertTrue(body.get("success"))
        self.assertIsInstance(body.get("data"), list)

    def test_get_report(self):
        """Test GET /api/analysis/{id}/report returns structured detailed report."""
        sample = self._create_mock_upload_file("report_test.pdf", b"%PDF-1.4 report payload")
        post_resp = self._run_async(analyze_files_controller([sample]))
        import json
        post_body = json.loads(post_resp.body.decode("utf-8"))
        analysis_id = post_body["data"]["analysisId"]

        # Fetch report
        report_resp = self._run_async(get_report_controller(analysis_id))
        self.assertEqual(report_resp.status_code, 200)

        report_body = json.loads(report_resp.body.decode("utf-8"))
        self.assertTrue(report_body.get("success"))
        report_data = report_body.get("data", {})
        self.assertIn("reportId", report_data)
        self.assertIn("target", report_data)
        self.assertIn("securitySummary", report_data)
        self.assertIn("technicalDetails", report_data)


if __name__ == "__main__":
    unittest.main()
