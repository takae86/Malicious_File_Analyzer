"""
Unit tests for the File Processing module.
Covers CONTRACT.md testing requirements for file processing:
- Valid file
- Missing file
- Oversized file
- Multiple files
- Invalid upload request
- Temporary-file cleanup
"""

import os
import unittest
from backend.file_processing.validation import (
    sanitize_filename,
    validate_file_size,
    validate_request,
    validate_file,
    ValidationError,
    InvalidRequestError,
    OversizedFileError,
    InvalidFilenameError,
)
from backend.file_processing.file_manager import (
    FileManager,
    generate_analysis_id,
)
from backend.file_processing.upload_service import (
    UploadService,
)


class TestFileProcessing(unittest.TestCase):

    def setUp(self):
        self.file_manager = FileManager()
        self.upload_service = UploadService(file_manager=self.file_manager, max_file_size=1024 * 1024)

    def tearDown(self):
        self.file_manager.cleanup()

    def test_analysis_id_generation(self):
        id1 = generate_analysis_id()
        id2 = generate_analysis_id()
        self.assertTrue(id1.startswith("A"))
        self.assertTrue(id2.startswith("A"))
        self.assertNotEqual(id1, id2)

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("sample.exe"), "sample.exe")
        # Path traversal attack vectors
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe")
        # Null bytes and unsafe chars
        self.assertEqual(sanitize_filename("test\x00file.txt"), "testfile.txt")
        self.assertEqual(sanitize_filename("file<script>.dll"), "file_script_.dll")

    def test_valid_file_upload(self):
        payload = {
            "filename": "sample.exe",
            "content": b"MZHeaderDummyDataForTest",
        }
        res = self.upload_service.process_file(payload)
        self.assertIn("analysisId", res)
        self.assertEqual(res["fileName"], "sample.exe")
        self.assertEqual(res["fileSize"], len(payload["content"]))
        self.assertEqual(res["status"], "QUEUED")
        self.assertTrue(os.path.exists(res["filePath"]))

    def test_missing_file_or_invalid_request(self):
        with self.assertRaises(InvalidRequestError):
            validate_request(None)

        with self.assertRaises(InvalidRequestError):
            validate_request([])

        with self.assertRaises(InvalidRequestError):
            self.upload_service.process_file(None)

    def test_oversized_file(self):
        huge_data = b"X" * (1024 * 1024 + 10)  # Exceeds max_file_size limit (1MB)
        payload = {
            "filename": "huge.bin",
            "content": huge_data,
        }
        with self.assertRaises(OversizedFileError):
            self.upload_service.process_file(payload)

    def test_empty_file(self):
        empty_payload = {
            "filename": "empty.bin",
            "content": b"",
        }
        with self.assertRaises(ValidationError):
            self.upload_service.process_file(empty_payload)

    def test_multiple_files_upload(self):
        file1 = {"filename": "doc1.pdf", "content": b"PDF-1.4 Data"}
        file2 = {"filename": "doc2.pdf", "content": b"PDF-1.5 Data"}
        results = self.upload_service.process_multiple_files([file1, file2])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["fileName"], "doc1.pdf")
        self.assertEqual(results[1]["fileName"], "doc2.pdf")
        self.assertNotEqual(results[0]["analysisId"], results[1]["analysisId"])

    def test_pass_to_analysis_pipeline_callback(self):
        passed = {}

        def dummy_pipeline(file_path, analysis_id):
            passed["file_path"] = file_path
            passed["analysis_id"] = analysis_id

        payload = {"filename": "test.dat", "content": b"Pipeline test data"}
        res = self.upload_service.process_file(payload, pipeline_callback=dummy_pipeline)

        self.assertEqual(passed.get("file_path"), res["filePath"])
        self.assertEqual(passed.get("analysis_id"), res["analysisId"])

    def test_temporary_file_cleanup(self):
        payload = {"filename": "clean_me.txt", "content": b"Temp data"}
        res = self.upload_service.process_file(payload)
        analysis_id = res["analysisId"]
        file_path = res["filePath"]

        self.assertTrue(os.path.exists(file_path))
        self.upload_service.cleanup_analysis(analysis_id)
        self.assertFalse(os.path.exists(file_path))


if __name__ == "__main__":
    unittest.main()
