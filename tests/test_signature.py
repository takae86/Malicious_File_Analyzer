"""
Unit tests for backend/analyzer/file_signature.py
Owner: Member 1 (Team Lead)
Compatible with both unittest and pytest
"""

import unittest
from backend.analyzer.file_signature import detect_signature


class TestSignature(unittest.TestCase):
    def test_signature_pe(self):
        data = b"MZ" + b"\x00" * 60
        res = detect_signature(data, "test.exe")
        self.assertEqual(res["signature"], "MZ")
        self.assertIn("PE Executable", res["detectedType"])
        self.assertFalse(res["isMismatch"])
        self.assertIsNone(res["warning"])

    def test_signature_pdf(self):
        data = b"%PDF-1.5 test document"
        res = detect_signature(data, "document.pdf")
        self.assertEqual(res["signature"], "%PDF")
        self.assertEqual(res["detectedType"], "PDF Document")
        self.assertFalse(res["isMismatch"])

    def test_signature_mismatch_detection(self):
        # PE file disguised as a PDF
        disguised_data = b"MZ" + b"\x90\x00" * 30
        res = detect_signature(disguised_data, "suspicious.pdf")
        self.assertTrue(res["isMismatch"])
        self.assertIsNotNone(res["warning"])
        self.assertIn("does not match detected type", res["warning"])

    def test_signature_zip(self):
        data = b"PK\x03\x04" + b"\x00" * 20
        res = detect_signature(data, "archive.zip")
        self.assertEqual(res["signature"], "PK..")
        self.assertEqual(res["detectedType"], "ZIP Archive")
        self.assertFalse(res["isMismatch"])


if __name__ == "__main__":
    unittest.main()
