"""
Unit tests for backend/analyzer/pe_analysis.py
Owner: Member 1 (Team Lead)
Compatible with both unittest and pytest
"""

import os
import tempfile
import unittest
from backend.analyzer.pe_analysis import analyze_pe


class TestPEAnalysis(unittest.TestCase):
    def test_pe_analysis_non_pe_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"This is purely text, definitely not a PE file.")
            tmp_path = tmp.name

        try:
            res = analyze_pe(tmp_path)
            # CRITICAL CONTRACT: Must return controlled response without crashing
            self.assertFalse(res["isPE"])
            self.assertTrue("not a Windows PE" in res["message"] or "Missing MZ" in res["message"])
            self.assertIsNone(res["details"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_pe_analysis_nonexistent_file(self):
        res = analyze_pe("non_existent_file_path.exe")
        self.assertFalse(res["isPE"])
        self.assertIn("File does not exist", res["message"])


if __name__ == "__main__":
    unittest.main()
