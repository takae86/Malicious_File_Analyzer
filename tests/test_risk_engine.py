"""
Unit tests for the Risk Engine and Heuristic Rules (Role 4).
Validates risk calculation, indicator generation, and contract compliance.
"""

import unittest
from backend.risk.risk_engine import RiskEngine, evaluate_risk, ALLOWED_RISK_LEVELS
from backend.risk.indicators import Indicator, create_indicator
from backend.risk.heuristic_rules import (
    check_double_extension,
    check_signature_mismatch,
    check_entropy,
    check_pe_findings,
    check_strings,
    evaluate_heuristics,
)


class TestRiskEngine(unittest.TestCase):
    """Test suite for RiskEngine functionality and contract compliance."""

    def setUp(self):
        self.engine = RiskEngine()

    def test_contract_example_input_high_risk(self):
        """Test the exact example input from CONTRACT.md Section 7 & 11."""
        findings = {
            "signatureMismatch": True,
            "highEntropy": True,
            "doubleExtension": True,
            "suspiciousPatterns": [],
        }
        result = evaluate_risk(findings)

        self.assertIn("indicators", result)
        self.assertIn("risk", result)
        self.assertEqual(result["risk"], "HIGH")
        self.assertIn(result["risk"], ALLOWED_RISK_LEVELS)
        self.assertTrue(len(result["indicators"]) >= 3)

    def test_benign_file_low_risk(self):
        """Test a clean file findings dictionary produces LOW risk."""
        findings = {
            "fileName": "document.txt",
            "fileSize": 1200,
            "fileType": "Text Document",
            "signature": "TXT",
            "entropy": 3.45,
            "strings": ["Hello world", "Standard document content"],
            "pe": {},
        }
        result = self.engine.evaluate(findings)

        self.assertEqual(result["risk"], "LOW")
        self.assertIn(result["risk"], ALLOWED_RISK_LEVELS)
        self.assertEqual(len(result["indicators"]), 0)

    def test_double_extension_heuristic(self):
        """Test detection of masquerading double extensions."""
        findings = {
            "fileName": "invoice.pdf.exe",
            "fileSize": 50000,
            "fileType": "Windows PE Executable",
            "signature": "MZ",
            "entropy": 5.12,
            "strings": [],
            "pe": {},
        }
        result = self.engine.evaluate(findings)

        self.assertEqual(result["risk"], "HIGH")
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("IND_DOUBLE_EXTENSION", indicator_ids)

    def test_legitimate_double_extension(self):
        """Test that benign compound extensions like .tar.gz are not flagged."""
        indicators = check_double_extension("archive.tar.gz")
        self.assertEqual(len(indicators), 0)

    def test_signature_mismatch_detection(self):
        """Test detection when a file claims to be a PDF but has MZ PE header."""
        findings = {
            "fileName": "suspicious.pdf",
            "fileType": "Windows PE Executable",
            "signature": "MZ",
            "entropy": 5.80,
        }
        result = self.engine.evaluate(findings)

        self.assertEqual(result["risk"], "HIGH")
        indicator_ids = [ind["id"] for ind in result["indicators"]]
        self.assertIn("IND_SIGNATURE_MISMATCH", indicator_ids)

    def test_high_entropy_detection(self):
        """Test that entropy >= 7.2 produces high entropy indicator and elevated risk."""
        indicators = check_entropy(7.65)
        self.assertTrue(len(indicators) > 0)
        self.assertEqual(indicators[0]["id"], "IND_HIGH_ENTROPY")
        self.assertEqual(indicators[0]["severity"], "HIGH")

        # Evaluate through engine
        findings = {"entropy": 7.85, "fileName": "sample.bin"}
        result = self.engine.evaluate(findings)
        self.assertIn(result["risk"], {"MEDIUM", "HIGH"})

    def test_pe_suspicious_sections(self):
        """Test detection of packed sections like UPX0."""
        pe_data = {
            "sections": [
                {"name": "UPX0", "raw_size": 0},
                {"name": "UPX1", "raw_size": 15000},
                {"name": ".rsrc", "raw_size": 2048},
            ]
        }
        indicators = check_pe_findings(pe_data)
        self.assertTrue(len(indicators) > 0)
        self.assertEqual(indicators[0]["id"], "IND_SUSPICIOUS_SECTION")

    def test_pe_suspicious_imports(self):
        """Test detection of dangerous API imports."""
        pe_data = {
            "imports": [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "URLDownloadToFileA",
            ]
        }
        indicators = check_pe_findings(pe_data)
        self.assertTrue(len(indicators) > 0)
        self.assertEqual(indicators[0]["id"], "IND_SUSPICIOUS_APIS")

    def test_suspicious_strings_detection(self):
        """Test heuristic detection of command execution patterns in strings."""
        sample_strings = [
            "powershell.exe -nop -w hidden -enc JABhID0A...",
            "cmd.exe /c start evil.bat",
            "vssadmin delete shadows",
        ]
        indicators = check_strings(sample_strings)
        self.assertTrue(len(indicators) >= 2)

    def test_edge_cases_and_empty_input(self):
        """Test engine handles empty/None/malformed inputs safely without crashing."""
        empty_res = self.engine.evaluate({})
        self.assertEqual(empty_res["risk"], "LOW")
        self.assertEqual(empty_res["indicators"], [])

        none_res = self.engine.evaluate(None)
        self.assertEqual(none_res["risk"], "LOW")
        self.assertEqual(none_res["indicators"], [])

    def test_indicator_model_structure(self):
        """Test Indicator class structure and dictionary conversion."""
        ind = Indicator(
            id="IND_TEST",
            title="Test Title",
            description="Test Description",
            severity="HIGH",
            category="TestCategory",
            details={"key": "val"},
        )
        data = ind.to_dict()
        self.assertEqual(data["id"], "IND_TEST")
        self.assertEqual(data["title"], "Test Title")
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["category"], "TestCategory")
        self.assertEqual(data["details"], {"key": "val"})


if __name__ == "__main__":
    unittest.main()
