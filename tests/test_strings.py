"""
Unit tests for backend/analyzer/strings.py
Owner: Member 1 (Team Lead)
Compatible with both unittest and pytest
"""

import unittest
from backend.analyzer.strings import extract_strings


class TestStrings(unittest.TestCase):
    def test_strings_ascii_extraction(self):
        content = b"\x00\x01\x02TargetStringOne\x00\xffAnotherSecretValue\x00"
        res = extract_strings(content, min_length=4)
        self.assertIn("TargetStringOne", res["strings"])
        self.assertIn("AnotherSecretValue", res["strings"])

    def test_strings_utf16_extraction(self):
        raw_utf16 = "WindowsSecretString".encode("utf-16le")
        content = b"\x00\x00" + raw_utf16 + b"\x00\x00"
        res = extract_strings(content, min_length=4)
        self.assertIn("WindowsSecretString", res["strings"])

    def test_strings_ioc_detection(self):
        data = (
            b"Connecting to http://malicious-c2-domain.com/beacon "
            b"at remote IP 198.51.100.25 via powershell -ExecutionPolicy Bypass"
        )
        res = extract_strings(data)
        patterns = res["suspiciousPatterns"]

        self.assertTrue(any("http://malicious-c2-domain.com/beacon" in u for u in patterns["urls"]))
        self.assertIn("198.51.100.25", patterns["ips"])
        self.assertIn("powershell", patterns["commands"])


if __name__ == "__main__":
    unittest.main()
