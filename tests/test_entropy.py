"""
Unit tests for backend/analyzer/entropy.py
Owner: Member 1 (Team Lead)
Compatible with both unittest and pytest
"""

import unittest
from backend.analyzer.entropy import calculate_entropy


class TestEntropy(unittest.TestCase):
    def test_entropy_zero_variance(self):
        # Identical bytes have 0 entropy
        data = b"\x00" * 1000
        res = calculate_entropy(data)
        self.assertEqual(res["entropy"], 0.0)
        self.assertFalse(res["isHighEntropy"])

    def test_entropy_high_random(self):
        # Uniform distribution across all 256 bytes has ~8.0 entropy
        data = bytes([i % 256 for i in range(10000)])
        res = calculate_entropy(data)
        self.assertGreaterEqual(res["entropy"], 7.5)
        self.assertTrue(res["isHighEntropy"])

    def test_entropy_empty(self):
        res = calculate_entropy(b"")
        self.assertEqual(res["entropy"], 0.0)
        self.assertFalse(res["isHighEntropy"])

    def test_entropy_scale_range(self):
        data = b"This is a standard text string with normal distribution."
        res = calculate_entropy(data)
        self.assertTrue(0.0 <= res["entropy"] <= 8.0)


if __name__ == "__main__":
    unittest.main()
