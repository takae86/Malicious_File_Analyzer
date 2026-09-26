"""
Unit tests for backend/analyzer/hashing.py
Owner: Member 1 (Team Lead)
Compatible with both unittest and pytest
"""

import os
import tempfile
import unittest
from backend.analyzer.hashing import compute_hashes


class TestHashing(unittest.TestCase):
    def test_hashing_with_bytes(self):
        # Hash for b"Hello World"
        result = compute_hashes(b"Hello World")
        self.assertEqual(result["md5"], "b10a8db164e0754105b7a99be72e3fe5")
        self.assertEqual(result["sha256"], "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")

    def test_hashing_with_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Test content for hashing module")
            tmp_path = tmp.name

        try:
            result = compute_hashes(tmp_path)
            self.assertEqual(len(result["md5"]), 32)
            self.assertEqual(len(result["sha256"]), 64)
            self.assertIsInstance(result["md5"], str)
            self.assertIsInstance(result["sha256"], str)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_hashing_nonexistent_file(self):
        with self.assertRaises(FileNotFoundError):
            compute_hashes("non_existent_file_path_12345.bin")


if __name__ == "__main__":
    unittest.main()
