"""
Malicious File Analyzer - Core Static Analysis Package
Owner: Member 1 (Team Lead)

Exports all static analysis modules and provides the unified static analysis
aggregator `run_static_analysis` adhering strictly to CONTRACT.md.
"""

import os
from typing import Dict, Any

from .hashing import compute_hashes
from .file_signature import detect_signature
from .entropy import calculate_entropy
from .strings import extract_strings
from .pe_analysis import analyze_pe
from .file_metadata import get_file_metadata


def run_static_analysis(file_path: str, original_filename: str = "") -> Dict[str, Any]:
    """
    Executes the entire static analysis pipeline on a file and produces
    the fixed analysis output format required by CONTRACT.md.

    :param file_path: Absolute or relative path to the target file.
    :param original_filename: Name of the file as submitted by the user.
    :return: Standardized analysis dictionary ready for risk assessment.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    filename = original_filename if original_filename else os.path.basename(file_path)

    # 1. Basic Metadata
    metadata = get_file_metadata(file_path, filename)

    # 2. Cryptographic Hashing (MD5 + SHA-256)
    hashes = compute_hashes(file_path)

    # 3. Magic Byte & Signature Detection
    sig_info = detect_signature(file_path, filename)

    # 4. Shannon Entropy (0.0 - 8.0)
    entropy_info = calculate_entropy(file_path)

    # 5. Printable String Extraction & IOC Detection
    string_info = extract_strings(file_path)

    # 6. Windows PE Analysis
    pe_info = analyze_pe(file_path)

    # Aggregate into CONTRACT.md analysis format
    return {
        "fileName": metadata["fileName"],
        "fileSize": metadata["fileSize"],
        "fileType": sig_info["detectedType"],
        "signature": sig_info["signature"],
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "entropy": entropy_info["entropy"],
        "strings": string_info["strings"],
        "pe": pe_info.get("details") or {},
        "raw_findings": {
            "isMismatch": sig_info["isMismatch"],
            "signatureWarning": sig_info["warning"],
            "isHighEntropy": entropy_info["isHighEntropy"],
            "suspiciousPatterns": string_info["suspiciousPatterns"],
            "isPE": pe_info["isPE"],
            "peMessage": pe_info["message"],
            "suspiciousImports": pe_info.get("details", {}).get("suspiciousImports", []) if pe_info.get("details") else []
        }
    }


__all__ = [
    "compute_hashes",
    "detect_signature",
    "calculate_entropy",
    "extract_strings",
    "analyze_pe",
    "get_file_metadata",
    "run_static_analysis"
]
