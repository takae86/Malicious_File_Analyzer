"""
Analysis service module for Malicious File Analyzer.
Orchestrates file processing, static analysis, risk assessment, and report generation.
"""

import hashlib
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from backend.risk.risk_engine import evaluate_risk


class AnalysisService:
    """Service handling file analysis pipeline and persistent result management."""

    def __init__(self):
        # In-memory storage for analysis records: analysisId -> result dict
        self._storage: Dict[str, Dict[str, Any]] = {}

    def _generate_analysis_id(self) -> str:
        """Generate a short unique analysis identifier."""
        return f"A{uuid.uuid4().hex[:8].upper()}"

    def _calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Compute MD5 and SHA-256 hashes for binary data."""
        # Check if Member 1's hashing module is available
        try:
            from backend.analyzer.hashing import calculate_hashes as m1_hashes
            return m1_hashes(data)
        except ImportError:
            md5_hash = hashlib.md5(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            return {
                "md5": md5_hash,
                "sha256": sha256_hash
            }

    def _calculate_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy (0.0 to 8.0 scale)."""
        # Check if Member 1's entropy module is available
        try:
            from backend.analyzer.entropy import calculate_entropy as m1_entropy
            return float(m1_entropy(data))
        except ImportError:
            if not data:
                return 0.0
            byte_counts = [0] * 256
            for b in data:
                byte_counts[b] += 1
            length = len(data)
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    prob = count / length
                    entropy -= prob * math.log2(prob)
            return round(entropy, 2)

    def _detect_signature(self, data: bytes, filename: str) -> Dict[str, str]:
        """Detect file magic bytes and MIME/file type."""
        # Check if Member 1's signature module is available
        try:
            from backend.analyzer.file_signature import detect_signature as m1_sig
            return m1_sig(data, filename)
        except ImportError:
            if data.startswith(b"MZ"):
                return {"signature": "MZ", "fileType": "Windows PE Executable"}
            elif data.startswith(b"%PDF"):
                return {"signature": "%PDF", "fileType": "PDF Document"}
            elif data.startswith(b"PK\x03\x04"):
                return {"signature": "PK", "fileType": "ZIP Archive / Office Open XML"}
            elif data.startswith(b"\x7fELF"):
                return {"signature": "ELF", "fileType": "Linux ELF Executable"}
            elif data.startswith(b"\x89PNG\r\n\x1a\n"):
                return {"signature": "PNG", "fileType": "PNG Image"}
            elif data.startswith(b"\xff\xd8\xff"):
                return {"signature": "JPEG", "fileType": "JPEG Image"}
            elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
                return {"signature": "GIF", "fileType": "GIF Image"}
            elif data.startswith(b"Rar!\x1a\x07"):
                return {"signature": "RAR", "fileType": "RAR Archive"}
            elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
                return {"signature": "7Z", "fileType": "7-Zip Archive"}
            else:
                ext = filename.rsplit(".", 1)[-1].upper() if "." in filename else "UNKNOWN"
                return {"signature": "UNKNOWN", "fileType": f"{ext} File (Generic / Unknown Binary)"}

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract printable ASCII and UTF-16 strings."""
        # Check if Member 1's strings module is available
        try:
            from backend.analyzer.strings import extract_strings as m1_strings
            return m1_strings(data, min_len)
        except ImportError:
            # Extract ASCII strings
            ascii_matches = re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
            results = [m.decode("ascii", errors="ignore") for m in ascii_matches[:500]]
            return results

    def _analyze_pe(self, data: bytes) -> Dict[str, Any]:
        """Perform basic Windows PE parsing safely without crashing on non-PE files."""
        # Check if Member 1's PE analysis module is available
        try:
            from backend.analyzer.pe_analysis import analyze_pe as m1_pe
            return m1_pe(data)
        except ImportError:
            if not data.startswith(b"MZ"):
                return {"is_pe": False, "status": "Not a PE file"}

            try:
                import pefile
                pe = pefile.PE(data=data, fast_load=True)
                sections = []
                for s in getattr(pe, "sections", []):
                    sec_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                    sections.append({
                        "name": sec_name,
                        "virtual_size": getattr(s, "Misc_VirtualSize", 0),
                        "raw_size": getattr(s, "SizeOfRawData", 0),
                    })

                imports = []
                try:
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imp in entry.imports:
                                if imp.name:
                                    imports.append(imp.name.decode("utf-8", errors="ignore"))
                except Exception:
                    pass

                return {
                    "is_pe": True,
                    "machine": hex(pe.FILE_HEADER.Machine) if hasattr(pe, "FILE_HEADER") else "Unknown",
                    "number_of_sections": len(sections),
                    "sections": sections,
                    "imports": imports[:100],
                }
            except Exception:
                # Return a controlled result rather than terminating execution
                return {"is_pe": True, "status": "PE header detected, detailed parse unavailable"}

    def analyze_file(self, filename: str, data: bytes) -> Dict[str, Any]:
        """
        Execute full static analysis pipeline for a single file payload.

        :param filename: Original name of the uploaded file
        :param data: Raw binary bytes of the file
        :return: Standardized analysis result dictionary conforming to CONTRACT.md
        """
        analysis_id = self._generate_analysis_id()
        file_size = len(data)

        # 1. Hashes
        hashes = self._calculate_hashes(data)

        # 2. Entropy
        entropy = self._calculate_entropy(data)

        # 3. File Signature
        sig_info = self._detect_signature(data, filename)
        file_type = sig_info.get("fileType", "Unknown")
        signature = sig_info.get("signature", "UNKNOWN")

        # 4. Strings Extraction
        strings = self._extract_strings(data)

        # 5. PE Analysis
        pe_info = self._analyze_pe(data)

        # 6. Prepare findings dict for Risk Engine
        preliminary_findings = {
            "fileName": filename,
            "fileSize": file_size,
            "fileType": file_type,
            "signature": signature,
            "entropy": entropy,
            "strings": strings,
            "pe": pe_info,
        }

        # 7. Evaluate Risk through Member 4 Risk Engine
        risk_result = evaluate_risk(preliminary_findings)
        indicators = risk_result.get("indicators", [])
        risk_level = risk_result.get("risk", "LOW")

        # 8. Assemble final contract-compliant object
        result = {
            "analysisId": analysis_id,
            "fileName": filename,
            "fileSize": file_size,
            "fileType": file_type,
            "signature": signature,
            "md5": hashes.get("md5", ""),
            "sha256": hashes.get("sha256", ""),
            "entropy": entropy,
            "strings": strings,
            "pe": pe_info,
            "indicators": indicators,
            "risk": risk_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Save in persistent storage
        self._storage[analysis_id] = result
        return result

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored analysis result by its ID."""
        return self._storage.get(analysis_id)

    def get_all_analyses(self) -> List[Dict[str, Any]]:
        """Retrieve list of all stored analysis records."""
        return list(self._storage.values())

    def generate_report(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate a detailed comprehensive report object for an analyzed file.

        :param analysis_id: Unique analysis ID
        :return: Report structure dictionary or None if analysis not found
        """
        analysis = self.get_analysis(analysis_id)
        if not analysis:
            return None

        # Build comprehensive report representation
        report = {
            "reportId": f"REP-{analysis['analysisId']}",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "target": {
                "fileName": analysis["fileName"],
                "fileSize": analysis["fileSize"],
                "fileType": analysis["fileType"],
                "signature": analysis["signature"],
                "md5": analysis["md5"],
                "sha256": analysis["sha256"],
            },
            "securitySummary": {
                "risk": analysis["risk"],
                "entropy": analysis["entropy"],
                "totalIndicators": len(analysis.get("indicators", [])),
                "indicators": analysis.get("indicators", []),
            },
            "technicalDetails": {
                "pe": analysis.get("pe", {}),
                "extractedStringsSample": analysis.get("strings", [])[:50],
            },
            "disclaimer": "This report is based on static analysis heuristics only. It is not an absolute verdict."
        }
        return report


# Global service singleton instance
analysis_service = AnalysisService()
