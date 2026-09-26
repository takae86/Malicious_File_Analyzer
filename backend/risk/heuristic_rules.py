"""
Heuristic rules module for Malicious File Analyzer.
Contains heuristic inspection logic and rules evaluation based on static analysis findings.
"""

import re
from typing import Dict, Any, List
from .indicators import create_indicator

# Known executable extensions that attackers commonly mask
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".pif", ".bat", ".cmd", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta",
    ".jar", ".msi", ".com"
}

# Common legitimate compound extensions
LEGITIMATE_COMPOUND_EXTS = {
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.z", ".user.js", ".min.js",
    ".min.css", ".d.ts", ".spec.ts", ".test.js", ".config.js"
}

# Suspicious section names often associated with packers or protectors
SUSPICIOUS_SECTIONS = {
    "upx0", "upx1", "upx2", "aspack", "adata", "nsp0", "nsp1", "nsp2",
    "petite", "fsg", "mew", "pecompact", "themida", "vmprotect", ".ndata"
}

# Suspicious Windows API imports commonly seen in malware
SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "createremotethread", "ntcreatethreadex",
    "queueuserapc", "setwindowshookex", "setwindowshookexa", "setwindowshookexw",
    "winexec", "shellexecutea", "shellexecutew", "urldownloadtofile",
    "urldownloadtofilea", "urldownloadtofilew", "httpsendrequesta", "httpsendrequestw",
    "internetopenurla", "internetopenurlw", "regsetvalueexa", "regsetvalueexw",
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"
}

# Suspicious string patterns
SUSPICIOUS_STRING_PATTERNS = [
    (r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\s+.*(?:-enc|-encodedcommand|-nop|-w\s+hidden|-exec\s+bypass)", "Obfuscated or hidden PowerShell invocation", "HIGH"),
    (r"(?i)\b(?:cmd\.exe\s+/c|rundll32\.exe|certutil\.exe\s+-urlcache|bitsadmin\.exe\s+/transfer)", "Suspicious system command execution", "HIGH"),
    (r"(?i)\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog)", "Shadow copy deletion (Ransomware behavior)", "HIGH"),
    (r"(?i)\b(?:mimikatz|sekurlsa|lsass\.dmp|samlib\.dll|lazagne)", "Credential dumping reference", "HIGH"),
    (r"(?i)\b(?:WScript\.Shell|Shell\.Application|ActiveXObject)\b", "Suspicious script automation object", "MEDIUM"),
    (r"(?i)\bHKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b", "Persistence registry run key reference", "MEDIUM"),
    (r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/[^\s]*)?", "Direct IP URL reference", "MEDIUM"),
]


def check_double_extension(filename: str) -> List[Dict[str, Any]]:
    """Check for suspicious double extensions (e.g., invoice.pdf.exe)."""
    indicators = []
    if not filename:
        return indicators

    filename_lower = filename.lower()
    
    # Check if filename uses Right-to-Left Override (RLO)
    if "\u202e" in filename:
        indicators.append(
            create_indicator(
                id="IND_RLO_CHARACTER",
                title="Right-to-Left Override (RLO) character detected",
                description="The filename contains an RLO character (U+202E) used to spoof extensions.",
                severity="HIGH",
                category="Filename",
                details={"filename": filename}
            )
        )

    # Check for excessive whitespace before extension
    if re.search(r"\s{4,}\.[a-zA-Z0-9]+$", filename):
        indicators.append(
            create_indicator(
                id="IND_SPACED_EXTENSION",
                title="Padded spaces before extension detected",
                description="The filename contains extensive spaces before the extension to hide it in UI.",
                severity="HIGH",
                category="Filename",
                details={"filename": filename}
            )
        )

    # Check double extension
    parts = filename_lower.split(".")
    if len(parts) >= 3:
        # Check if it's a known benign compound extension
        combined_tail = f".{parts[-2]}.{parts[-1]}"
        if combined_tail not in LEGITIMATE_COMPOUND_EXTS:
            last_ext = f".{parts[-1]}"
            prev_ext = f".{parts[-2]}"
            
            # If the final extension is executable and previous is document/image/archive
            if last_ext in EXECUTABLE_EXTENSIONS and prev_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".png", ".txt", ".mp4", ".zip", ".rar"}:
                indicators.append(
                    create_indicator(
                        id="IND_DOUBLE_EXTENSION",
                        title="Suspicious double file extension detected",
                        description=f"File masquerades with dual extension '{prev_ext}{last_ext}' to mislead users.",
                        severity="HIGH",
                        category="Filename",
                        details={"primary_extension": prev_ext, "actual_extension": last_ext}
                    )
                )
    return indicators


def check_signature_mismatch(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check if detected magic byte signature mismatches the filename extension."""
    indicators = []
    
    # Direct boolean input support from contract
    if findings.get("signatureMismatch") is True:
        indicators.append(
            create_indicator(
                id="IND_SIGNATURE_MISMATCH",
                title="File signature mismatch detected",
                description="The detected file type magic bytes do not match the declared file extension.",
                severity="HIGH",
                category="Signature",
                details=findings.get("signatureDetails", {})
            )
        )
        return indicators

    filename = findings.get("fileName") or findings.get("filename") or ""
    file_type = findings.get("fileType") or findings.get("file_type") or ""
    signature = findings.get("signature") or ""
    
    if not filename:
        return indicators

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    type_lower = file_type.lower()

    # If extension claims benign document/image but header is executable/PE
    if ext in {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".csv"}:
        if "pe" in type_lower or "executable" in type_lower or signature.upper().startswith("MZ"):
            indicators.append(
                create_indicator(
                    id="IND_SIGNATURE_MISMATCH",
                    title="File signature mismatch detected",
                    description=f"File extension '{ext}' disguises a Windows Executable (PE) binary.",
                    severity="HIGH",
                    category="Signature",
                    details={"claimed_extension": ext, "detected_type": file_type, "signature": signature}
                )
            )
    return indicators


def check_entropy(entropy_val: float) -> List[Dict[str, Any]]:
    """Check Shannon entropy value for signs of packing or encryption."""
    indicators = []
    if entropy_val is None:
        return indicators

    if entropy_val >= 7.2:
        indicators.append(
            create_indicator(
                id="IND_HIGH_ENTROPY",
                title="High Shannon entropy detected",
                description=f"Entropy is {entropy_val:.2f}/8.00. This strongly suggests packed, compressed, or encrypted payload.",
                severity="HIGH" if entropy_val >= 7.5 else "MEDIUM",
                category="Entropy",
                details={"entropy": round(entropy_val, 2)}
            )
        )
    elif entropy_val >= 6.5:
        indicators.append(
            create_indicator(
                id="IND_ELEVATED_ENTROPY",
                title="Elevated Shannon entropy detected",
                description=f"Entropy is {entropy_val:.2f}/8.00, indicating compressed or dense content.",
                severity="LOW",
                category="Entropy",
                details={"entropy": round(entropy_val, 2)}
            )
        )
    return indicators


def check_pe_findings(pe_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Inspect PE structure for suspicious sections and API imports."""
    indicators = []
    if not isinstance(pe_data, dict) or not pe_data:
        return indicators

    # Check suspicious sections
    sections = pe_data.get("sections") or []
    for section in sections:
        sec_name = section.get("name", "").strip().lower() if isinstance(section, dict) else str(section).strip().lower()
        if any(susp in sec_name for susp in SUSPICIOUS_SECTIONS):
            indicators.append(
                create_indicator(
                    id="IND_SUSPICIOUS_SECTION",
                    title=f"Suspicious PE section detected ({sec_name})",
                    description=f"The PE section '{sec_name}' is commonly produced by executable packers (e.g., UPX, ASPack).",
                    severity="HIGH",
                    category="PE Structure",
                    details={"section_name": sec_name}
                )
            )
            break

    # Check suspicious imports
    imports = pe_data.get("imports") or []
    found_suspicious_apis = []
    if isinstance(imports, list):
        for item in imports:
            func_name = ""
            if isinstance(item, dict):
                func_name = item.get("name", "").lower()
            elif isinstance(item, str):
                func_name = item.lower()
            if func_name in SUSPICIOUS_IMPORTS:
                found_suspicious_apis.append(func_name)

    if found_suspicious_apis:
        indicators.append(
            create_indicator(
                id="IND_SUSPICIOUS_APIS",
                title="Dangerous Windows API imports detected",
                description=f"Executable imports sensitive APIs frequently used in process injection, debugging evasion, or downloader malware.",
                severity="HIGH" if len(found_suspicious_apis) >= 3 else "MEDIUM",
                category="PE Structure",
                details={"apis": list(set(found_suspicious_apis))[:10]}
            )
        )

    return indicators


def check_strings(strings_list: List[str]) -> List[Dict[str, Any]]:
    """Scan extracted strings for suspicious commands, URLs, or indicators."""
    indicators = []
    if not strings_list:
        return indicators

    # Combine or iterate strings
    sample_text = "\n".join(strings_list[:2000])  # limit search space for performance

    for pattern, description, severity in SUSPICIOUS_STRING_PATTERNS:
        matches = re.findall(pattern, sample_text)
        if matches:
            indicators.append(
                create_indicator(
                    id="IND_SUSPICIOUS_STRING",
                    title=description,
                    description=f"Found pattern match: {description}",
                    severity=severity,
                    category="Strings",
                    details={"matches": [m[:100] for m in matches[:5]]}
                )
            )
    return indicators


def evaluate_heuristics(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Run all heuristic rules against the provided analysis findings dictionary.
    
    :param findings: Dictionary with analysis metadata and results
    :return: List of indicator dictionaries
    """
    indicators = []

    # 1. Direct boolean indicators contract support (e.g. { "signatureMismatch": true, ... })
    if findings.get("doubleExtension") is True:
        indicators.append(
            create_indicator(
                id="IND_DOUBLE_EXTENSION",
                title="Double extension detected",
                description="A secondary executable extension was detected.",
                severity="HIGH",
                category="Filename"
            )
        )

    if findings.get("highEntropy") is True:
        indicators.append(
            create_indicator(
                id="IND_HIGH_ENTROPY",
                title="High entropy detected",
                description="High Shannon entropy indicates potential packing or encryption.",
                severity="HIGH",
                category="Entropy"
            )
        )

    # 2. Heuristic checks on explicit file fields
    filename = findings.get("fileName") or findings.get("filename") or ""
    if filename and not findings.get("doubleExtension"):
        indicators.extend(check_double_extension(filename))

    indicators.extend(check_signature_mismatch(findings))

    entropy_val = findings.get("entropy")
    if isinstance(entropy_val, (int, float)) and not findings.get("highEntropy"):
        indicators.extend(check_entropy(float(entropy_val)))

    pe_info = findings.get("pe") or {}
    if isinstance(pe_info, dict):
        indicators.extend(check_pe_findings(pe_info))

    strings_data = findings.get("strings") or []
    if isinstance(strings_data, list):
        indicators.extend(check_strings(strings_data))

    # 3. Incorporate any pre-existing suspicious patterns or indicators passed in
    suspicious_patterns = findings.get("suspiciousPatterns") or []
    for pat in suspicious_patterns:
        if isinstance(pat, str):
            indicators.append(
                create_indicator(
                    id="IND_CUSTOM_PATTERN",
                    title="Suspicious pattern detected",
                    description=pat,
                    severity="MEDIUM",
                    category="Pattern"
                )
            )
        elif isinstance(pat, dict):
            indicators.append(pat)

    existing_indicators = findings.get("indicators") or []
    for ind in existing_indicators:
        if isinstance(ind, dict) and ind not in indicators:
            indicators.append(ind)

    return indicators
