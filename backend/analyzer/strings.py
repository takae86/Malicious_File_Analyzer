"""
Malicious File Analyzer - String Extraction Module
Owner: Member 1 (Team Lead)

Extracts ASCII and UTF-16 readable strings from binary files.
Also flags potential Indicators of Compromise (IOCs).
"""

import re
import os
from typing import Dict, List, Union

URL_REGEX = re.compile(rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{4,}', re.IGNORECASE)
IPV4_REGEX = re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
SUSPICIOUS_COMMANDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "certutil",
    "bitsadmin", "reg.exe", "net.exe", "whoami", "rundll32",
    "schtasks", "vssadmin", "mimikatz", "invoke-expression", "iex"
]


class StringsResult(list):
    """
    List subclass containing extracted strings that also supports dict access
    for full compatibility with both Member 4's services and Lead 1's tests.
    """
    def __init__(self, strings_list: List[str], suspicious_patterns: Dict[str, Any]):
        super().__init__(strings_list)
        self.strings = strings_list
        self.suspiciousPatterns = suspicious_patterns

    def __getitem__(self, item):
        if item == "strings":
            return self.strings
        elif item == "suspiciousPatterns":
            return self.suspiciousPatterns
        return super().__getitem__(item)

    def get(self, item, default=None):
        if item == "strings":
            return self.strings
        elif item == "suspiciousPatterns":
            return self.suspiciousPatterns
        return default


def extract_strings(
    file_input: Union[str, bytes],
    min_length: int = 4,
    max_strings: int = 200
) -> StringsResult:
    """
    Extracts readable ASCII and UTF-16 strings, and identifies IOC patterns.
    """
    if isinstance(file_input, bytes):
        raw_data = file_input
    elif isinstance(file_input, str):
        if not os.path.exists(file_input):
            raise FileNotFoundError(f"File not found: {file_input}")
        with open(file_input, "rb") as f:
            raw_data = f.read(5 * 1024 * 1024)
    else:
        raise TypeError("file_input must be a file path (str) or bytes")

    # Extract ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
    ascii_matches = [m.decode('latin-1') for m in ascii_pattern.findall(raw_data)]

    # Extract UTF-16LE strings
    utf16_pattern = re.compile(rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}')
    utf16_matches = []
    for m in utf16_pattern.findall(raw_data):
        try:
            utf16_matches.append(m.decode('utf-16le'))
        except UnicodeDecodeError:
            continue

    all_strings = []
    seen = set()
    for s in ascii_matches + utf16_matches:
        cleaned = s.strip()
        if len(cleaned) >= min_length and cleaned not in seen:
            seen.add(cleaned)
            all_strings.append(cleaned)

    # Extract IOCs
    detected_urls = list({u.decode('latin-1') for u in URL_REGEX.findall(raw_data)})
    detected_ips = list({ip.decode('latin-1') for ip in IPV4_REGEX.findall(raw_data)})
    filtered_ips = [
        ip for ip in detected_ips
        if not ip.startswith(("0.", "127.", "255."))
    ]

    detected_commands = []
    lower_strings = [s.lower() for s in all_strings]
    for cmd in SUSPICIOUS_COMMANDS:
        for s in lower_strings:
            if cmd in s and cmd not in detected_commands:
                detected_commands.append(cmd)

    return StringsResult(
        all_strings[:max_strings],
        {
            "urls": detected_urls[:50],
            "ips": filtered_ips[:50],
            "commands": detected_commands
        }
    )
