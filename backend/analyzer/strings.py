"""
Malicious File Analyzer - String Extraction Module
Owner: Member 1 (Team Lead)

Extracts ASCII and UTF-16 readable strings from binary files.
Also flags potential Indicators of Compromise (IOCs) such as URLs,
IP addresses, system commands, and sensitive file paths.
"""

import re
import os
from typing import Dict, List, Union

# Regex patterns for IOC detection
URL_REGEX = re.compile(rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{4,}', re.IGNORECASE)
IPV4_REGEX = re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
SUSPICIOUS_COMMANDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "certutil",
    "bitsadmin", "reg.exe", "net.exe", "whoami", "rundll32",
    "schtasks", "vssadmin", "mimikatz", "invoke-expression", "iex"
]


def extract_strings(
    file_input: Union[str, bytes],
    min_length: int = 4,
    max_strings: int = 200
) -> Dict[str, Union[List[str], Dict[str, List[str]]]]:
    """
    Extracts readable ASCII and UTF-16 strings, and identifies IOC patterns.

    :param file_input: File path (str) or raw bytes (bytes).
    :param min_length: Minimum character sequence length (default: 4).
    :param max_strings: Maximum number of general strings to return.
    :return: Dictionary containing 'strings' and 'suspiciousPatterns'.
    """
    if isinstance(file_input, bytes):
        raw_data = file_input
    elif isinstance(file_input, str):
        if not os.path.exists(file_input):
            raise FileNotFoundError(f"File not found: {file_input}")
        with open(file_input, "rb") as f:
            # Read up to first 5MB to avoid denial-of-service on huge files
            raw_data = f.read(5 * 1024 * 1024)
    else:
        raise TypeError("file_input must be a file path (str) or bytes")

    # Extract ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
    ascii_matches = [m.decode('latin-1') for m in ascii_pattern.findall(raw_data)]

    # Extract UTF-16LE strings (common in Windows binaries)
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
    # Filter out common private/invalid IPs
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

    return {
        "strings": all_strings[:max_strings],
        "suspiciousPatterns": {
            "urls": detected_urls[:50],
            "ips": filtered_ips[:50],
            "commands": detected_commands
        }
    }
