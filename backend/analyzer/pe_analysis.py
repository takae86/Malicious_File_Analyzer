"""
Malicious File Analyzer - PE Analysis Module
Owner: Member 1 (Team Lead)

Inspects Windows Portable Executable (PE) binaries (.exe, .dll, .sys).
Extracts header values, section characteristics, section entropy, and suspicious imported APIs.
CRITICAL CONTRACT REQUIREMENT:
If the file is not a supported PE, returns a controlled structured result without raising unhandled exceptions.
"""

import os
from typing import Dict, Any, List

# Highly suspicious Windows APIs commonly used by malware (injections, evasion, persistence)
SUSPICIOUS_PE_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext",
    "OpenProcess", "Process32First", "Process32Next", "CreateToolhelp32Snapshot",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "RegSetValueExA", "RegSetValueExW", "SetWindowsHookExA", "SetWindowsHookExW"
}


def analyze_pe(file_path: str) -> Dict[str, Any]:
    """
    Parses Windows PE headers and sections safely.

    :param file_path: Path to the target binary.
    :return: Structured dictionary with PE inspection results.
    """
    if not os.path.exists(file_path):
        return {
            "isPE": False,
            "message": f"File does not exist: {file_path}",
            "details": None
        }

    # Verify MZ header first before invoking pefile
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                return {
                    "isPE": False,
                    "message": "File is not a Windows PE executable (Missing MZ signature)",
                    "details": None
                }
    except Exception as e:
        return {
            "isPE": False,
            "message": f"Error reading file header: {str(e)}",
            "details": None
        }

    try:
        import pefile
    except ImportError:
        return {
            "isPE": False,
            "message": "pefile library is not installed",
            "details": None
        }

    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()

        # Architecture detection
        machine_type = "Unknown"
        if hasattr(pe, "FILE_HEADER") and pe.FILE_HEADER:
            if pe.FILE_HEADER.Machine == 0x014c:
                machine_type = "x86 (32-bit)"
            elif pe.FILE_HEADER.Machine == 0x8664:
                machine_type = "x64 (64-bit)"
            elif pe.FILE_HEADER.Machine == 0x0200:
                machine_type = "Intel Itanium"
            elif pe.FILE_HEADER.Machine == 0xaa64:
                machine_type = "ARM64"

        # Entry point
        entry_point = "0x0"
        if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER:
            entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # Parse sections
        sections_info: List[Dict[str, Any]] = []
        for sec in pe.sections:
            sec_name = sec.Name.decode("latin-1", errors="ignore").strip("\x00")
            sec_entropy = round(sec.get_entropy(), 2)
            sections_info.append({
                "name": sec_name,
                "virtualAddress": hex(sec.VirtualAddress),
                "virtualSize": sec.Misc_VirtualSize,
                "rawSize": sec.SizeOfRawData,
                "entropy": sec_entropy,
                "isHighEntropy": sec_entropy >= 7.0
            })

        # Parse imports & detect suspicious APIs
        imported_functions: List[str] = []
        suspicious_found: List[str] = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("latin-1", errors="ignore")
                        imported_functions.append(func_name)
                        if func_name in SUSPICIOUS_PE_APIS:
                            suspicious_found.append(func_name)

        pe.close()

        return {
            "isPE": True,
            "message": "Windows PE analysis completed",
            "details": {
                "machine": machine_type,
                "entryPoint": entry_point,
                "numberOfSections": len(sections_info),
                "sections": sections_info,
                "totalImports": len(imported_functions),
                "suspiciousImports": suspicious_found
            }
        }

    except pefile.PEFormatError as err:
        return {
            "isPE": False,
            "message": f"Malformed or unsupported PE format: {str(err)}",
            "details": None
        }
    except Exception as err:
        return {
            "isPE": False,
            "message": f"PE parsing error: {str(err)}",
            "details": None
        }
