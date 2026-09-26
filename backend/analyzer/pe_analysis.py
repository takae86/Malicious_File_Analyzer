"""
Malicious File Analyzer - PE Analysis Module
Owner: Member 1 (Team Lead)

Inspects Windows Portable Executable (PE) binaries (.exe, .dll, .sys).
Extracts header values, section characteristics, section entropy, and suspicious imported APIs.
CRITICAL CONTRACT REQUIREMENT:
If the file is not a supported PE, returns a controlled structured result without raising unhandled exceptions.
Supports both file paths and raw byte payloads.
"""

import os
from typing import Dict, Any, List, Union

SUSPICIOUS_PE_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext",
    "OpenProcess", "Process32First", "Process32Next", "CreateToolhelp32Snapshot",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "RegSetValueExA", "RegSetValueExW", "SetWindowsHookExA", "SetWindowsHookExW"
}


def analyze_pe(file_input: Union[str, bytes]) -> Dict[str, Any]:
    """
    Parses Windows PE headers and sections safely.

    :param file_input: Path to the target binary (str) or raw binary data (bytes).
    :return: Structured dictionary with PE inspection results.
    """
    raw_bytes = None
    file_path = None

    if isinstance(file_input, bytes):
        raw_bytes = file_input
        if not raw_bytes.startswith(b"MZ"):
            return {
                "isPE": False,
                "is_pe": False,
                "message": "File is not a Windows PE executable (Missing MZ signature)",
                "status": "Not a PE file",
                "details": None
            }
    elif isinstance(file_input, str):
        file_path = file_input
        if not os.path.exists(file_path):
            return {
                "isPE": False,
                "is_pe": False,
                "message": f"File does not exist: {file_path}",
                "status": "File does not exist",
                "details": None
            }
        try:
            with open(file_path, "rb") as f:
                magic = f.read(2)
                if magic != b"MZ":
                    return {
                        "isPE": False,
                        "is_pe": False,
                        "message": "File is not a Windows PE executable (Missing MZ signature)",
                        "status": "Not a PE file",
                        "details": None
                    }
        except Exception as e:
            return {
                "isPE": False,
                "is_pe": False,
                "message": f"Error reading file header: {str(e)}",
                "status": "Error reading file",
                "details": None
            }
    else:
        raise TypeError("file_input must be a file path (str) or bytes")

    try:
        import pefile
    except ImportError:
        return {
            "isPE": False,
            "is_pe": False,
            "message": "pefile library is not installed",
            "status": "pefile not installed",
            "details": None
        }

    try:
        if raw_bytes is not None:
            pe = pefile.PE(data=raw_bytes, fast_load=True)
        else:
            pe = pefile.PE(file_path, fast_load=True)

        pe.parse_data_directories()

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

        entry_point = "0x0"
        if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER:
            entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        sections_info: List[Dict[str, Any]] = []
        for sec in getattr(pe, "sections", []):
            sec_name = sec.Name.decode("latin-1", errors="ignore").strip("\x00")
            sec_entropy = round(sec.get_entropy(), 2)
            sections_info.append({
                "name": sec_name,
                "virtualAddress": hex(sec.VirtualAddress),
                "virtualSize": sec.Misc_VirtualSize,
                "virtual_size": sec.Misc_VirtualSize,
                "rawSize": sec.SizeOfRawData,
                "raw_size": sec.SizeOfRawData,
                "entropy": sec_entropy,
                "isHighEntropy": sec_entropy >= 7.0
            })

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
            "is_pe": True,
            "message": "Windows PE analysis completed",
            "machine": machine_type,
            "entry_point": entry_point,
            "number_of_sections": len(sections_info),
            "sections": sections_info,
            "imports": imported_functions[:100],
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
            "is_pe": False,
            "message": f"Malformed or unsupported PE format: {str(err)}",
            "status": "Malformed PE format",
            "details": None
        }
    except Exception as err:
        return {
            "isPE": False,
            "is_pe": False,
            "message": f"PE parsing error: {str(err)}",
            "status": "PE parsing error",
            "details": None
        }
