"""
Malicious File Analyzer - Shannon Entropy Module
Owner: Member 1 (Team Lead)

Calculates Shannon entropy on a scale of 0.00 to 8.00.
High entropy (> 7.00) typically indicates encryption, packing, or compression,
a common hallmark of obfuscated malware.
"""

import math
import os
from typing import Dict, Union
from collections import Counter


def calculate_entropy(file_input: Union[str, bytes]) -> Dict[str, Union[float, bool]]:
    """
    Calculates Shannon Entropy for the given file or bytes.

    :param file_input: File path (str) or raw bytes (bytes).
    :return: Dictionary containing 'entropy' (float rounded to 2 decimals) and 'isHighEntropy' (bool).
    """
    byte_counts = Counter()
    total_bytes = 0

    if isinstance(file_input, bytes):
        byte_counts.update(file_input)
        total_bytes = len(file_input)
    elif isinstance(file_input, str):
        if not os.path.exists(file_input):
            raise FileNotFoundError(f"File not found: {file_input}")
        
        with open(file_input, "rb") as f:
            while chunk := f.read(65536):
                byte_counts.update(chunk)
                total_bytes += len(chunk)
    else:
        raise TypeError("file_input must be a file path (str) or bytes")

    if total_bytes == 0:
        return {
            "entropy": 0.0,
            "isHighEntropy": False
        }

    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    entropy_val = round(entropy, 2)
    # Entropy threshold >= 7.0 indicates high likelihood of packing or encryption
    is_high_entropy = entropy_val >= 7.0

    return {
        "entropy": entropy_val,
        "isHighEntropy": is_high_entropy
    }
