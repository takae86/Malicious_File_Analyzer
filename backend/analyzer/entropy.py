"""
Malicious File Analyzer - Shannon Entropy Module
Owner: Member 1 (Team Lead)

Calculates Shannon entropy on a scale of 0.00 to 8.00.
High entropy (> 7.00) indicates potential packing/encryption.
"""

import math
import os
from typing import Dict, Union
from collections import Counter


class EntropyResult(float):
    """
    Float subclass representing entropy that also behaves like a dict
    for backward/forward integration compatibility.
    """
    def __new__(cls, value: float, is_high: bool = False):
        val = round(float(value), 2)
        obj = super().__new__(cls, val)
        obj.entropy = val
        obj.isHighEntropy = is_high
        return obj

    def __getitem__(self, item):
        if item == "entropy":
            return float(self)
        elif item == "isHighEntropy":
            return self.isHighEntropy
        raise KeyError(item)

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default


def calculate_entropy(file_input: Union[str, bytes]) -> EntropyResult:
    """
    Calculates Shannon Entropy for the given file or bytes.

    :param file_input: File path (str) or raw bytes (bytes).
    :return: EntropyResult (behaves as both float and dict).
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
        return EntropyResult(0.0, False)

    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    entropy_val = round(entropy, 2)
    is_high_entropy = entropy_val >= 7.0

    return EntropyResult(entropy_val, is_high_entropy)
