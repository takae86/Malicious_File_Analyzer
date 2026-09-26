"""
Indicators module for Malicious File Analyzer.
Defines indicator data structures and factory functions for reporting threat findings.
"""

from typing import Dict, Any, Optional


class Indicator:
    """Represents a discrete security finding or suspicious heuristic indicator."""

    def __init__(
        self,
        id: str,
        title: str,
        description: str,
        severity: str = "MEDIUM",
        category: str = "General",
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize an Indicator instance.

        :param id: Unique identifier code for the indicator (e.g., 'IND_DOUBLE_EXT')
        :param title: Short human-readable summary
        :param description: Detailed explanation of why this was flagged
        :param severity: Severity level ('LOW', 'MEDIUM', 'HIGH')
        :param category: Classification category (e.g., 'Signature', 'Entropy', 'Heuristic')
        :param details: Additional contextual key-value pairs
        """
        self.id = id
        self.title = title
        self.description = description
        self.severity = severity.upper() if severity else "MEDIUM"
        self.category = category
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert indicator to standardized dictionary format."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "details": self.details,
        }

    def __repr__(self) -> str:
        return f"<Indicator {self.id}: {self.title} [{self.severity}]>"


def create_indicator(
    id: str,
    title: str,
    description: str,
    severity: str = "MEDIUM",
    category: str = "General",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Helper factory function to create a standardized indicator dict."""
    indicator = Indicator(
        id=id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        details=details,
    )
    return indicator.to_dict()
