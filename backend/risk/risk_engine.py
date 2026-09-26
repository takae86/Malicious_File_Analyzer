"""
Risk engine module for Malicious File Analyzer.
Evaluates structured analysis findings and calculates overall risk levels (LOW, MEDIUM, HIGH).
"""

from typing import Dict, Any, List
from .heuristic_rules import evaluate_heuristics

# Permitted risk levels strictly constrained by CONTRACT.md
ALLOWED_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}


class RiskEngine:
    """Core risk evaluation engine that classifies file threat levels."""

    def __init__(self):
        # Weights assigned to different indicator severities
        self.severity_scores = {
            "HIGH": 30,
            "MEDIUM": 15,
            "LOW": 5
        }

    def evaluate(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate analysis findings and return structured risk result.

        :param findings: Dictionary containing analysis metrics or indicators
        :return: Dict containing 'indicators' list and 'risk' string ("LOW"|"MEDIUM"|"HIGH")
        """
        if not findings or not isinstance(findings, dict):
            return {
                "indicators": [],
                "risk": "LOW"
            }

        # Collect all indicators via heuristic rules
        indicators = evaluate_heuristics(findings)

        # Calculate score and highest severity
        total_score = 0
        has_high_severity = False
        medium_count = 0

        for ind in indicators:
            sev = ind.get("severity", "MEDIUM").upper() if isinstance(ind, dict) else "MEDIUM"
            total_score += self.severity_scores.get(sev, 10)
            if sev == "HIGH":
                has_high_severity = True
            elif sev == "MEDIUM":
                medium_count += 1

        # Determine risk level based on severity and score
        if has_high_severity or total_score >= 30 or medium_count >= 2:
            risk = "HIGH"
        elif total_score >= 15 or medium_count >= 1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # Ensure risk is strictly one of the allowed contract values
        if risk not in ALLOWED_RISK_LEVELS:
            risk = "LOW"

        return {
            "indicators": indicators,
            "risk": risk
        }


def evaluate_risk(findings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standard interface function to assess risk for a given findings dictionary.
    
    :param findings: Analysis findings
    :return: {"indicators": [...], "risk": "LOW"|"MEDIUM"|"HIGH"}
    """
    engine = RiskEngine()
    return engine.evaluate(findings)
