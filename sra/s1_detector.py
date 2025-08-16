import re
from typing import Dict, Any

class S1Detector:
    """Very small, fast pattern-based detector for demo."""
    def __init__(self):
        self.patterns_high = [
            r"ignore.{0,20}previous.{0,20}instructions",
            r"(reveal|show).{0,10}(system|training|secret|api|key|prompt)",
            r"<!--.*?-->",
        ]
        self.patterns_medium = [
            r"(bypass|override|circumvent).{0,20}(safety|policy|guard|rule)",
            r"(jailbreak|exploit|hack)",
        ]

    def classify(self, text: str) -> Dict[str, Any]:
        for pat in self.patterns_high:
            if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                return {
                    "risk_level": "high",
                    "confidence": 0.95,
                    "reason": f"Matched: {pat}"
                }
        for pat in self.patterns_medium:
            if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                return {
                    "risk_level": "medium",
                    "confidence": 0.80,
                    "reason": f"Matched: {pat}"
                }
        return {
            "risk_level": "low",
            "confidence": 0.75,
            "reason": "No suspicious patterns detected"
        }