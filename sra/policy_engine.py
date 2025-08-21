# SPDX-License-Identifier: MIT
# Minimal policy engine for SRA demo
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import os
import yaml


@dataclass
class PolicyDecision:
    action: str                 # "allow" | "template" | "block"
    reason: str                 # short human-readable reason
    policy_rule: str            # rule id / label
    template_set: Optional[List[str]] = None
    retry_after: Optional[int] = None  # seconds (optional)


class PolicyEngine:
    """
    Demo-grade policy engine:
    - Loads thresholds & routing rules from YAML (or uses safe defaults)
    - Evaluates against S1 risk, optional scope & budget hints from caller
    """

    def __init__(self, config_path: Optional[str] = None):
        self._policy = self._load_policy(config_path)

        # Cached views for convenience
        self._thr = self._policy["bands"]["s1"]["pressure_thresholds"]
        self._rules = self._policy["routing"]["rules"]

    # ---------- Public API ----------
    def route(
        self,
        s1: Dict[str, Any],
        user_scope: str = "general",
        hints: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Args:
          s1: e.g. {"pressure": 0.31, "risk_level": "low"} (from S1Detector)
          user_scope: caller's scope label (optional)
          hints: optional dict with:
            - budget: {"remaining_epsilon": float}
            - rate_limit: {"qpm_exceeded": bool}
            - required_scope: str
        """
        hints = hints or {}
        ctx = {
            "s1.pressure": float(s1.get("pressure", 0.0)),
            "s1.risk_level": str(s1.get("risk_level", "low")),
            "user.scope": user_scope,
            "budget.remaining_epsilon": float(
                (hints.get("budget") or {}).get("remaining_epsilon", 99.0)
            ),
            "rate_limit.queries_per_minute_exceeded": bool(
                (hints.get("rate_limit") or {}).get("qpm_exceeded", False)
            ),
            "query.required_scope": (hints.get("required_scope") or user_scope),
        }

        # Evaluate rules top-to-bottom, first match wins
        for rule in self._rules:
            if self._eval(rule["condition"], ctx):
                return PolicyDecision(
                    action=rule["action"],
                    reason=rule.get("reason", rule["name"]),
                    policy_rule=rule.get("name", "unnamed_rule"),
                    template_set=rule.get("template_set"),
                    retry_after=rule.get("retry_after"),
                )

        # Fallback: allow
        return PolicyDecision(
            action="allow",
            reason="default allow",
            policy_rule="default_allow",
        )

    # ---------- Internals ----------
    def _load_policy(self, path: Optional[str]) -> Dict[str, Any]:
        if path and os.path.exists(path):
            with open(path, "r") as f:
                return yaml.safe_load(f)

        # Safe defaults if no file present
        return {
            "bands": {
                "s1": {
                    "pressure_thresholds": {
                        "low": 0.20,
                        "medium": 0.35,
                        "high": 0.65,
                        "critical": 0.90,
                    }
                }
            },
            "routing": {
                "rules": [
                    {
                        "name": "Critical risk blocking",
                        "condition": "s1.pressure >= bands.s1.pressure_thresholds.critical",
                        "action": "block",
                        "reason": "Critical security risk detected",
                    },
                    {
                        "name": "High risk blocking",
                        "condition": "s1.pressure >= bands.s1.pressure_thresholds.high",
                        "action": "block",
                        "reason": "High security risk detected",
                    },
                    {
                        "name": "Budget exhaustion",
                        "condition": "budget.remaining_epsilon < 0.01",
                        "action": "block",
                        "reason": "Privacy budget exhausted",
                    },
                    {
                        "name": "Rate limiting",
                        "condition": "rate_limit.queries_per_minute_exceeded == True",
                        "action": "block",
                        "reason": "Rate limit exceeded",
                        "retry_after": 60,
                    },
                    {
                        "name": "Scope authorization",
                        "condition": "query.required_scope != user.scope",
                        "action": "block",
                        "reason": "Insufficient authorization scope",
                    },
                    {
                        "name": "Medium risk template enforcement",
                        "condition": "s1.pressure >= bands.s1.pressure_thresholds.medium",
                        "action": "template",
                        "reason": "Medium risk - restricted to template responses",
                        "template_set": ["general_info"],  # maps to your S2 set
                    },
                    {
                        "name": "Low risk template enforcement",
                        "condition": "s1.pressure >= bands.s1.pressure_thresholds.low",
                        "action": "template",
                        "reason": "Low risk - public information only",
                        "template_set": ["general_info"],
                    },
                    {
                        "name": "Default allow",
                        "condition": "default",
                        "action": "allow",
                        "reason": "Low risk",
                    },
                ]
            },
        }

    def _eval(self, condition: str, ctx: Dict[str, Any]) -> bool:
        if condition == "default":
            return True

        # make a tiny expression language: we support comparisons & equality
        # replace known tokens with their literal values
        # Example in YAML: "s1.pressure >= bands.s1.pressure_thresholds.medium"
        # We expand "bands.s1.pressure_thresholds.medium" from the loaded policy.
        expanded = condition

        # Expand policy constants (bands.*)
        def dig(root: Dict[str, Any], dotted: str) -> Any:
            node: Any = root
            for p in dotted.split("."):
                node = node[p]
            return node

        # First, expand any 'bands.' references
        while "bands." in expanded:
            start = expanded.index("bands.")
            end = self._find_token_end(expanded, start)
            token = expanded[start:end]
            value = dig(self._policy, token)
            expanded = expanded.replace(token, repr(value))

        # Now expand ctx variables
        for k, v in ctx.items():
            expanded = expanded.replace(k, repr(v))

        # only allow a safe subset of Python expressions
        allowed_names = {"True": True, "False": False}
        try:
            return bool(eval(expanded, {"__builtins__": {}}, allowed_names))
        except Exception:
            return False

    @staticmethod
    def _find_token_end(s: str, start: int) -> int:
        # token ends on whitespace or comparator characters
        i = start
        while i < len(s) and s[i] not in " <>!=()&|+-*/,\n\t":
            i += 1
        return i