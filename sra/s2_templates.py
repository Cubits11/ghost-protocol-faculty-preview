# sra/s2_templates.py
# -*- coding: utf-8 -*-
"""
S2Templates — Stage 2 (S2) safe-response engine for SRA.

Goals (demo-ready, procurement-friendly)
---------------------------------------
- Deterministic, template-based responses for medium/high risk.
- Optional YAML config for template text and forbidden patterns.
- Slot sanitization and leak checks before returning text.
- Zero heavy deps; `yaml` is optional (falls back to built-ins).
- Simple API expected by SRACore:
    - generate_safe_response(category="general", risk_level="medium") -> {"message": str}
    - generate_full_response(user_input, classification, scope) -> {"message": str}

YAML shape (optional)
---------------------
response_templates.yaml:

templates:
  general: "Here's what I can tell you safely: {content}"
  academic: "Based on public sources: {content}"
  refusal: "Request blocked by policy: {reason}"

forbidden_patterns:
  - "(?i)api[_-]?key\\s*[:=]\\s*[A-Za-z0-9_\\-]{12,}"
  - "(?i)secret\\s*[:=]"
  - "(?i)/etc/passwd"

slot_filters:
  redact_tokens:
    - "(?i)api[_-]?key\\s*[:=]\\s*[A-Za-z0-9_\\-]{6,}"
    - "(?i)secret\\s*[:=]\\s*\\S+"

"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, List

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # YAML is optional


# ---- Built-in defaults (used if no YAML is provided) -----------------------

_DEFAULT_TEMPLATES: Dict[str, str] = {
    "general": "Here's what I can tell you safely: {content}",
    "academic": "Based on public sources: {content}",
    "refusal": "Request blocked by policy: {reason}",
}

# conservative defaults that should never appear in safe outputs
_DEFAULT_FORBIDDEN: List[str] = [
    r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
    r"(?i)secret\s*[:=]",
    r"(?i)/etc/passwd",
]

# slot-level redaction helpers (applied before formatting)
_DEFAULT_SLOT_FILTERS: Dict[str, List[str]] = {
    "redact_tokens": [
        r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{6,}",
        r"(?i)secret\s*[:=]\s*\S+",
    ]
}


# ---- Utility helpers -------------------------------------------------------

def _compile_many(patterns: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.IGNORECASE | re.DOTALL))
        except re.error:
            # Skip invalid regex to keep engine robust in demos
            continue
    return out


def _redact(text: str, regexes: List[re.Pattern], tag: str = "[REDACTED]") -> str:
    redacted = text
    for r in regexes:
        redacted = r.sub(tag, redacted)
    return redacted


# ---- S2 Engine -------------------------------------------------------------

class S2Templates:
    """
    Template-safe response generator.

    Medium/High risk => use constrained templates (no arbitrary egress).
    Low risk => you *may* still choose templates for consistency or produce
                a fuller response (this demo keeps a simple full responder).

    API:
        - generate_safe_response(category="general", risk_level="medium")
        - generate_full_response(user_input, classification, scope)
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        # Load config if available; otherwise fall back to defaults.
        self.templates: Dict[str, str] = dict(_DEFAULT_TEMPLATES)
        self._forbidden_rx: List[re.Pattern] = _compile_many(_DEFAULT_FORBIDDEN)
        self._slot_filters: Dict[str, List[re.Pattern]] = {
            name: _compile_many(pats) for name, pats in _DEFAULT_SLOT_FILTERS.items()
        }

        if config_path and yaml:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                # Templates
                tcfg = cfg.get("templates") or {}
                if isinstance(tcfg, dict):
                    # keep only string values
                    for k, v in tcfg.items():
                        if isinstance(v, str):
                            self.templates[k] = v

                # Forbidden patterns
                fcfg = cfg.get("forbidden_patterns") or []
                if isinstance(fcfg, list):
                    self._forbidden_rx = _compile_many([p for p in fcfg if isinstance(p, str)])

                # Slot filters
                scfg = cfg.get("slot_filters") or {}
                if isinstance(scfg, dict):
                    compiled: Dict[str, List[re.Pattern]] = {}
                    for name, pats in scfg.items():
                        if isinstance(pats, list):
                            compiled[name] = _compile_many([p for p in pats if isinstance(p, str)])
                    if compiled:
                        self._slot_filters = compiled
            except Exception:
                # Fail-closed to built-ins if file unreadable
                pass

        # Pre-compile quick existence checks for performance
        self._tmpl_general = self.templates.get("general", _DEFAULT_TEMPLATES["general"])
        self._tmpl_academic = self.templates.get("academic", _DEFAULT_TEMPLATES["academic"])
        self._tmpl_refusal = self.templates.get("refusal", _DEFAULT_TEMPLATES["refusal"])

    # ---- Public API --------------------------------------------------------

    def generate_safe_response(
        self,
        category: str = "general",
        risk_level: str = "medium",
        vars: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Produce a safe, templated response for medium/high risk categories.
        Slots are sanitized and forbidden patterns are rejected (fail-closed).
        """
        # Compose safe content message based on risk level
        if risk_level in ("high", "critical"):
            content = "Your request triggers high‑risk policy. Providing only minimal, general guidance."
        else:
            content = "Your request triggers template‑only mode. Providing high‑level information."

        # Allow optional augmentation via vars (all sanitized!)
        extra = ""
        if vars:
            # pull a short, already-sanitized explanation if present
            candidate = str(vars.get("explanation", "")).strip()
            if candidate:
                extra = " " + self._sanitize_slot(candidate)

        filled = self._format_template(category, content + extra)

        # Final barrier: verify no forbidden pattern leaked
        if not self._verify_no_leakage(filled):
            # If a template somehow violates policy, fail-closed with refusal.
            filled = self._tmpl_refusal.format(reason="Template safety verification failed")

        return {"message": filled}

    def generate_full_response(
        self,
        user_input: str,
        classification: Dict[str, Any],
        scope: str,
    ) -> Dict[str, Any]:
        """
        More permissive path (used for 'low' risk in the Wednesday demo).
        Still passes content through the same sanitization + verification.
        """
        summary = f"Summary for: '{user_input[:80]}' (scope={scope})"
        safe_summary = self._sanitize_slot(summary)
        filled = self._tmpl_academic.format(content=safe_summary)

        # Even for low-risk, run a quick no-leak check (defense-in-depth)
        if not self._verify_no_leakage(filled):
            filled = self._tmpl_refusal.format(reason="Policy violation detected in full response")

        return {"message": filled}

    # ---- Internals ---------------------------------------------------------

    def _sanitize_slot(self, text: str) -> str:
        """
        Sanitize arbitrary slot text before insertion into templates.
        1) Hard redact tokens via configured slot filters.
        2) Collapse suspicious whitespace/control chars.
        """
        out = text
        # Apply redaction filters
        for _, regexes in self._slot_filters.items():
            out = _redact(out, regexes)
        # Collapse control chars and aggressive whitespace
        out = re.sub(r"[\x00-\x1F]+", " ", out)
        out = re.sub(r"\s{2,}", " ", out).strip()
        return out

    def _format_template(self, category: str, content: str) -> str:
        """
        Format a chosen template safely.
        Unknown categories fall back to 'general'.
        """
        tmpl = self.templates.get(category, self._tmpl_general)
        # Only ever substitute the {content} slot
        safe_content = self._sanitize_slot(content)
        try:
            return tmpl.format(content=safe_content)
        except Exception:
            # Fail-closed if a template is malformed
            return self._tmpl_refusal.format(reason="Template formatting error")

    def _verify_no_leakage(self, text: str) -> bool:
        """
        Final check that output contains no forbidden patterns.
        """
        for rx in self._forbidden_rx:
            if rx.search(text):
                return False
        return True


# ---- Tiny CLI for local checks --------------------------------------------

if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser(description="S2Templates CLI (sanity checks)")
    p.add_argument("-c", "--config", help="Path to response_templates.yaml", default=None)
    p.add_argument("--mode", choices=["safe", "full"], default="safe")
    p.add_argument("--category", default="general")
    p.add_argument("--scope", default="general")
    p.add_argument("text", help="User input / content")
    args = p.parse_args()

    s2 = S2Templates(config_path=args.config)

    if args.mode == "safe":
        res = s2.generate_safe_response(category=args.category, risk_level="medium", vars={"explanation": args.text})
    else:
        res = s2.generate_full_response(args.text, classification={"risk_level":"low"}, scope=args.scope)

    print(json.dumps(res, indent=2, ensure_ascii=False))