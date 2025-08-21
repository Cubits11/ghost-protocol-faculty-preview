# -*- coding: utf-8 -*-
"""
S1Detector — Stage 1 (S1) risk classifier for SRA.

Features
--------
- Config-driven attack pattern DB (YAML) w/ category weights and severity.
- Dual engine: compiled regex AND multi-pattern Aho-Corasick for O(n) scans.
- Pressure scoring in [0.0, 1.0] with thresholds => {low, medium, high, critical}.
- Context heuristics for multi-turn exploitation and anomaly nudges.
- Pluggable semantic intent shim (no heavy deps; swap in real model later).
- Rich trace output: matches, features, categories, confidence components.

Output schema
-------------
{
  "risk_level": "low|medium|high|critical",
  "pressure": float,            # 0.0–1.0
  "confidence": float,          # alias for pressure (monotone)
  "reasons": [str],             # human-readable reasons
  "features": {
      "pattern_matches": [
          {
            "category": str,
            "pattern_id": str,
            "severity": "low|medium|high",
            "span": [start, end],
            "snippet": str,
            "weight": float,
            "engine": "regex|ac"
          }, ...
      ],
      "semantic_intents": ["attack_attempt", ...],
      "context_flags": ["multi_turn_setup", ...]
  }
}
"""

from __future__ import annotations

import os
import re
import json
import math
import argparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # optional
except Exception:
    yaml = None

# ---------------- Aho-Corasick (minimal local) ------------------------------

class _ACNode:
    __slots__ = ("next", "fail", "out")
    def __init__(self):
        self.next: Dict[str, _ACNode] = {}
        self.fail: Optional[_ACNode] = None
        self.out: List[Tuple[str, str]] = []  # [(category, pattern_id)]

class _AhoCorasick:
    def __init__(self):
        self.root = _ACNode()

    def add(self, pat: str, tag: Tuple[str, str]) -> None:
        node = self.root
        for ch in pat:
            node = node.next.setdefault(ch, _ACNode())
        node.out.append(tag)

    def build(self) -> None:
        from collections import deque
        q = deque()
        for node in self.root.next.values():
            node.fail = self.root
            q.append(node)
        while q:
            r = q.popleft()
            for ch, nxt in r.next.items():
                q.append(nxt)
                f = r.fail
                while f and ch not in f.next:
                    f = f.fail
                nxt.fail = f.next[ch] if f and ch in f.next else self.root
                nxt.out += nxt.fail.out if nxt.fail else []

    def finditer(self, text: str):
        node = self.root
        for i, ch in enumerate(text):
            while node and ch not in node.next:
                node = node.fail
            if not node:
                node = self.root
                continue
            node = node.next[ch]
            for (category, pattern_id) in node.out:
                yield (i, category, pattern_id)

# ---------------- Data structures ------------------------------------------

@dataclass
class Pattern:
    regex: Optional[re.Pattern]
    literal: Optional[str]
    category: str
    pattern_id: str
    severity: str
    weight: float

@dataclass
class S1Config:
    thresholds: Dict[str, float]    # {"low":0.2,"medium":0.4,"high":0.7,"critical":0.9}
    patterns: List[Pattern]
    use_ac: bool = True
    ac_min_len: int = 4

# ---------------- Built-in defaults ----------------------------------------

_DEFAULT_THRESHOLDS = {"low": 0.20, "medium": 0.40, "high": 0.70, "critical": 0.90}

_BUILTIN_PATTERNS: List[Tuple[str, str, str, float]] = [
    ("instruction_injection", r"ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|prompts?|commands?)", "high", 0.95),
    ("credential_extraction", r"(reveal|show|display|tell)\s+.{0,20}(secret|password|key|token|credential)s?", "high", 0.90),
    ("system_probing",        r"(what|how)\s+.{0,20}(are\s+you|were\s+you)\s+.{0,20}(trained|programmed|built)",   "medium", 0.85),
    ("jailbreak_attempts",    r"(bypass|circumvent|get\s+around|work\s+around)\s+.{0,20}(security|safety|restriction|filter|rule)", "high", 0.92),
    ("html_xml_injection",    r"<!--.*?(ignore|system|admin|override|inject).*?-->", "medium", 0.80),
    ("data_exfiltration",     r"(list|show|enumerate|dump)\s+.{0,20}(all\s+)?(users?|files?|documents?|data)", "high", 0.85),
]

# ---------------- YAML loader ----------------------------------------------

def _safe_yaml_load(path: str) -> Optional[Dict[str, Any]]:
    """Load YAML into a dict; tolerate empty files and non-dicts."""
    if not yaml or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        y = yaml.safe_load(f)
    if not isinstance(y, dict):
        return {}
    return y

def _load_yaml_patterns(path: str) -> Optional[S1Config]:
    y = _safe_yaml_load(path)
    if y is None:
        return None

    thresholds_block = (((y.get("bands") or {}).get("s1") or {}).get("pressure_thresholds") or {})
    thresholds = {
        "low":      float(thresholds_block.get("low",      _DEFAULT_THRESHOLDS["low"])),
        "medium":   float(thresholds_block.get("medium",   _DEFAULT_THRESHOLDS["medium"])),
        "high":     float(thresholds_block.get("high",     _DEFAULT_THRESHOLDS["high"])),
        "critical": float(thresholds_block.get("critical", _DEFAULT_THRESHOLDS["critical"])),
    }

    # Pattern sources:
    # 1) y["patterns"] -> {category: [regex_or_literal, ...]}
    # 2) y["bands"]["s1"]["detectors"] -> [{"type":"regex_set","patterns":{...}}, ...]
    patterns_root = y.get("patterns")
    if patterns_root is None:
        patterns_root = ((y.get("bands") or {}).get("s1") or {}).get("detectors", [])

    weights = ((y.get("pattern_metadata") or {}).get("confidence_weights") or {})
    sev_map = ((y.get("pattern_metadata") or {}).get("severity_levels") or {})

    pat_cfg: List[Tuple[str, str, str, float, str]] = []

    def add_group(cat: str, items: List[str]):
        severity = sev_map.get(cat, "medium")
        weight = float(weights.get(cat, 0.75))
        for idx, pat in enumerate(items):
            pat_cfg.append((cat, str(pat), severity, weight, f"{cat}__{idx}"))

    if isinstance(patterns_root, dict):
        for cat, items in patterns_root.items():
            if isinstance(items, list):
                add_group(cat, items)
    elif isinstance(patterns_root, list):
        for det in patterns_root:
            if isinstance(det, dict) and det.get("type") == "regex_set":
                groups = det.get("patterns", {})
                if isinstance(groups, dict):
                    for cat, items in groups.items():
                        if isinstance(items, list):
                            add_group(cat, items)

    compiled: List[Pattern] = []
    for (cat, pat, severity, weight, pid) in pat_cfg:
        literal = None
        regex = None
        looks_literal = not re.search(r"[.^$*+?{}\[\]|()\\]", pat)
        try:
            regex = re.compile(pat, re.IGNORECASE | re.DOTALL)
        except re.error:
            looks_literal = True
            regex = None
        if looks_literal and len(pat) >= 4:
            literal = pat
        compiled.append(Pattern(regex=regex, literal=literal, category=cat,
                                pattern_id=pid, severity=severity, weight=float(weight)))

    return S1Config(thresholds=thresholds, patterns=compiled, use_ac=True)

def _builtin_config() -> S1Config:
    compiled: List[Pattern] = []
    for idx, (cat, pat, sev, wt) in enumerate(_BUILTIN_PATTERNS):
        compiled.append(Pattern(
            regex=re.compile(pat, re.IGNORECASE | re.DOTALL),
            literal=None,
            category=cat,
            pattern_id=f"{cat}__{idx}",
            severity=sev,
            weight=wt,
        ))
    return S1Config(thresholds=_DEFAULT_THRESHOLDS, patterns=compiled, use_ac=True)

# ---------------- Semantic intent shim -------------------------------------

def _semantic_intents(text: str) -> List[str]:
    intents = []
    t = text.lower()
    if any(k in t for k in [
        "ignore previous", "ignore instructions", "jailbreak",
        "bypass security", "bypass guard"
    ]):
        intents.append("attack_attempt")
    if any(k in t for k in [
        "how were you trained", "show your training",
        "system prompt", "reveal system prompt", "reveal the system prompt"
    ]):
        intents.append("system_probe")
    return intents

# ---------------- Context heuristics ---------------------------------------

def _context_flags(history: Optional[List[str]]) -> List[str]:
    flags: List[str] = []
    if not history:
        return flags
    last = " ".join(history[-5:]).lower()
    if re.search(r"\bremember\b.{0,20}\b(for later|next time)\b", last):
        flags.append("multi_turn_setup")
    if re.search(r"\b(code\s*word|trigger|signal|phrase)\b", last):
        flags.append("latent_trigger_setup")
    if re.search(r"\bstart over\b|\breset\b", last):
        flags.append("context_reset_probe")
    return flags

# ---------------- S1 Detector ----------------------------------------------

class S1Detector:
    """
    Stage 1 (S1) risk classifier.
    Returns structured dict with risk level, pressure (confidence), reasons, and features.

    Pressure aggregation:
        base = 1 - exp(-k * sum(weights(matches)))      [logistic squash; k≈0.9]
        + 0.20 if suspicious semantic intents present
        + 0.10 if context flags indicate multi-turn setup / latent triggers
        Clamp to [0.0, 1.0], then map to categorical via thresholds.
    """

    def __init__(self, config_path: Optional[str] = None):
        # Try enterprise YAML; fall back to built-ins.
        cfg = None
        for candidate in filter(None, [
            config_path,
            os.environ.get("SRA_ATTACK_CONFIG"),
            "config/attack_patterns.yaml"
        ]):
            cfg = _load_yaml_patterns(candidate)
            if cfg is not None:
                break
        if cfg is None:
            cfg = _builtin_config()

        self.cfg = cfg

        # Build AC over literal-ish patterns
        self.ac = None
        if self.cfg.use_ac:
            ac = _AhoCorasick()
            lit_count = 0
            for p in self.cfg.patterns:
                if p.literal and len(p.literal) >= self.cfg.ac_min_len:
                    ac.add(p.literal.lower(), (p.category, p.pattern_id))
                    lit_count += 1
            if lit_count:
                ac.build()
                self.ac = ac

        self._by_id = {p.pattern_id: p for p in self.cfg.patterns}

    # ---- Public API --------------------------------------------------------

    def classify(self, text: str, context_history: Optional[List[str]] = None) -> Dict[str, Any]:
        text_lc = text.lower()

        # 1) Pattern matches
        matches = self._find_matches(text, text_lc)

        # 2) Semantic intents
        intents = _semantic_intents(text)

        # 3) Context analysis
        flags = _context_flags(context_history)

        # 4) Pressure aggregation
        pressure, reasons = self._aggregate_pressure(matches, intents, flags)

        # 5) Risk bucket
        level = self._to_level(pressure)

        return {
            "risk_level": level,
            "pressure": pressure,
            "confidence": pressure,
            "reasons": reasons,
            "features": {
                "pattern_matches": matches,
                "semantic_intents": intents,
                "context_flags": flags,
            },
        }

    # ---- Internals ---------------------------------------------------------

    def _find_matches(self, text: str, text_lc: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        # AC pass (fast substrings)
        if self.ac:
            for i, cat, pid in self.ac.finditer(text_lc):
                p = self._by_id.get(pid)
                if not p:
                    continue
                L = len(p.literal or "")
                start = max(0, i - L + 1)
                end = i + 1
                out.append({
                    "category": cat,
                    "pattern_id": pid,
                    "severity": p.severity,
                    "span": [start, end],
                    "snippet": text[max(0, start):min(len(text), end)],
                    "weight": p.weight,
                    "engine": "ac",
                })

        # Regex pass (precise)
        for p in self.cfg.patterns:
            if not p.regex:
                continue
            for m in p.regex.finditer(text):
                start, end = m.span()
                snippet = text[max(0, start):min(len(text), end)]
                out.append({
                    "category": p.category,
                    "pattern_id": p.pattern_id,
                    "severity": p.severity,
                    "span": [start, end],
                    "snippet": snippet,
                    "weight": p.weight,
                    "engine": "regex",
                })

        # Deduplicate (prefer regex over AC)
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for rec in sorted(out, key=lambda r: (r["engine"] != "regex", -r["weight"])):
            key = (rec["pattern_id"], tuple(rec["span"]))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(rec)
        return deduped

    def _aggregate_pressure(
        self,
        matches: List[Dict[str, Any]],
        intents: List[str],
        flags: List[str],
    ) -> Tuple[float, List[str]]:
        s = 0.0
        reasons: List[str] = []
        for m in matches:
            s += float(m.get("weight", 0.0))
        if s > 0:
            reasons.append(f"{len(matches)} pattern match(es) detected")

        # Logistic squash to [0,1]; prevents weight explosions
        k = 0.9
        base = 1.0 - math.exp(-k * s)
        pressure = base

        if any(t in intents for t in ("attack_attempt", "system_probe")):
            pressure += 0.20
            reasons.append("suspicious semantic intent")

        if any(f in flags for f in ("multi_turn_setup", "latent_trigger_setup", "context_reset_probe")):
            pressure += 0.10
            reasons.append("context anomaly")

        pressure = max(0.0, min(1.0, pressure))
        return pressure, (reasons or ["no risky pattern matched"])

    def _to_level(self, pressure: float) -> str:
        th = self.cfg.thresholds
        if pressure >= th.get("critical", 0.90):
            return "critical"
        if pressure >= th.get("high", 0.70):
            return "high"
        if pressure >= th.get("medium", 0.40):
            return "medium"
        return "low"

# ---------------- CLI -------------------------------------------------------

def _cli() -> None:
    p = argparse.ArgumentParser(description="S1Detector CLI")
    p.add_argument("text", help="User input to classify")
    p.add_argument("-c", "--config", help="Path to attack_patterns.yaml (optional)")
    p.add_argument("-H", "--history", nargs="*", help="Recent conversation turns (optional)")
    args = p.parse_args()

    det = S1Detector(config_path=args.config)
    res = det.classify(args.text, context_history=args.history or [])
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    _cli()