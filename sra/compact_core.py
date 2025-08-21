from __future__ import annotations
import json, os, re, time, hashlib
from typing import Dict, Any, Optional

class SRACore:
    """
    Minimal, demo-only core with:
      - __init__(policy_path=None, audit_path="logs/demo_audit.jsonl")
      - process_request(prompt: str) -> dict
    Writes a hash-chained audit log to audit_path:
      {"timestamp","decision","reason","prev_hash","hash",...}
    """

    def __init__(self, policy_path: Optional[str] = None, audit_path: str = "logs/demo_audit.jsonl"):
        self.audit_path = audit_path
        os.makedirs(os.path.dirname(self.audit_path), exist_ok=True)

        # Simple demo rules (hard-coded to avoid yaml dependency mismatch)
        # Block if it looks like obvious prompt-injection
        self.block_patterns = [
            re.compile(r"ignore.{0,20}previous.{0,20}instructions", re.I),
            re.compile(r"reveal.{0,20}(prompt|secrets?|api keys?)", re.I),
        ]
        # Constrain output if “jailbreak/bypass” is mentioned
        self.template_patterns = [
            re.compile(r"jailbreak", re.I),
            re.compile(r"bypass.{0,10}(safety|rules?)", re.I),
        ]

    # ---------- audit helpers ----------
    def _last_hash(self) -> str:
        if not os.path.exists(self.audit_path):
            return "GENESIS"
        last = None
        with open(self.audit_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if not last:
            return "GENESIS"
        try:
            obj = json.loads(last)
            return obj.get("hash", "GENESIS")
        except Exception:
            return "GENESIS"

    def _line_hash(self, prev_hash: str, entry_no_hash: Dict[str, Any]) -> str:
        payload = json.dumps({"prev": prev_hash, **entry_no_hash}, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _audit(self, decision: str, reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
        extra = extra or {}
        prev = self._last_hash()
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "decision": decision,
            "reason": reason,
            **extra,
            "prev_hash": prev,
        }
        h = self._line_hash(prev, {k: v for k, v in entry.items() if k != "hash"})
        entry["hash"] = h
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    # ---------- main API ----------
    def process_request(self, prompt: str) -> Dict[str, Any]:
        """
        Returns:
          {"status": "allowed"|"blocked", "response": {...}, "mode": "...", "latency_ms": float}
        """
        t0 = time.perf_counter()

        # Block?
        for pat in self.block_patterns:
            if pat.search(prompt):
                self._audit("BLOCKED", "SRA-INJECTION_DETECTED-001", {"prompt": prompt[:160]})
                return {
                    "status": "blocked",
                    "response": {
                        "message": "Request blocked: embedded instructions violate isolation policy.",
                        "policy_reference": "SRA-INJECTION_DETECTED-001",
                    },
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                }

        # Template-only?
        for pat in self.template_patterns:
            if pat.search(prompt):
                msg = ("Here's what I can tell you safely: "
                       "Your request triggers template-only mode. "
                       "Providing high-level info.")
                self._audit("ALLOWED", "template_only", {"prompt": prompt[:160]})
                return {
                    "status": "allowed",
                    "mode": "template_only",
                    "response": {"message": msg},
                    "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                }

        # Normal allow
        msg = f"Based on public sources: Summary for: '{prompt}' (scope=general)"
        self._audit("ALLOWED", "normal", {"prompt": prompt[:160]})
        return {
            "status": "allowed",
            "response": {"message": msg},
            "epsilon_cost": 0.1,
            "budget_remaining": 0.9,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        }