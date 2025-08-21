# sra/core.py
"""
SRA Core Processing Engine — Faculty demo build

Pipeline (demo):
  S1 (classify) → Router (risk / PII) → S2 / CopperGround → S3 (budgets & rate) → S4 (audit)

Notes
-----
- No external PolicyEngine; we approximate the router with simple, readable rules that
  mirror your policy.yaml (medium→template, high/critical→block, PII→notice template).
- Relies on the *upgraded* BudgetTracker providing QPM gating & ε snapshots:
    can_issue_request(), notify_request_issued(), spend(), get_remaining(), snapshot()
- Produces audit entries compatible with the upgraded AuditLogger (entry_hash + prev_hash).
"""

from __future__ import annotations

import time
from typing import Dict, Any, Optional, List, Tuple

from .s1_detector import S1Detector
from .s2_templates import S2Templates
from .copper_ground import CopperGround
from .audit_logger import AuditLogger
from .budget_tracker import BudgetTracker


class SRACore:
    """Main SRA processing engine integrating S1/S2 + budgets + audit."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        *,
        # S3 defaults (fine for the demo; tweak from app.py if desired)
        initial_epsilon: float = 1.0,
        qpm_limit: int = 3,
        window_seconds: int = 10,
    ) -> None:
        # Core components (defensive to constructor drift)
        self.detector = self._init_detector(config_path)
        self.templates = self._init_templates(config_path)
        self.copper_ground = CopperGround()
        self.audit = self._init_audit(config_path)

        # Budgets / rate (S3)
        # Requires the upgraded BudgetTracker with QPM window support.
        self.budget = BudgetTracker(
            initial_epsilon=initial_epsilon,
            qpm_limit=qpm_limit,
            window_seconds=window_seconds,
        )

        # Telemetry
        self.requests_processed = 0
        self.attacks_blocked = 0

    # ------------------------------ Public API ------------------------------ #

    def process_request(
        self,
        user_input: str,
        user_scope: str = "public",
        context_history: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Returns:
          {
            status: "allowed" | "template" | "blocked" | "error",
            action: same as status (UPPER for quick UI metric),
            response: object (message / refusal bundle),
            latency_ms: float,
            classification: {...},      # S1 details
            s1_pressure_score: float,   # convenience
            epsilon_cost: float,        # for allowed/template
            budget_remaining: float,
            retry_after: Optional[int]  # for rate‑limited
          }
        """
        t0 = time.time()
        self.requests_processed += 1

        # --- S3 pre‑gates: rate limit & hard ε exhaustion (cheap checks) ---
        ok, retry_after = self._rate_gate()
        if not ok:
            return self._handle_rate_limited(user_input, user_scope, t0, retry_after)

        if self.budget.get_remaining() <= 0.0:
            return self._handle_budget_exhausted(user_input, user_scope, t0)

        # --- S1: classify (pattern / light semantics) ---
        try:
            try:
                classification = self.detector.classify(user_input, context_history or [])
            except TypeError:
                classification = self.detector.classify(user_input)
        except Exception as e:
            # Defensive: S1 failure becomes safe refusal
            return self._handle_system_error(user_input, user_scope, t0, str(e))

        # Router (demo): high/critical → block; medium → template; PII leak → notice/template
        risk = str(classification.get("risk_level", "low")).lower()
        pressure = self._extract_pressure(classification)

        # PII notice path (mirrors policy rule: pii_leak ≥ 1 and pressure ≥ ~0.35)
        pii_count = self._count_pattern_matches(classification, "pii_leak")
        if pii_count >= 1 and (pressure if isinstance(pressure, (int, float)) else 0.0) >= 0.35:
            result = self._handle_template(
                user_input, user_scope, classification, t0, template_category="pii_notice"
            )
            self._notify_request_issued()  # QPM window tick
            return result

        if risk in {"high", "critical"}:
            result = self._handle_block(user_input, classification, t0)
            self._notify_request_issued()
            return result

        if risk == "medium":
            result = self._handle_template(user_input, user_scope, classification, t0)
            self._notify_request_issued()
            return result

        # Low risk: allow
        result = self._handle_allow(user_input, user_scope, classification, t0)
        self._notify_request_issued()
        return result

    def get_stats(self) -> Dict[str, Any]:
        snap = self.budget.snapshot()
        return {
            "requests_processed": self.requests_processed,
            "attacks_blocked": self.attacks_blocked,
            "block_rate": self.attacks_blocked / max(self.requests_processed, 1),
            "budget_remaining": snap.get("epsilon_remaining", self.budget.get_remaining()),
            "audit_entries": self.audit.get_entry_count(),
            "qpm_limit": snap.get("qpm_limit"),
            "qpm_window_seconds": snap.get("window_seconds"),
            "qpm_requests_in_window": snap.get("request_count_current_window"),
        }

    # ------------------------------ Handlers -------------------------------- #

    def _handle_block(self, user_input: str, classification: Dict[str, Any], t0: float) -> Dict[str, Any]:
        refusal = self.copper_ground.generate_refusal(
            "injection_detected",
            {
                "matched": classification.get(
                    "reason",
                    (classification.get("reasons", ["pattern match"]) or ["pattern match"])[0],
                ),
                "risk_level": classification.get("risk_level", "high"),
                "violation_type": "injection_detected",
                "text": user_input,
            },
        )
        latency = self._lat_ms(t0)
        self.attacks_blocked += 1

        self.audit.log_decision(
            decision="BLOCKED",
            reason="High risk - policy block",
            extra={
                "input": user_input,
                "risk_level": classification.get("risk_level", "high"),
                "s1_pressure_score": self._extract_pressure(classification),
                "latency_ms": latency,
                "classification": classification,
                "budget_snapshot": self.budget.snapshot(),
            },
        )
        return {
            "status": "blocked",
            "action": "BLOCKED",
            "response": refusal,
            "latency_ms": latency,
            "classification": classification,
            "s1_pressure_score": self._extract_pressure(classification),
        }

    def _handle_template(
        self,
        user_input: str,
        user_scope: str,
        classification: Dict[str, Any],
        t0: float,
        *,
        template_category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Medium-risk (or PII-notice) path: produce a constrained, template-based response.
        """
        # Choose template category (fallback to "general")
        category = template_category or classification.get("topic", "general")

        # S2Templates safe response API expects `vars` (optional) with sanitized hints
        templated = self.templates.generate_safe_response(
            category=category,
            risk_level="medium",
            vars={"explanation": self._safe_prompt_echo(user_input)},
        )
        # generate_safe_response returns {"message": "..."}
        response = {"message": templated.get("message", ""), "template_category": category}

        # Accounting
        latency = self._lat_ms(t0)
        epsilon_cost = self._calculate_privacy_cost(user_input, classification)

        # Prevent overspend of ε
        if epsilon_cost > max(0.0, self.budget.get_remaining()):
            return self._handle_budget_exhausted(user_input, user_scope, t0, attempted_cost=epsilon_cost)

        # Spend ε and write audit
        self.budget.spend(epsilon_cost)
        self.audit.log_decision(
            decision="TEMPLATE",
            reason="Medium risk - template mode",
            extra={
                "input": user_input,
                "risk_level": classification.get("risk_level", "medium"),
                "s1_pressure_score": self._extract_pressure(classification),
                "latency_ms": latency,
                "template_used": category,
                "classification": classification,
                "epsilon_cost": epsilon_cost,
                "budget_snapshot": self.budget.snapshot(),
            },
        )

        return {
            "status": "template",
            "action": "TEMPLATE",
            "response": response,
            "latency_ms": latency,
            "epsilon_cost": epsilon_cost,
            "budget_remaining": self.budget.get_remaining(),
            "classification": classification,
            "s1_pressure_score": self._extract_pressure(classification),
        }

    def _handle_allow(
        self, user_input: str, user_scope: str, classification: Dict[str, Any], t0: float
    ) -> Dict[str, Any]:
        content = self._draft_safe_summary(user_input, user_scope)
        response = {"message": f"Based on public sources: {content}"}

        latency = self._lat_ms(t0)
        epsilon_cost = self._calculate_privacy_cost(user_input, classification)

        if epsilon_cost > max(0.0, self.budget.get_remaining()):
            return self._handle_budget_exhausted(user_input, user_scope, t0, attempted_cost=epsilon_cost)

        self.budget.spend(epsilon_cost)

        self.audit.log_decision(
            decision="ALLOWED",
            reason="Low risk - allowed",
            extra={
                "input": user_input,
                "risk_level": classification.get("risk_level", "low"),
                "s1_pressure_score": self._extract_pressure(classification),
                "latency_ms": latency,
                "classification": classification,
                "epsilon_cost": epsilon_cost,
                "budget_snapshot": self.budget.snapshot(),
            },
        )
        return {
            "status": "allowed",
            "action": "ALLOWED",
            "response": response,
            "latency_ms": latency,
            "epsilon_cost": epsilon_cost,
            "budget_remaining": self.budget.get_remaining(),
            "classification": classification,
            "s1_pressure_score": self._extract_pressure(classification),
        }

    def _handle_rate_limited(
        self, user_input: str, user_scope: str, t0: float, retry_after: Optional[int]
    ) -> Dict[str, Any]:
        latency = self._lat_ms(t0)
        refusal = self.copper_ground.generate_refusal(
            "rate_limited",
            {
                "text": user_input,
                "scope": user_scope,
                "retry_after": retry_after,
                "rate_limit_reset_epoch": time.time() + (retry_after or 0),
                "violation_type": "rate_limited",
            },
        )
        self.attacks_blocked += 1
        self.audit.log_decision(
            decision="BLOCKED",
            reason="Rate limit exceeded",
            extra={
                "input": user_input,
                "risk_level": "low",
                "s1_pressure_score": 0.0,
                "latency_ms": latency,
                "retry_after": retry_after,
                "budget_snapshot": self.budget.snapshot(),
            },
        )
        # Do NOT count ε spend on a rate‑limited block.
        self._notify_request_issued()  # still consumes a QPM slot
        return {
            "status": "blocked",
            "action": "BLOCKED",
            "response": refusal,
            "latency_ms": latency,
            "retry_after": retry_after,
            "classification": {"risk_level": "low", "pressure": 0.0, "reasons": ["rate_limited"]},
            "s1_pressure_score": 0.0,
        }

    def _handle_budget_exhausted(
        self,
        user_input: str,
        user_scope: str,
        t0: float,
        *,
        attempted_cost: Optional[float] = None,
    ) -> Dict[str, Any]:
        latency = self._lat_ms(t0)
        refusal = self.copper_ground.generate_refusal(
            "budget_exceeded",
            {
                "text": user_input,
                "scope": user_scope,
                "violation_type": "budget_exceeded",
                "budget_reset_epoch": None,  # could be wired if you implement periodic refill
                "attempted_cost": attempted_cost,
            },
        )
        self.attacks_blocked += 1
        self.audit.log_decision(
            decision="BLOCKED",
            reason="Privacy budget exhausted",
            extra={
                "input": user_input,
                "risk_level": "low",
                "s1_pressure_score": 0.0,
                "latency_ms": latency,
                "attempted_cost": attempted_cost,
                "budget_snapshot": self.budget.snapshot(),
            },
        )
        return {
            "status": "blocked",
            "action": "BLOCKED",
            "response": refusal,
            "latency_ms": latency,
            "classification": {"risk_level": "low", "pressure": 0.0, "reasons": ["budget_exceeded"]},
            "s1_pressure_score": 0.0,
        }

    def _handle_system_error(self, user_input: str, user_scope: str, t0: float, err: str) -> Dict[str, Any]:
        latency = self._lat_ms(t0)
        refusal = self.copper_ground.generate_refusal("system_error", {"error": err, "text": user_input})
        self.attacks_blocked += 1
        self.audit.log_decision(
            decision="ERROR",
            reason=f"System error: {err}",
            extra={
                "input": user_input,
                "latency_ms": latency,
                "scope": user_scope,
                "budget_snapshot": self.budget.snapshot(),
            },
        )
        return {"status": "error", "action": "ERROR", "response": refusal, "latency_ms": latency}

    # ------------------------------ Helpers --------------------------------- #

    @staticmethod
    def _safe_prompt_echo(user_input: str, max_len: int = 160) -> str:
        s = (user_input or "").strip().replace("\n", " ")
        return f"request about: {s[: max_len - 1] + '…' if len(s) > max_len else s}"

    @staticmethod
    def _draft_safe_summary(user_input: str, user_scope: str, max_len: int = 80) -> str:
        topic = (user_input or "").strip().split("\n", 1)[0]
        if len(topic) > max_len:
            topic = topic[: max_len - 1] + "…"
        return f"summary for '{topic}' (scope={user_scope})"

    @staticmethod
    def _extract_pressure(classification: Dict[str, Any]) -> float:
        # Prefer 'pressure'; fall back to 'pressure_score' or 'confidence'
        for k in ("pressure", "pressure_score", "confidence"):
            v = classification.get(k)
            try:
                return round(float(v), 3)
            except Exception:
                continue
        return 0.0

    @staticmethod
    def _count_pattern_matches(classification: Dict[str, Any], category: str) -> int:
        try:
            matches = classification.get("features", {}).get("pattern_matches", []) or []
            return sum(1 for m in matches if str(m.get("category", "")).lower() == category.lower())
        except Exception:
            return 0

    @staticmethod
    def _lat_ms(t0: float) -> float:
        return round((time.time() - t0) * 1000.0, 1)

    # Component initializers (defensive to ctor signatures)
    @staticmethod
    def _init_detector(config_path: Optional[str]) -> S1Detector:
        try:
            return S1Detector(config_path) if config_path else S1Detector()
        except TypeError:
            return S1Detector()

    @staticmethod
    def _init_templates(config_path: Optional[str]) -> S2Templates:
        try:
            return S2Templates(config_path) if config_path else S2Templates(None)
        except TypeError:
            return S2Templates()

    @staticmethod
    def _init_audit(config_path: Optional[str]) -> AuditLogger:
        try:
            return AuditLogger(config_path) if config_path else AuditLogger()
        except TypeError:
            return AuditLogger()

    # --- S3 glue ---

    def _rate_gate(self) -> Tuple[bool, Optional[int]]:
        """
        Returns (ok, retry_after_seconds). If not ok, request should be blocked as rate-limited.
        """
        try:
            ok, retry_after = self.budget.can_issue_request()
            return bool(ok), (int(retry_after) if retry_after is not None else None)
        except AttributeError:
            # Backward compatibility with the simple BudgetTracker (no QPM support)
            return True, None

    def _notify_request_issued(self) -> None:
        try:
            self.budget.notify_request_issued()
        except AttributeError:
            pass  # simple tracker has no window accounting

    # Privacy cost: light, deterministic heuristic for the demo
    def _calculate_privacy_cost(self, user_input: str, classification: Dict[str, Any]) -> float:
        base = 0.10
        if len(user_input or "") > 200:
            base *= 1.5
        try:
            conf = float(classification.get("confidence", 1.0))
        except Exception:
            conf = 1.0
        if conf < 0.8:
            base *= 1.2
        if str(classification.get("risk_level", "low")).lower() == "medium":
            base *= 1.1
        # Cap and round for stable UI
        return round(min(base, 0.5), 3)