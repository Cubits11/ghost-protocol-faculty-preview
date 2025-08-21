# sra/budget_tracker.py
"""
Budget tracking for the SRA demo.

- Simple epsilon (ε) budget with safe arithmetic and 3‑decimal readout.
- Optional request rate limiting (QPM) using a sliding time window.
- Backwards + forwards compatible API for the demo core/UI.

Public API:
  spend(eps), spend_if_available(eps), get_remaining(), reset(), is_exhausted()
  percent_remaining(), get_stats(), save(path), load(path), to_dict(), from_dict()

S3 hooks expected by SRACore:
  snapshot() -> dict
  can_issue_request() -> (allowed: bool, retry_after_seconds: Optional[int])
  notify_request_issued() -> None

Legacy aliases (kept for tests / older code):
  can_request() == can_issue_request()
  record_request() == notify_request_issued()

Conveniences exposed as properties:
  queries_per_minute_exceeded, retry_after_seconds
"""

from __future__ import annotations
from typing import Optional, Tuple, Dict, Any, List
from threading import Lock
import json, math, time

def _to_float_safe(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
    except Exception:
        return default
    if not math.isfinite(v) or v < 0.0:
        return default
    return v

class BudgetTracker:
    def __init__(
        self,
        initial_epsilon: float = 1.0,
        qpm_limit: Optional[int] = None,
        window_seconds: int = 60,
    ):
        self._lock = Lock()
        self._remaining = _to_float_safe(initial_epsilon, 0.0)

        self._qpm_limit: Optional[int] = int(qpm_limit) if qpm_limit is not None else None
        self._window_seconds: int = max(int(window_seconds), 1)
        self._req_timestamps: List[float] = []

        # cached outputs for properties
        self._last_retry_after: Optional[int] = None

    # ---- ε‑budget ----------------------------------------------------------
    def spend(self, epsilon_cost: float) -> None:
        eps = _to_float_safe(epsilon_cost, 0.0)
        with self._lock:
            self._remaining = max(0.0, self._remaining - eps)

    def spend_if_available(self, epsilon_cost: float) -> bool:
        eps = _to_float_safe(epsilon_cost, 0.0)
        with self._lock:
            if self._remaining >= eps:
                self._remaining -= eps
                return True
            return False

    def get_remaining(self) -> float:
        with self._lock:
            return round(self._remaining + 1e-7, 3)

    @property
    def remaining_epsilon(self) -> float:
        return self.get_remaining()

    def reset(self, new_epsilon: float) -> None:
        with self._lock:
            self._remaining = _to_float_safe(new_epsilon, 0.0)

    def is_exhausted(self) -> bool:
        return self.get_remaining() <= 0.0

    def percent_remaining(self) -> float:
        return round(min(self.get_remaining(), 1.0) * 100.0, 1)

    # ---- QPM sliding‑window rate limiting ---------------------------------
    def set_rate_limit(self, qpm_limit: Optional[int], window_seconds: int = 60) -> None:
        with self._lock:
            self._qpm_limit = int(qpm_limit) if qpm_limit is not None else None
            self._window_seconds = max(int(window_seconds), 1)
            self._trim(time.time())

    def _trim(self, now: float) -> None:
        cutoff = now - self._window_seconds
        ts = self._req_timestamps
        i = 0
        n = len(ts)
        while i < n and ts[i] < cutoff:
            i += 1
        if i:
            del ts[:i]

    def _window_used(self, now: float) -> int:
        self._trim(now)
        return len(self._req_timestamps)

    # ---- S3 hooks used by SRACore -----------------------------------------
    def can_issue_request(self, now: Optional[float] = None) -> Tuple[bool, Optional[int]]:
        with self._lock:
            if self._qpm_limit is None:
                self._last_retry_after = None
                return True, None

            now_f = float(now) if now is not None else time.time()
            used = self._window_used(now_f)

            if used < self._qpm_limit:
                self._last_retry_after = None
                return True, None

            oldest = self._req_timestamps[0]
            retry_after = max(0, int(math.ceil((oldest + self._window_seconds) - now_f)))
            self._last_retry_after = retry_after
            return False, retry_after

    def notify_request_issued(self, now: Optional[float] = None) -> None:
        with self._lock:
            if self._qpm_limit is None:
                return
            now_f = float(now) if now is not None else time.time()
            self._trim(now_f)
            self._req_timestamps.append(now_f)

    # ---- Legacy aliases (tests / older UI) --------------------------------
    def can_request(self, now: Optional[float] = None) -> Tuple[bool, Optional[int]]:
        return self.can_issue_request(now)

    def record_request(self, now: Optional[float] = None) -> None:
        self.notify_request_issued(now)

    # ---- Introspection -----------------------------------------------------
    @property
    def queries_per_minute_exceeded(self) -> bool:
        ok, _ = self.can_issue_request()
        return not ok

    @property
    def retry_after_seconds(self) -> Optional[int]:
        # most recent computed value; triggers a recompute if needed
        _, ra = self.can_issue_request()
        return ra

    def get_qpm_used(self, now: Optional[float] = None) -> int:
        with self._lock:
            now_f = float(now) if now is not None else time.time()
            return self._window_used(now_f)

    def get_stats(self) -> Dict[str, Any]:
        ok, retry = self.can_issue_request()
        return {
            "remaining_epsilon": self.get_remaining(),
            "percent_remaining": self.percent_remaining(),
            "exhausted": self.is_exhausted(),
            "rate_limit_enabled": self._qpm_limit is not None,
            "qpm_limit": self._qpm_limit,
            "qpm_used": self.get_qpm_used(),
            "window_seconds": self._window_seconds,
            "can_request": ok,
            "retry_after_seconds": retry,
        }

    def snapshot(self) -> Dict[str, Any]:
        """Stable shape consumed by SRACore.get_stats() & audit extras."""
        ok, retry = self.can_issue_request()
        return {
            "remaining_epsilon": self.get_remaining(),
            "qpm_limit": self._qpm_limit,
            "window_seconds": self._window_seconds,
            "request_count_current_window": self.get_qpm_used(),
            "rate_limit_enabled": self._qpm_limit is not None,
            "can_request": ok,
            "retry_after_seconds": retry,
        }

    # ---- Persistence -------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "remaining_epsilon": self._remaining,
                "qpm_limit": self._qpm_limit,
                "window_seconds": self._window_seconds,
                "req_timestamps": list(self._req_timestamps),
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BudgetTracker":
        bt = cls(
            initial_epsilon=_to_float_safe(data.get("remaining_epsilon"), 0.0),
            qpm_limit=(int(data["qpm_limit"]) if data.get("qpm_limit") is not None else None),
            window_seconds=int(data.get("window_seconds", 60)),
        )
        ts = data.get("req_timestamps") or []
        now_f = time.time()
        with bt._lock:
            bt._req_timestamps = [float(t) for t in ts if isinstance(t, (int, float))]
            bt._trim(now_f)
        return bt

    def save(self, path: str) -> None:
        try:
            now_f = time.time()
            with self._lock:
                self._trim(now_f)
                payload = self.to_dict()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
        except Exception:
            pass  # demo-grade: ignore persistence errors

    @classmethod
    def load(cls, path: str) -> "BudgetTracker":
        try:
            with open(path, "r", encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except Exception:
            return cls()

    # ---- Niceties ----------------------------------------------------------
    def __repr__(self) -> str:
        st = self.get_stats()
        return f"BudgetTracker(eps={st['remaining_epsilon']}, qpm={st['qpm_limit']}, used={st['qpm_used']}/{st['qpm_limit'] or '∞'})"