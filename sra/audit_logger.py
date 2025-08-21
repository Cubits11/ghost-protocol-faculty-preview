import os
import json
import hashlib
import time
from typing import Tuple, List, Dict, Any, Optional, Callable

class AuditLogger:
    """
    Minimal tamper-evident, hash-chained audit log.
    """

    def __init__(self, path: str = "logs/demo_audit.jsonl"):
        self.path = path
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        if not os.path.exists(self.path):
            open(self.path, "a").close()

    def _line_hash(self, prev_hash: str, obj: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        h.update(prev_hash.encode("utf-8"))
        h.update(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        return h.hexdigest()

    def _last_hash(self) -> str:
        """
        Return the most recent entry hash. Prefer `entry_hash` (new),
        otherwise fall back to legacy `hash`. If the log is empty or
        missing, return 'GENESIS'.
        """
        try:
            last: Optional[str] = None
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last = line
            if not last:
                return "GENESIS"
            data = json.loads(last)
            return data.get("entry_hash") or data.get("hash") or "GENESIS"
        except FileNotFoundError:
            return "GENESIS"

    def log_decision(self, decision: str, reason: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        prev = self._last_hash()
        payload: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "decision": decision,
            "reason": reason,
            "prev_hash": prev,
        }
        if extra:
            for k, v in extra.items():
                if k not in ("hash", "entry_hash"):
                    payload[k] = v

        # Compute the hash over all fields except the hash fields themselves
        to_hash = {k: v for k, v in payload.items() if k not in ("hash", "entry_hash")}
        h = self._line_hash(prev, to_hash)
        payload["hash"] = h                 # legacy/back-compat
        payload["entry_hash"] = h           # preferred (UI/CLI expect this)

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

        return payload

    def get_recent_entries(self, n: int = 10) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            return []
        return rows[-n:] if n > 0 else rows

    def get_entry_count(self) -> int:
        count = 0
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                        count += 1
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            return 0
        return count

    def verify_chain(self) -> Tuple[bool, int]:
        """
        Verify the entire chain. Returns (ok, checked_count).
        - If the log is missing or has zero valid entries, return (False, 0)
          to signal "no decision yet" so the UI shows neutral/empty.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                prev = "GENESIS"
                checked = 0
                has_any = False
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    has_any = True
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return (False, checked)

                    claimed = entry.get("entry_hash") or entry.get("hash") or ""
                    prev_ptr = entry.get("prev_hash", "")
                    if prev_ptr != prev:
                        return (False, checked)

                    no_hash = {k: v for k, v in entry.items() if k not in ("hash", "entry_hash")}
                    recomputed = self._line_hash(prev_ptr, no_hash)
                    if recomputed != claimed:
                        return (False, checked)

                    prev = claimed
                    checked += 1

                if not has_any:
                    return (False, 0)  # signal "no chain" so UI shows neutral/empty
                return (True, checked)
        except FileNotFoundError:
            return (False, 0)

    def simulate_tamper_last_entry(
        self,
        mutate: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        field: str = "reason",
        new_value: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Atomically simulate tampering of the last valid JSON entry by editing the file in place
        via a temp file + replace. This DOES NOT recompute hashes (by design), so verification
        should fail. Also tags the entry with tampered=True for UI rendering.
        """
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        except FileNotFoundError:
            return None

        if not lines:
            return None

        idx = len(lines) - 1
        while idx >= 0:
            try:
                last_obj = json.loads(lines[idx])
                break
            except json.JSONDecodeError:
                idx -= 1
        if idx < 0:
            return None

        tampered = dict(last_obj)
        if mutate:
            tampered = mutate(tampered)
        else:
            if field == "hash" or field == "entry_hash":
                field = "reason"
            if new_value is None:
                original = str(tampered.get(field, ""))
                tampered[field] = (original + " (tampered)").strip()
            else:
                tampered[field] = new_value

        # Explicit UI hint
        tampered["tampered"] = True

        # DO NOT recalculate 'hash'/'entry_hash' to ensure tamper-evidence triggers
        lines[idx] = json.dumps(tampered, ensure_ascii=False)

        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(ln + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.path)

        return tampered