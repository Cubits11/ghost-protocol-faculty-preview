import hashlib, json, time
from typing import Dict, Any, List

class AuditLogger:
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []
        self.prev_hash = "0" * 64

    def _hash(self, entry: Dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

    def log_decision(self, input_text: str, decision: str, reason: str, latency: float, metadata: Dict[str, Any] = None):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "input_hash": hashlib.sha256(input_text.encode()).hexdigest()[:16],
            "decision": decision,
            "reason": reason,
            "latency_ms": round(latency, 1),
            "metadata": metadata or {},
            "prev_hash": self.prev_hash,
        }
        h = self._hash(entry)
        entry["hash"] = h
        self.chain.append(entry)
        self.prev_hash = h

    def get_recent_entries(self, n: int = 5):
        return self.chain[-n:]

    def get_entry_count(self) -> int:
        return len(self.chain)