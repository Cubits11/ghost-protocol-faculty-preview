import re

class Scan:
    def __init__(self, taints): 
        self.taints = taints
        self.has_taints = bool(taints)

class PoisonScanner:
    def __init__(self, policy_patterns: dict):
        pats = []
        for key in ("pii", "jailbreak", "exfil"):
            for p in (policy_patterns.get(key, []) or []):
                pats.append(re.compile(p, re.I))
        self.rx = pats

    def inspect(self, query: str, chunks: list[str]) -> Scan:
        taints = []
        for idx, c in enumerate([query, *chunks]):
            hits = [r.pattern for r in self.rx if r.search(c or "")]
            if hits: 
                taints.append({"idx": idx, "hits": hits})
        return Scan(taints)
