from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

@dataclass
class RetrievedChunk:
    doc_id: str
    text: str
    score: float
    meta: Dict[str, Any]

@dataclass
class ScanResult:
    tainted: bool
    reasons: List[str]
    redactions: List[Tuple[int, int]]  # spans in text
    risk_score: float

class RAGGuardrail:
    """
    Interpose before generation:
      1) scan retrieved chunks
      2) drop or redact tainted spans
      3) compute risk
      4) decide route: TEMPLATE / DP_SUMMARY / ALLOW / DENY
    """
    def __init__(self, policy, s1_detector, s2_templates, budget_accountant, audit_logger):
        self.policy = policy
        self.s1 = s1_detector
        self.s2 = s2_templates
        self.budget = budget_accountant
        self.audit = audit_logger

    def scan_chunk(self, chunk: RetrievedChunk) -> ScanResult:
        # TODO: replace with your s1_detector features (regex/AC hits, keys, emails, jailbreak cues)
        reasons, spans = [], []
        risk = 0.0
        if "-----BEGIN" in chunk.text:  # toy secret cue
            reasons.append("key_material")
            risk += 0.7
        if "@gmail.com" in chunk.text:
            reasons.append("email")
            risk += 0.3
        return ScanResult(tainted=bool(reasons), reasons=reasons, redactions=spans, risk_score=min(risk, 1.0))

    def scan(self, chunks: List[RetrievedChunk]) -> Dict[str, Any]:
        results = [self.scan_chunk(c) for c in chunks]
        tainted = any(r.tainted for r in results)
        risk = max((r.risk_score for r in results), default=0.0)
        return {"results": results, "tainted": tainted, "risk": risk}

    def decide_route(self, scan_out: Dict[str, Any]) -> str:
        risk = scan_out["risk"]
        if scan_out["tainted"] or risk >= self.policy.taint_threshold:
            return "TEMPLATE"  # or "DP_SUMMARY" depending on query type
        return "ALLOW"

    def process(self, session_id: str, chunks: List[RetrievedChunk], query: str) -> Dict[str, Any]:
        scan_out = self.scan(chunks)
        route = self.decide_route(scan_out)

        # Account DP (0 for ALLOW, positive for DP_SUMMARY)
        rho_turn = 0.0
        if route == "DP_SUMMARY":
            rho_turn = self.policy.rho_per_summary
        self.budget.add_rho(rho_turn)

        receipt = {
            "turn": self.budget.turn,
            "route": route,
            "rho_turn": rho_turn,
            **self.budget.summary(),  # adds rho_session, epsilon_session, kl_bound, tv_bound, mi_bits
            "len_bucket": self._bucket_len(query),
            "time_bucket": 0,  # TODO: fill with real timing
            "scan": {"tainted": scan_out["tainted"], "risk": scan_out["risk"]},
        }
        self.audit.write(receipt)
        return {"route": route, "scan": scan_out, "receipt": receipt}

    @staticmethod
    def _bucket_len(text: str) -> int:
        n = len(text)
        if n < 64: return 0
        if n < 128: return 1
        if n < 256: return 2
        if n < 512: return 3
        return 4