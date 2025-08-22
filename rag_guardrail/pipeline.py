from s4_audit.crypto_receipts import Signer
from s3_budget.accountant import ZCDPAccountant
from rag_guardrail.scanner import PoisonScanner

class GuardedRAG:
    def __init__(self, policy: dict, master_key: bytes, session_id: str):
        self.policy = policy
        self.signer = Signer(master_key, session_id)
        self.acc = ZCDPAccountant(delta=policy.get("delta", 1e-6))
        self.scanner = PoisonScanner(policy_patterns=policy)
        self.turn = 0

    def _receipt(self, route: str, mechanism: str, params: dict):
        self.turn += 1
        payload = {
            "session_id": "sess_demo",
            "turn": self.turn,
            "route": route,
            "mechanism": mechanism,
            "params": params
        }
        return self.signer.sign_and_chain(payload, self.turn)

    def answer(self, query: str, chunks: list[str]):
        scan = self.scanner.inspect(query, chunks)
        if scan.has_taints:
            out = "[risk_brief_v1] Top themes: security, auth, moderate. No names; no quotes."
            rcpt = self._receipt("TEMPLATE", "DFA", {
                "rho_turn": 0.0,
                "rho_session": self.acc.rho,
                "epsilon_session": self.acc.eps(),
                "delta": self.acc.delta,
                "tv_bound": 0.0,
                "mi_bound_bits": 0.0
            })
            return out, rcpt, scan
        # else ALLOW (non-DP)
        out = "Safe summary of retrieved content."
        tv, name = self.acc.tv_bounds()
        rcpt = self._receipt("ALLOW", "POST-PROCESS", {
            "rho_turn": 0.0,
            "rho_session": self.acc.rho,
            "epsilon_session": self.acc.eps(),
            "delta": self.acc.delta,
            "tv_bound": tv,
            "tv_inequality": name,
            "mi_bound_bits": self.acc.mi_bound_bits(),
            "dp_claim": False
        })
        return out, rcpt, scan
