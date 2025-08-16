import time
from typing import Dict, Any, Optional
from .s1_detector import S1Detector
from .s2_templates import S2Templates
from .copper_ground import CopperGround
from .audit_logger import AuditLogger
from .budget_tracker import BudgetTracker

class SRACore:
    def __init__(self, config_path: Optional[str] = None):
        self.detector = S1Detector()
        self.templates = S2Templates(config_path)
        self.copper = CopperGround()
        self.audit = AuditLogger()
        self.budget = BudgetTracker()
        self.requests = 0
        self.blocked = 0

    def process_request(self, user_input: str, user_scope: str = "general") -> Dict[str, Any]:
        start = time.time()
        self.requests += 1

        cls = self.detector.classify(user_input)

        if cls["risk_level"] == "high":
            self.blocked += 1
            refusal = self.copper.generate_refusal("injection_detected", cls)
            latency = (time.time() - start) * 1000
            self.audit.log_decision(user_input, "BLOCKED", refusal["policy_reference"], latency, cls)
            return {"status": "blocked", "response": refusal, "latency_ms": round(latency, 1), "classification": cls}

        if cls["risk_level"] == "medium":
            resp = self.templates.generate_safe_response("general", "medium")
            latency = (time.time() - start) * 1000
            self.audit.log_decision(user_input, "ALLOWED_TEMPLATE", "Medium risk - template mode", latency, cls)
            return {"status": "allowed", "response": resp, "mode": "template_only", "latency_ms": round(latency, 1),
                    "budget_remaining": self.budget.get_remaining()}

        # low risk → charge tiny epsilon and return full template response
        epsilon_cost = 0.1
        if not self.budget.allocate(epsilon_cost, user_scope):
            refusal = self.copper.generate_refusal("budget_exceeded", {"cost": epsilon_cost})
            latency = (time.time() - start) * 1000
            self.audit.log_decision(user_input, "BLOCKED", "Budget exceeded", latency, cls)
            return {"status": "blocked", "response": refusal, "latency_ms": round(latency, 1)}

        resp = self.templates.generate_full_response(user_input, cls, user_scope)
        latency = (time.time() - start) * 1000
        self.audit.log_decision(user_input, "ALLOWED", "Low risk - OK", latency, cls)
        return {"status": "allowed", "response": resp, "budget_remaining": self.budget.get_remaining(),
                "epsilon_cost": epsilon_cost, "latency_ms": round(latency, 1)}

    def get_stats(self) -> Dict[str, Any]:
        return {
            "requests_processed": self.requests,
            "attacks_blocked": self.blocked,
            "block_rate": self.blocked / self.requests if self.requests else 0.0,
            "budget_remaining": self.budget.get_remaining(),
            "audit_entries": self.audit.get_entry_count(),
        }