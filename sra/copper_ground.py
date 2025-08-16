from typing import Dict, Any

class CopperGround:
    def generate_refusal(self, violation_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        messages = {
            "injection_detected": "Request blocked: embedded instructions violate isolation policy.",
            "budget_exceeded": "Request blocked: privacy budget would be exceeded.",
            "system_error": "Request blocked: internal error; safe refusal returned."
        }
        return {
            "policy_reference": f"SRA-{violation_type.upper()}-001",
            "message": messages.get(violation_type, "Request refused."),
            "context": context,
        }