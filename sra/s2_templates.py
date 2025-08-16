from typing import Dict, Any

class S2Templates:
    """Tiny template system for safe responses."""
    def __init__(self, _config_path=None):
        self.templates = {
            "general": "Here's what I can tell you safely: {content}",
            "academic": "Based on public sources: {content}",
        }

    def generate_safe_response(self, category: str = "general", risk_level: str = "medium") -> Dict[str, Any]:
        msg = "Your request triggers template-only mode. Providing high-level info."
        return {"message": self.templates.get(category, self.templates["general"]).format(content=msg)}

    def generate_full_response(self, user_input: str, classification: Dict[str, Any], scope: str) -> Dict[str, Any]:
        # In a real system you’d call an LLM; for the demo we return a canned response
        content = f"Summary for: '{user_input[:80]}' (scope={scope})"
        return {"message": self.templates["academic"].format(content=content)}