from typing import List, Dict, Any, Tuple
from .base import AttemptLog

def false_allow_rate(attack_logs: List[AttemptLog]) -> float:
    attempts = len(attack_logs)
    allows = sum(1 for a in attack_logs if a.result.status == "allowed")
    return allows/attempts if attempts else 0.0

def false_block_rate(benign_results: List[AttemptLog]) -> float:
    attempts = len(benign_results)
    blocks = sum(1 for a in benign_results if a.result.status == "blocked")
    return blocks/attempts if attempts else 0.0

def attack_success_rate(attack_logs: List[AttemptLog]) -> float:
    return 1.0 if any(a.result.status=="allowed" for a in attack_logs) else 0.0

def steps_to_first_breach(attack_logs: List[AttemptLog]) -> int:
    for i, a in enumerate(attack_logs):
        if a.result.status == "allowed":
            return i+1
    return -1

def degradation_curve(budgets: List[int], far_per_budget: Dict[int, float]) -> List[Tuple[int,float]]:
    return [(b, far_per_budget.get(b,0.0)) for b in budgets]