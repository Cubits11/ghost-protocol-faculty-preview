import json, os, time, hashlib
from typing import List, Dict, Any
from .base import EgressSystem, AttackProbe, AttackBudget, Mutator, AttackerStrategy, AttemptLog
from .metrics import false_allow_rate, attack_success_rate, steps_to_first_breach

def _run_id() -> str:
    return hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]

class AttackExecutor:
    def __init__(self, sut: EgressSystem, out_dir: str = "results/runs"):
        self.sut = sut
        os.makedirs(out_dir, exist_ok=True)
        self.out_dir = out_dir

    def run_one(self, base_attack: AttackProbe, mutators: List[Mutator], strategy: AttackerStrategy, budget: AttackBudget) -> Dict[str, Any]:
        logs: List[AttemptLog] = strategy.run(self.sut, base_attack, mutators, budget)
        far = false_allow_rate(logs)
        asr = attack_success_rate(logs)
        steps = steps_to_first_breach(logs)
        run = {
            "run_id": _run_id(),
            "strategy": strategy.name,
            "budget": budget.__dict__,
            "base_attack": base_attack.prompt,
            "attempts": len(logs),
            "FAR": far,
            "ASR": asr,
            "steps_to_breach": steps,
            "logs": [a.__dict__ for a in logs]
        }
        out = os.path.join(self.out_dir, f"{run['run_id']}.json")
        with open(out, "w") as f:
            json.dump(run, f, indent=2, default=str)
        return run