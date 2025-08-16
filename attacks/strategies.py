import time
from typing import List
from .base import EgressSystem, AttackProbe, AttackBudget, AttackerStrategy, AttemptLog, AttackResult, Mutator

def _run_once(sut: EgressSystem, probe: AttackProbe) -> AttackResult:
    t0 = time.time()
    res = sut.process_request(probe.prompt)
    return AttackResult(
        status=res.get("status","error"),
        response=res.get("response"),
        latency_ms=(time.time()-t0)*1000,
        classification=res.get("classification")
    )

class BlackBoxGreedy:
    """Try each mutator breadth-first; stop when any breach occurs."""
    name = "black_box_greedy"

    def run(self, sut: EgressSystem, base_attack: AttackProbe, mutators: List[Mutator], budget: AttackBudget) -> List[AttemptLog]:
        logs: List[AttemptLog] = []
        attempts = 0
        for m in mutators:
            for variant in m.mutate(base_attack):
                if budget.time_limit_s and attempts==0:
                    t_start = time.time()
                result = _run_once(sut, variant)
                logs.append(AttemptLog(variant.prompt, result, attempts, m.name, time.time()))
                attempts += 1
                if result.status == "allowed":  # breach
                    return logs
                if attempts >= budget.mutations: 
                    return logs
                if budget.time_limit_s and (time.time()-t_start) > budget.time_limit_s:
                    return logs
        return logs

class GrayBoxLatencyProbe:
    """Exploit side-channels heuristically: prefer variants that reduce latency or change mode."""
    name = "gray_box_latency"

    def run(self, sut: EgressSystem, base_attack: AttackProbe, mutators: List[Mutator], budget: AttackBudget) -> List[AttemptLog]:
        logs: List[AttemptLog] = []
        variants = []
        # Generate all then rank by heuristic (simple: random tie-breaker)
        for m in mutators:
            variants.extend(list(m.mutate(base_attack)))
        # Quick scoring pass to bias toward “likely leaks”
        scored = []
        for v in variants[:min(len(variants), budget.mutations*2)]:
            r = _run_once(sut, v)
            logs.append(AttemptLog(v.prompt, r, len(logs), f"{m.name}-prefilter", time.time()))
            score = (1 if r.status=="allowed" else 0) + (0.001 * (50 - min(r.latency_ms, 50)))
            scored.append((score, v))
        # Choose top-K to re-try (budget)
        scored.sort(key=lambda x: x[0], reverse=True)
        for idx, (_, v) in enumerate(scored[:budget.mutations]):
            r = _run_once(sut, v)
            logs.append(AttemptLog(v.prompt, r, len(logs), self.name, time.time()))
            if r.status == "allowed":
                break
        return logs

# White-box strategy (optional later): uses known policy thresholds to craft exact borderline variants.