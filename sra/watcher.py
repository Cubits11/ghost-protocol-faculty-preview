from dataclasses import dataclass
from typing import List, Dict, Any
import math
from collections import Counter

# --- KS on bucketed distributions ---
def ks_stat(buckets_a: List[int], buckets_b: List[int], k: int = 10) -> float:
    ca = Counter(buckets_a); cb = Counter(buckets_b)
    tot_a, tot_b = sum(ca.values()), sum(cb.values())
    cdf_a, cdf_b, d = 0.0, 0.0, 0.0
    for i in range(k):
        cdf_a += ca.get(i, 0) / (tot_a or 1)
        cdf_b += cb.get(i, 0) / (tot_b or 1)
        d = max(d, abs(cdf_a - cdf_b))
    return d

# --- Toy logistic on simple features (expand later) ---
def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

@dataclass
class LogisticModel:
    w_len: float = 0.0
    w_time: float = 0.0
    b: float = 0.0

    def score(self, len_bucket: int, time_bucket: int) -> float:
        z = self.w_len * float(len_bucket) + self.w_time * float(time_bucket) + self.b
        return sigmoid(z)

# --- SPRT gate (sequential) ---
class SPRTGate:
    def __init__(self, alpha=0.05, beta=0.10, p0=0.1, p1=0.3, tau=0.6):
        self.A = math.log((1 - beta) / alpha)
        self.B = math.log(beta / (1 - alpha))
        self.p0, self.p1, self.tau = p0, p1, tau
        self.llr = 0.0

    def step(self, score: float):
        x = 1.0 if score > self.tau else 0.0
        num = self.p1 if x else (1 - self.p1)
        den = self.p0 if x else (1 - self.p0)
        self.llr += math.log(num / den)
        if self.llr >= self.A: return "H1"   # suspicious → downgrade
        if self.llr <= self.B: return "H0"   # safe
        return "CONT"

@dataclass
class Watcher:
    ks_warn: float = 0.2
    ks_panic: float = 0.3
    clf_tau: float = 0.6
    clf_model: LogisticModel = LogisticModel()
    sprt: SPRTGate = SPRTGate()

    def observe_window(self, recent_len_buckets: List[int], baseline_len_buckets: List[int],
                       recent_time_buckets: List[int], baseline_time_buckets: List[int]) -> Dict[str, Any]:
        ks_len = ks_stat(recent_len_buckets, baseline_len_buckets, k=10)
        ks_time = ks_stat(recent_time_buckets, baseline_time_buckets, k=10)
        level = "ok"
        if max(ks_len, ks_time) >= self.ks_panic: level = "panic"
        elif max(ks_len, ks_time) >= self.ks_warn: level = "warn"
        return {"ks_len": ks_len, "ks_time": ks_time, "level": level}

    def score_turn(self, len_bucket: int, time_bucket: int) -> Dict[str, Any]:
        s = self.clf_model.score(len_bucket, time_bucket)
        verdict = self.sprt.step(s)
        action = "none"
        if s > self.clf_tau or verdict == "H1":
            action = "downgrade"
        return {"score": s, "sprt": verdict, "action": action}