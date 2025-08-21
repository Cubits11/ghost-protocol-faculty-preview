# sra/scoring.py
from dataclasses import dataclass
from typing import Dict, List, Tuple
import math

@dataclass(frozen=True)
class PressureConfig:
    thresholds: Dict[str, float]             # {"low":0.2,"medium":0.4,"high":0.7,"critical":0.9}
    logistic_k: float = 0.9
    intent_bonus: float = 0.20               # applied once if any suspicious intents present
    context_bonus: float = 0.10              # applied once if any anomaly flags present
    # Optionally: per-intent/flag bonuses instead of flat ones
    per_intent_bonus: Dict[str, float] = None
    per_flag_bonus: Dict[str, float] = None

def aggregate_pressure(
    matches: List[Dict],
    intents: List[str],
    flags: List[str],
    cfg: PressureConfig
) -> Tuple[float, List[str], str]:
    s = sum(float(m.get("weight", 0.0)) for m in matches)
    reasons: List[str] = []
    if s > 0:
        reasons.append(f"{len(matches)} pattern match(es) detected")

    base = 1.0 - math.exp(-cfg.logistic_k * s)
    pressure = base

    # Intent bonuses
    applied_intent_bonus = False
    if cfg.per_intent_bonus:
        for it in intents:
            b = cfg.per_intent_bonus.get(it)
            if b:
                pressure += b; applied_intent_bonus = True
    elif intents:
        pressure += cfg.intent_bonus; applied_intent_bonus = True
    if applied_intent_bonus:
        reasons.append("suspicious semantic intent")

    # Context bonuses
    applied_flag_bonus = False
    if cfg.per_flag_bonus:
        for fl in flags:
            b = cfg.per_flag_bonus.get(fl)
            if b:
                pressure += b; applied_flag_bonus = True
    elif flags:
        pressure += cfg.context_bonus; applied_flag_bonus = True
    if applied_flag_bonus:
        reasons.append("context anomaly")

    pressure = max(0.0, min(1.0, pressure))
    level = _to_level(pressure, cfg.thresholds)
    if not reasons:
        reasons = ["no risky pattern matched"]
    return pressure, reasons, level

def _to_level(p: float, th: Dict[str, float]) -> str:
    if p >= th.get("critical", 0.90): return "critical"
    if p >= th.get("high", 0.70):     return "high"
    if p >= th.get("medium", 0.40):   return "medium"
    return "low"