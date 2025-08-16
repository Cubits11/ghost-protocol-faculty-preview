from typing import List
from pathlib import Path
from .base import AttackProbe

def load_adversarial(path: str = "data/attack_examples.txt") -> List[AttackProbe]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [AttackProbe(prompt=l.strip()) for l in lines if l.strip() and not l.strip().startswith("#")]

def load_benign(path: str = "data/benign_examples.txt") -> List[str]:
    return [l.strip() for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")]