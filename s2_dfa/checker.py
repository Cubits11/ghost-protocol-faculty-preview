import json
from typing import List

def build_ac(substrings: List[str]):
    # Simplified version without ahocorasick dependency
    class SimpleAC:
        def __init__(self, patterns):
            self.patterns = patterns
        def iter(self, text):
            results = []
            for i, p in enumerate(self.patterns):
                if p in text:
                    results.append((0, (i, p)))
            return results
    return SimpleAC(substrings)

def dfa_accepts(output: str, dfa_json_path: str) -> bool:
    # minimal DFA: states, start, accept, transitions
    spec = json.load(open(dfa_json_path))
    state = spec["start"]
    for ch in output:
        state = spec["transitions"].get(state, {}).get(ch, None)
        if state is None: return False
    return state in set(spec["accept"])

def safe_output(output: str, dfa_path: str, bad_substrings: List[str]) -> bool:
    if not dfa_accepts(output, dfa_path): return False
    ac = build_ac([s for s in bad_substrings if len(s) >= 3])
    for _, (_, s) in ac.iter(output):
        return False
    return True
