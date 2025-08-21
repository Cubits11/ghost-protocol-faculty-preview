# sra/audit_view.py
"""
Minimal audit view helpers for the SRA demo.

- Verifies integrity of the SHA-256 hash-chained JSONL audit log.
- Returns clear signals for empty/missing logs (no chain yet).
- Tolerates legacy 'hash' while preferring 'entry_hash'.
- Provides small utilities to fetch tail entries, format them for display,
  and to tag the last entry as tampered for demo purposes.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any


# ---------- Internal helpers ----------

def _canonical_json(obj: Dict[str, Any]) -> str:
    """Compact, stable JSON used for hashing comparisons."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _extract_entry_hash(entry: Dict[str, Any]) -> Optional[str]:
    """
    Prefer new 'entry_hash', fall back to legacy 'hash'.
    Do not mutate the incoming entry.
    """
    if "entry_hash" in entry and isinstance(entry["entry_hash"], str):
        return entry["entry_hash"]
    if "hash" in entry and isinstance(entry["hash"], str):
        return entry["hash"]
    return None


# ---------- Public API ----------

def verify_integrity(audit_path: str) -> Tuple[bool, Optional[int]]:
    """
    Verify the entire audit chain.

    Returns:
      (ok, error_at_line)
      - ok == True and error_at_line is None: chain verified
      - ok == False and error_at_line is None: file missing or empty (no chain yet)
      - ok == False and error_at_line is int: chain broken at that (1-based) line
    """
    p = Path(audit_path)
    if not p.exists():
        # No file → “no chain yet” (caller/UI can show neutral state)
        return (False, None)

    prev = "GENESIS"
    checked = 0
    has_any = False

    with p.open("r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            has_any = True
            try:
                entry: Dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                return (False, line_no)

            # Previous pointer must match
            prev_ptr = entry.get("prev_hash")
            if prev_ptr != prev:
                return (False, line_no)

            # Extract stored hash (entry_hash or legacy hash)
            stored = _extract_entry_hash(entry)
            if not stored:
                return (False, line_no)

            # Recompute hash over all fields except 'entry_hash' and 'hash'
            to_hash = {k: v for k, v in entry.items() if k not in ("entry_hash", "hash")}
            recomputed = hashlib.sha256((prev + _canonical_json(to_hash)).encode("utf-8")).hexdigest()

            if recomputed != stored:
                return (False, line_no)

            prev = stored
            checked += 1

    if not has_any:
        # Empty file → “no chain yet”
        return (False, None)

    return (True, None)


def get_audit_tail(audit_path: str, n: int = 10) -> List[Dict[str, Any]]:
    """
    Return the last n parseable entries from the audit log.
    """
    p = Path(audit_path)
    if not p.exists():
        return []

    rows: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                # skip malformed lines
                continue
    return rows[-n:] if n > 0 else rows


def format_entry(entry: Dict[str, Any]) -> str:
    """
    Produce a compact human-readable line for CLI/log printing.
    (Your Streamlit UI should render fields directly.)
    """
    ts_str = str(entry.get("timestamp", ""))
    # Try to handle both ISO strings and epoch-like numbers
    try:
        if isinstance(ts_str, (int, float)):
            dt = datetime.fromtimestamp(float(ts_str))
        elif isinstance(ts_str, str) and ts_str:
            # Allow bare "YYYY-MM-DDTHH:MM:SS" or full ISO
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.fromtimestamp(0)
        else:
            dt = datetime.fromtimestamp(0)
    except Exception:
        dt = datetime.fromtimestamp(0)

    decision = str(entry.get("decision", "UNKNOWN")).upper()
    risk = str(entry.get("risk_level", entry.get("classification", {}).get("risk_level", "N/A")))
    h = _extract_entry_hash(entry) or "N/A"
    tampered = entry.get("tampered", False)

    # Light emoji code for quick scan
    if decision in {"ALLOWED", "ALLOW"}:
        dmark = "✅"
    elif decision in {"BLOCKED", "DENY", "DENIED"}:
        dmark = "❌"
    elif decision in {"TEMPLATE"}:
        dmark = "🛡️"
    elif decision in {"ERROR"}:
        dmark = "⚠️"
    else:
        dmark = "ℹ️"

    tamper_tag = " | TAMPERED" if tampered else ""
    return f"[{dt.strftime('%H:%M:%S')}] {dmark} {decision} | Risk: {risk} | Hash: {h[:12]}...{tamper_tag}"


def tamper_last_entry(audit_path: str) -> bool:
    """
    Mark the last entry as tampered (for demo).
    Does NOT recompute hashes, so verify_integrity() should fail afterwards.

    We set:
      - entry['tampered'] = True
      - entry['reason'] = entry['reason'] + " (tampered)"  (if present)
    """
    p = Path(audit_path)
    if not p.exists():
        return False

    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return False

    # Find last parseable entry
    idx = len(lines) - 1
    while idx >= 0:
        try:
            last = json.loads(lines[idx])
            break
        except json.JSONDecodeError:
            idx -= 1
    if idx < 0:
        return False

    # Mutate a copy WITHOUT touching entry_hash/hash fields
    tampered = dict(last)
    tampered["tampered"] = True
    if "reason" in tampered:
        try:
            tampered["reason"] = (str(tampered["reason"]) + " (tampered)").strip()
        except Exception:
            tampered["reason"] = "tampered"

    # Write back (no hash recompute on purpose)
    lines[idx] = json.dumps(tampered, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


# ---------- Convenience CLI-ish helpers ----------

def verify(audit_path: str = "logs/demo_audit.jsonl") -> bool:
    ok, where = verify_integrity(audit_path)
    if ok:
        print("✅ Audit integrity verified.")
        return True
    if where is None:
        print("ℹ️ No audit chain yet (empty or missing log).")
    else:
        print(f"❌ Audit corrupted at entry line {where}.")
    return False


def show_tail(audit_path: str = "logs/demo_audit.jsonl", n: int = 5) -> None:
    rows = get_audit_tail(audit_path, n)
    print(f"\n📊 Last {min(n, len(rows))} audit entries")
    print("-" * 60)
    for e in rows:
        print(format_entry(e))
    print("-" * 60)