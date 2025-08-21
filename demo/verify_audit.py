#!/usr/bin/env python3
"""
Audit verification demo using sra.audit_view
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sra.audit_view import verify, show_tail, tamper_last_entry


def main():
    """Run audit verification demo."""
    audit_path = "logs/demo_audit.jsonl"
    
    print("\n🔍 SRA Audit Verification Demo")
    print("=" * 60)
    
    # Show recent entries
    show_tail(audit_path, n=3)
    
    # Verify integrity
    print("\nVerifying audit integrity...")
    is_valid = verify(audit_path)
    
    if len(sys.argv) > 1 and sys.argv[1] == "--tamper":
        print("\n⚠️  Tampering with last entry for demo...")
        if tamper_last_entry(audit_path):
            print("Tampered! Now verifying again...")
            verify(audit_path)
        else:
            print("Failed to tamper (no entries?)")
    
    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())