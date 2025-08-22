from s4_audit.crypto_receipts import Signer
import json, os, tempfile

def test_chain_and_verify_roundtrip():
    s = Signer(b"master_key_32bytes__________", "sess_demo")
    receipts = []
    for t in range(3):
        payload = {
            "session_id": "sess_demo",
            "turn": t+1,
            "route": "ALLOW",
            "mechanism": "POST",
            "params": {"rho": 0.0}
        }
        receipts.append(s.sign_and_chain(payload, t+1))
    
    # Simulate verify script
    from s4_audit.verify_audit import verify_chain
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
        for r in receipts:
            f.write(json.dumps(r) + "\n")
        path = f.name
    
    assert verify_chain(path, b"master_key_32bytes__________", "sess_demo") == -1
    os.unlink(path)

def test_mutation_detected():
    s = Signer(b"k"*32, "sess_demo")
    r = s.sign_and_chain({
        "session_id": "sess_demo",
        "turn": 1,
        "route": "ALLOW",
        "mechanism": "POST",
        "params": {}
    }, 1)
    r["route"] = "TAMPER"
    
    from s4_audit.verify_audit import verify_chain
    import tempfile, json
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
        f.write(json.dumps(r) + "\n")
        path = f.name
    
    assert verify_chain(path, b"k"*32, "sess_demo") == 0
    os.unlink(path)
