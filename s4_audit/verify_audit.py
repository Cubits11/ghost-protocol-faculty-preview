import json, hmac, hashlib, sys
from .crypto_receipts import hkdf_expand, chain_update

def verify_chain(path: str, master_key: bytes, session_id: str) -> int:
    k = master_key; sid = session_id.encode(); H_prev = b"\x00"*32
    with open(path) as f:
        for idx, line in enumerate(f):
            r = json.loads(line)
            raw = json.dumps({k:v for k,v in r.items() if k not in ("hash_prev_hex","hash_curr_hex","sig_hex")},
                             sort_keys=True, separators=(",",":")).encode()
            H_curr = chain_update(H_prev, raw)
            info = sid + b"|" + str(r["turn"]).encode()
            k = hkdf_expand(k, info, 32)
            sig = hmac.new(k, H_curr, hashlib.sha256).hexdigest()
            if sig != r["sig_hex"] or H_prev.hex() != r["hash_prev_hex"] or H_curr.hex() != r["hash_curr_hex"]:
                return idx
            H_prev = H_curr
    return -1

if __name__ == "__main__":
    idx = verify_chain(sys.argv[1], b"master_key_32bytes__________", "sess_demo")
    print("OK" if idx == -1 else f"FAIL at line {idx}")
