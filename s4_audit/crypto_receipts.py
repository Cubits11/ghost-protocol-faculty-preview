import hmac, hashlib, json

def hkdf_expand(prk: bytes, info: bytes, L: int = 32) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:L]

def chain_update(H_prev: bytes, receipt_bytes: bytes) -> bytes:
    m = hashlib.sha256(); m.update(H_prev); m.update(receipt_bytes); return m.digest()

class Signer:
    def __init__(self, master_key: bytes, session_id: str):
        self.k_t = master_key
        self.sid = session_id.encode()
        self.H_prev = b"\x00" * 32

    def sign_and_chain(self, payload: dict, turn: int) -> dict:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        H_curr = chain_update(self.H_prev, raw)
        sig = hmac.new(self.k_t, H_curr, hashlib.sha256).hexdigest()
        rcpt = {**payload, "hash_prev_hex": self.H_prev.hex(),
                "hash_curr_hex": H_curr.hex(), "sig_hex": sig}
        info = self.sid + b"|" + str(turn).encode()
        self.k_t = hkdf_expand(self.k_t, info, 32)
        self.H_prev = H_curr
        return rcpt
