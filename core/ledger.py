# core/ledger.py
import json, hashlib, time, os
class Ledger:
    def __init__(self, path): self.p=path; os.makedirs(os.path.dirname(path),exist_ok=True)
    def _last(self):
        try: *_, last=open(self.p).read().splitlines(); return json.loads(last)
        except: return {"idx":-1,"hash":"0"*64}
    def write(self, kind, payload):
        prev=self._last(); idx=prev["idx"]+1
        rec={"idx":idx,"ts":time.time(),"kind":kind,"payload":payload,"prev":prev["hash"]}
        rec["hash"]=hashlib.sha256(json.dumps(rec,sort_keys=True).encode()).hexdigest()
        with open(self.p,"a") as f: f.write(json.dumps(rec)+"\n")
    def verify(self):
        prev_hash="0"*64
        for i,line in enumerate(open(self.p)):
            rec=json.loads(line); h=rec["hash"]
            exp=hashlib.sha256(json.dumps({k:v for k,v in rec.items() if k!="hash"},sort_keys=True).encode()).hexdigest()
            assert h==exp and rec["prev"]==prev_hash, f"break at {i}"
            prev_hash=h
        return True
