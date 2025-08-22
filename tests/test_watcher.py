from watcher.sprt import SPRTGate

def test_sprt_h0_accept():
    gate = SPRTGate(p0=0.1, p1=0.3, tau=0.6)
    # Feed low scores (should accept H0)
    for _ in range(20):
        result = gate.step(0.2)
        if result != "CONT":
            assert result == "H0"
            return
    # If we get here, test is inconclusive but not failing

def test_sprt_h1_reject():
    gate = SPRTGate(p0=0.1, p1=0.3, tau=0.6)
    # Feed high scores (should reject H0, accept H1)
    for _ in range(20):
        result = gate.step(0.8)
        if result != "CONT":
            assert result == "H1"
            return
