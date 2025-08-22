import math

class SPRTGate:
    def __init__(self, alpha=0.05, beta=0.10, p0=0.1, p1=0.3, tau=0.6):
        self.A = math.log((1-beta)/alpha)
        self.B = math.log(beta/(1-alpha))
        self.p0, self.p1, self.tau = p0, p1, tau
        self.llr = 0.0
        
    def step(self, score: float):
        x = 1.0 if score > self.tau else 0.0
        num = self.p1 if x else (1-self.p1)
        den = self.p0 if x else (1-self.p0)
        self.llr += math.log(num/den)
        if self.llr >= self.A: return "H1"
        if self.llr <= self.B: return "H0"
        return "CONT"
