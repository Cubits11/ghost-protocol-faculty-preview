from math import sqrt, log
LN2 = 0.6931471805599453

class ZCDPAccountant:
    def __init__(self, delta: float = 1e-6):
        self.rho = 0.0
        self.delta = float(delta)
        self.turn = 0

    def add_rho(self, rho_t: float) -> float:
        assert rho_t >= 0.0
        self.rho += rho_t; self.turn += 1
        return rho_t

    def add_gaussian(self, sensitivity: float, sigma: float) -> float:
        rho_t = (sensitivity * sensitivity) / (2.0 * sigma * sigma)
        return self.add_rho(rho_t)

    def eps(self) -> float:
        if self.rho == 0.0: return 0.0
        return self.rho + 2.0 * sqrt(self.rho * log(1.0 / self.delta))

    def kl_bound(self) -> float:
        return self.rho

    def tv_bounds(self):
        kl = max(self.kl_bound(), 1e-18)
        tv_pinsker = (0.5 * kl) ** 0.5
        import math
        tv_bh = (1.0 - math.exp(-kl)) ** 0.5
        return (tv_bh, "BH") if tv_bh <= tv_pinsker else (tv_pinsker, "Pinsker")

    def mi_bound_bits(self) -> float:
        return self.rho / LN2

    def summary(self) -> dict:
        tv, name = self.tv_bounds()
        return {
            "turn": self.turn, "rho_session": self.rho,
            "epsilon_session": self.eps(), "delta": self.delta,
            "kl_bound": self.kl_bound(), "tv_bound": tv,
            "tv_inequality": name, "mi_bound_bits": self.mi_bound_bits()
        }
