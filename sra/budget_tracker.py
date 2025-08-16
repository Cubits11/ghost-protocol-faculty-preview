class BudgetTracker:
    def __init__(self, initial_budget: float = 1.0):
        self.remaining = float(initial_budget)

    def allocate(self, epsilon_cost: float, _scope: str) -> bool:
        if self.remaining >= epsilon_cost:
            self.remaining -= epsilon_cost
            return True
        return False

    def get_remaining(self) -> float:
        return round(self.remaining, 2)