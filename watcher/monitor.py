"""KS test and AUC monitoring for distribution drift."""
import numpy as np
from scipy import stats

class DriftMonitor:
    def __init__(self, baseline_scores, alpha=0.05):
        self.baseline = np.array(baseline_scores)
        self.alpha = alpha
        
    def ks_test(self, current_scores):
        """Kolmogorov-Smirnov test for distribution drift."""
        stat, pval = stats.ks_2samp(self.baseline, current_scores)
        return {"ks_stat": stat, "p_value": pval, "drift": pval < self.alpha}
