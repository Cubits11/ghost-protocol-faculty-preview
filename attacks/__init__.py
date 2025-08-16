# attacks/__init__.py
"""
Attack Framework Package

This package provides tools for evaluating AI egress control systems
through systematic attack testing and mutation strategies.
"""

from .base import (
    # Protocols
    EgressSystem,
    Mutator,
    AttackerStrategy, 
    LeakageScorer,
    
    # Data classes
    AttackBudget,
    AttackProbe,
    AttackResult,
    AttemptLog,
    
    # Implementations
    SRATarget,
    SimpleLeakageScorer,
    
    # Utilities
    create_attack_probe,
    log_attempt,
)

__version__ = "0.1.0"

__all__ = [
    # Protocols
    "EgressSystem",
    "Mutator",
    "AttackerStrategy",
    "LeakageScorer", 
    
    # Data classes
    "AttackBudget",
    "AttackProbe",
    "AttackResult", 
    "AttemptLog",
    
    # Implementations
    "SRATarget",
    "SimpleLeakageScorer",
    
    # Utilities
    "create_attack_probe",
    "log_attempt",
]