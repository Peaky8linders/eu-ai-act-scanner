"""A small arithmetic CLI utility — pure Python, no AI/ML whatsoever.

Used as a scanner fixture for the out-of-scope path: a repository with no
AI framework, model, or agent signal must be reported as "not an AI system"
rather than scored (and the fix loop must refuse to remediate it).
"""

from __future__ import annotations


def add(a: float, b: float) -> float:
    """Return the sum of two numbers."""
    return a + b


def subtract(a: float, b: float) -> float:
    """Return the difference of two numbers."""
    return a - b


def multiply(a: float, b: float) -> float:
    """Return the product of two numbers."""
    return a * b


def divide(a: float, b: float) -> float:
    """Return the quotient of two numbers; raises on division by zero."""
    if b == 0:
        raise ZeroDivisionError("division by zero")
    return a / b
