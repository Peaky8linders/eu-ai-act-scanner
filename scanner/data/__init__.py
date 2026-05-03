"""Data-only reference modules for the EU AI Act scanner.

These modules are pure constants and pure helpers — no I/O, no mutable
state, deterministic for the same inputs. Engines reference these tables
the same way they reference :mod:`scanner.kb` (single source of truth;
never inline literals in engine code).
"""
