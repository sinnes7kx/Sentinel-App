"""Sentinel backend — authorized security assessment platform.

The FastAPI application layer wraps a ported, safety-critical domain core
(scope enforcement, bounded tool execution, evidence redaction, recovery).
Nothing here relaxes the guarantees of that core; the API re-checks scope and
authorization at its own boundary in addition to the execution layer.
"""

__version__ = "0.1.0"
