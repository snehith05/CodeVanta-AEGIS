"""The detector pipeline. Each detector looks at one action in context and returns signals."""
from .base import Context
from .dataleak import data_leak
from .destructive import destructive
from .financial import financial
from .identity import identity
from .intent import infer_scope, intent
from .lookalike import lookalike
from .provenance import provenance
from .rules import custom_rules
from .velocity import fingerprint, velocity

DETECTORS = [identity, custom_rules, financial, destructive, data_leak, provenance, intent, velocity, lookalike]

DETECTOR_LABELS = {
    "identity": "Identity & least privilege",
    "baseline": "Action risk tier",
    "policy": "Policy-as-code rule",
    "financial": "Financial controls",
    "destructive": "Blast-radius control",
    "data-leak": "Data-leak guard",
    "provenance": "Provenance (taint) tracking",
    "intent": "Intent drift",
    "velocity": "Circuit breaker",
    "lookalike": "Lookalike domains",
    "injection": "Prompt-injection scanner",
}

__all__ = ["Context", "DETECTORS", "DETECTOR_LABELS", "fingerprint", "infer_scope"]
