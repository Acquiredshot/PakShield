"""
PakShield → Mask Network redaction integration.

Wraps Mask Network's TrafficMasker / AnonymisationPipeline so PakShield API
responses can redact sensitive identity and access data (credentials, tokens,
PII, session secrets) before returning them to callers or before emitting
events to the Event Fabric.

Mask's redaction primitives (from mask_network/portal.py):
    TrafficMasker.mask(payload, rule_set)        — redact a payload by rule set
    AnonymisationPipeline(anonymizers, rules)    — chain anonymizers

PakShield rule sets:
    - "api_response"   — redact credential values, session secrets, tokens in API responses
    - "event_payload"  — redact sensitive fields before emitting to Event Fabric
    - "audit_log"      — redact secrets in audit log output
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("pakshield.mask_redaction")

# Try to import Mask's redaction primitives. PakShield runs standalone, so
# fall back to a no-op implementation when Mask is unavailable.
try:
    from mask_network.portal import TrafficMasker, AnonymisationPipeline
    _MASK_AVAILABLE = True
except ImportError:
    _MASK_AVAILABLE = False
    TrafficMasker = AnonymisationPipeline = None  # type: ignore[misc, assignment]


# ---------------------------------------------------------------------------
# PakShield redaction rule sets
# ---------------------------------------------------------------------------

CREDENTIAL_MASK_RULES = [
    {"path": "password", "action": "mask", "replace": "***REDACTED***"},
    {"path": "secret", "action": "mask", "replace": "***REDACTED***"},
    {"path": "token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "api_key", "action": "mask", "replace": "***REDACTED***"},
    {"path": "private_key", "action": "mask", "replace": "***REDACTED***"},
    {"path": "credential_hash", "action": "mask", "replace": "***REDACTED***"},
    {"path": "*.password", "action": "mask", "replace": "***REDACTED***"},
    {"path": "*.secret", "action": "mask", "replace": "***REDACTED***"},
    {"path": "*.token", "action": "mask", "replace": "***REDACTED***"},
]

SESSION_MASK_RULES = [
    {"path": "session_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "refresh_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "access_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "*.session_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "*.refresh_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "*.access_token", "action": "mask", "replace": "***REDACTED***"},
]

PII_MASK_RULES = [
    {"path": "email", "action": "partial", "keep": 3, "separator": "***@***.***"},
    {"path": "phone", "action": "mask", "replace": "***REDACTED***"},
    {"path": "ssn", "action": "mask", "replace": "***REDACTED***"},
    {"path": "passport", "action": "mask", "replace": "***REDACTED***"},
    {"path": "ipi", "action": "mask", "replace": "***REDACTED***"},
]

# Composed rule sets
RULE_SETS = {
    "api_response": CREDENTIAL_MASK_RULES + SESSION_MASK_RULES,
    "event_payload": CREDENTIAL_MASK_RULES + PII_MASK_RULES,
    "audit_log": CREDENTIAL_MASK_RULES + PII_MASK_RULES + SESSION_MASK_RULES,
}


# ---------------------------------------------------------------------------
# Local fallback mask implementation
# ---------------------------------------------------------------------------

def _apply_rule(value: Any, rule: dict[str, Any]) -> Any:
    """Apply a single mask rule to a scalar value."""
    action = rule.get("action", "mask")
    if action == "mask":
        return rule.get("replace", "***REDACTED***")
    if action == "partial":
        s = str(value)
        keep = rule.get("keep", 0)
        sep = rule.get("separator", "***")
        if len(s) <= keep:
            return s
        return s[:keep] + sep
    return value


def _get_by_path(obj: Any, path: str) -> tuple[int, Any]:
    """Return (depth, value) at a dotted/glob path within obj. -1 if missing."""
    if not path or path.startswith("*."):
        return -1, None
    parts = path.split(".")
    cur: Any = obj
    for i, part in enumerate(parts):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, (list, tuple)):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return -1, None
        else:
            return -1, None
        if cur is None and i < len(parts) - 1:
            return -1, None
    return 0, cur


def _mask_dict(obj: Any, rules: list[dict[str, Any]]) -> Any:
    """Recursively mask fields in a dict/list per the given rules.

    Returns a new object with matched fields replaced. No mutation of the
    original.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            # Direct path match on this key
            matched = False
            for rule in rules:
                path = rule.get("path", "")
                if path == k or path.startswith("*."):
                    out[k] = _apply_rule(v, rule)
                    matched = True
                    break
            if not matched:
                # Recurse into children — check wildcard child paths
                child_rules = [r for r in rules if r.get("path", "").startswith("*.")]
                if child_rules:
                    out[k] = _mask_dict(v, child_rules)
                else:
                    out[k] = _mask_dict(v, rules)
        return out
    if isinstance(obj, list):
        return [_mask_dict(item, rules) for item in obj]
    return obj


class PakShieldMaskRedaction:
    """Redacts sensitive identity and access data from PakShield API responses.

    Uses Mask Network's TrafficMasker when available; falls back to the local
    rule engine otherwise. Always safe to call — never raises.
    """

    def __init__(self) -> None:
        self._masker: Any = None
        self._pipeline: Any = None
        if _MASK_AVAILABLE and TrafficMasker is not None:
            try:
                self._masker = TrafficMasker()
                self._pipeline = AnonymisationPipeline(
                    anonymizers=[self._masker], rules=CREDENTIAL_MASK_RULES
                )
            except Exception as exc:
                logger.warning("Mask Network redaction init failed: %s — using fallback", exc)
                self._masker = None
                self._pipeline = None

    def mask_api_response(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Redact credential/session fields in an API response payload."""
        if self._pipeline is not None:
            try:
                return self._pipeline.run(payload)
            except Exception as exc:
                logger.warning("Mask pipeline failed, using fallback: %s", exc)
        return _mask_dict(payload, RULE_SETS["api_response"])

    def mask_event_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive fields in an event payload before emitting to Event Fabric."""
        if self._masker is not None:
            try:
                result = self._masker.mask(payload, RULE_SETS["event_payload"])
                if isinstance(result, dict):
                    return result
            except Exception as exc:
                logger.warning("Mask masker failed, using fallback: %s", exc)
        return _mask_dict(payload, RULE_SETS["event_payload"])

    def mask_audit_log(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Redact secrets in audit log output."""
        if self._pipeline is not None:
            try:
                return self._pipeline.run(payload)
            except Exception as exc:
                logger.warning("Mask pipeline failed, using fallback: %s", exc)
        return _mask_dict(payload, RULE_SETS["audit_log"])

    def redact_credentials(self, obj: Any) -> Any:
        """Convenience: redact credential fields from any dict/list structure."""
        return _mask_dict(obj, CREDENTIAL_MASK_RULES)

    def redact_session(self, obj: Any) -> Any:
        """Convenience: redact session token fields from any dict/list structure."""
        return _mask_dict(obj, SESSION_MASK_RULES)

    def redact_pii(self, obj: Any) -> Any:
        """Convenience: redact PII fields from any dict/list structure."""
        return _mask_dict(obj, PII_MASK_RULES)
