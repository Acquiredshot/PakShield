"""
PakShield → Wolf-Pak Event Fabric integration.

Emits PakShield domain events (AccessEvent, RiskEvent, Finding, Violation,
Remediation) to the Wolf-Pak Event Fabric intake server so Network Guardian
and Mask Network can correlate identity/access signals with network and host
telemetry.

Intake server: http://localhost:8090/api/event-fabric/intake
Shared envelope schema: timestamp_ms, asset_id, source, event_type, severity, payload
Cross-app join key: asset_id (PakShield populates asset_id from the owning device)

Usage from core.py:
    from pakshield_event_bus import PakShieldEventBus
    event_bus = PakShieldEventBus()
    event_bus.emit_access_event(conn, access_event_dict)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("pakshield.event_bus")

INTAKE_URL = os.environ.get(
    "WOLF_PAK_EVENT_FABRIC_URL", "http://localhost:8090/api/event-fabric/intake"
)
SOURCE = "PAKSHIELD"
SOURCE_VERSION = os.environ.get("PAKSHIELD_VERSION", "0.1.0")


def _now_ms() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def _emit(envelope: dict[str, Any]) -> bool:
    """POST a single event envelope to the Event Fabric intake server.

    Returns True on success (202), False on any failure (log-and-continue —
    event emission must never break the API request that triggered it).
    """
    payload = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        INTAKE_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"PakShield/{SOURCE_VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.URLError as exc:
        logger.warning(
            "Event Fabric intake unreachable (%s) — event dropped: %s",
            INTAKE_URL, envelope.get("event_id", "?"),
        )
        return False
    except Exception as exc:
        logger.warning(
            "Unexpected error posting event %s to Event Fabric: %s",
            envelope.get("event_id", "?"), exc,
        )
        return False

    if status != 202:
        logger.warning(
            "Event Fabric returned %s for event %s: %s",
            status, envelope.get("event_id", "?"), body[:200],
        )
        return False

    logger.debug("Event Fabric accepted event %s (family=%s)", envelope.get("event_id"), envelope.get("family"))
    return True


class PakShieldEventBus:
    """Emits PakShield domain events to the Wolf-Pak Event Fabric.

    Every method is fire-and-forget: a failure to reach the intake server
    is logged and swallowed so the API request that triggered the event
    still succeeds.
    """

    def __init__(self, intake_url: str | None = None) -> None:
        self.intake_url = intake_url or INTAKE_URL

    def emit_access_event(
        self,
        *,
        event_id: str,
        identity_id: str,
        device_id: str,
        application_id: str,
        resource_id: str,
        permission_id: str,
        decision: str,
        reason: str,
        ip_address: str,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit an access decision as a DetectionEvent on the 'access' channel."""
        ts = timestamp_ms or _now_ms()
        envelope = {
            "timestamp_ms": ts,
            "asset_id": device_id or "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": "access_decision",
            "severity": "info",
            "category": "access",
            "description": f"Access {'granted' if decision == 'allow' else 'denied'}: {identity_id} -> {resource_id} via {permission_id}",
            "family": "detection",
            "event_id": event_id,
            "payload": {
                "identity_id": identity_id,
                "device_id": device_id,
                "application_id": application_id,
                "resource_id": resource_id,
                "permission_id": permission_id,
                "decision": decision,
                "reason": reason,
                "ip_address": ip_address,
            },
        }
        return _emit(envelope)

    def emit_risk_event(
        self,
        *,
        event_id: str,
        identity_id: str,
        device_id: str,
        risk_type: str,
        risk_score: float,
        description: str,
        details: dict[str, Any] | None = None,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit a risk signal as a DetectionEvent on the 'risk' channel."""
        ts = timestamp_ms or _now_ms()
        severity = "low" if risk_score < 30 else "medium" if risk_score < 65 else "high"
        envelope = {
            "timestamp_ms": ts,
            "asset_id": device_id or "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": "risk_signal",
            "severity": severity,
            "category": "risk",
            "description": description,
            "family": "detection",
            "event_id": event_id,
            "payload": {
                "identity_id": identity_id,
                "device_id": device_id,
                "risk_type": risk_type,
                "risk_score": risk_score,
                "details": details or {},
            },
        }
        return _emit(envelope)

    def emit_finding(
        self,
        *,
        event_id: str,
        identity_id: str,
        device_id: str,
        category: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit a security finding as a DetectionEvent on the 'finding' channel."""
        ts = timestamp_ms or _now_ms()
        envelope = {
            "timestamp_ms": ts,
            "asset_id": device_id or "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": "security_finding",
            "severity": severity,
            "category": category,
            "description": description,
            "family": "detection",
            "event_id": event_id,
            "payload": {
                "identity_id": identity_id,
                "device_id": device_id,
                "category": category,
                "severity": severity,
                "title": title,
                "description": description,
                "recommendation": recommendation,
            },
        }
        return _emit(envelope)

    def emit_violation(
        self,
        *,
        event_id: str,
        identity_id: str,
        device_id: str,
        policy_id: str,
        resource_id: str,
        action: str,
        severity: str,
        description: str,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit a policy violation as a DetectionEvent on the 'violation' channel."""
        ts = timestamp_ms or _now_ms()
        envelope = {
            "timestamp_ms": ts,
            "asset_id": device_id or "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": "policy_violation",
            "severity": severity,
            "category": "violation",
            "description": description,
            "family": "detection",
            "event_id": event_id,
            "payload": {
                "identity_id": identity_id,
                "device_id": device_id,
                "policy_id": policy_id,
                "resource_id": resource_id,
                "action": action,
                "description": description,
            },
        }
        return _emit(envelope)

    def emit_remediation(
        self,
        *,
        event_id: str,
        identity_id: str,
        device_id: str,
        finding_id: str,
        remediation_type: str,
        action_taken: str,
        status: str,
        description: str,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit a remediation as an AuditEvent."""
        ts = timestamp_ms or _now_ms()
        envelope = {
            "timestamp_ms": ts,
            "asset_id": device_id or "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": "remediation",
            "severity": "info",
            "category": "remediation",
            "description": description,
            "family": "audit",
            "event_id": event_id,
            "actor": "PAKSHIELD",
            "action": remediation_type,
            "outcome": status,
            "payload": {
                "identity_id": identity_id,
                "device_id": device_id,
                "finding_id": finding_id,
                "remediation_type": remediation_type,
                "action_taken": action_taken,
                "status": status,
            },
        }
        return _emit(envelope)

    def emit_credential_event(
        self,
        *,
        event_id: str,
        identity_id: str,
        credential_id: str,
        event_type: str,
        severity: str,
        description: str,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit a credential lifecycle event (create/rotate/expire/revoke)."""
        ts = timestamp_ms or _now_ms()
        envelope = {
            "timestamp_ms": ts,
            "asset_id": "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": event_type,
            "severity": severity,
            "category": "credential",
            "description": description,
            "family": "audit",
            "event_id": event_id,
            "actor": "PAKSHIELD",
            "payload": {
                "identity_id": identity_id,
                "credential_id": credential_id,
                "event_type": event_type,
            },
        }
        return _emit(envelope)

    def emit_session_event(
        self,
        *,
        event_id: str,
        identity_id: str,
        session_id: str,
        device_id: str,
        application_id: str,
        event_type: str,
        severity: str,
        description: str,
        timestamp_ms: int | None = None,
    ) -> bool:
        """Emit a session lifecycle event (create/refresh/terminate)."""
        ts = timestamp_ms or _now_ms()
        envelope = {
            "timestamp_ms": ts,
            "asset_id": device_id or "",
            "source": SOURCE,
            "source_version": SOURCE_VERSION,
            "event_type": event_type,
            "severity": severity,
            "category": "session",
            "description": description,
            "family": "audit",
            "event_id": event_id,
            "actor": "PAKSHIELD",
            "payload": {
                "identity_id": identity_id,
                "session_id": session_id,
                "device_id": device_id,
                "application_id": application_id,
                "event_type": event_type,
            },
        }
        return _emit(envelope)
