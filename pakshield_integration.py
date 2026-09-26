"""
PakShield — Wolf-Pak Security Core integration layer.

Wires PakShield into the three Wolf-Pak Security Core components so identity,
access, and privilege intelligence flows to the rest of the platform:

1. Event Fabric — PakShield emits access events, risk events, findings,
   violations, and remediations so Network Guardian and Mask can correlate
   identity/access signals with network and host telemetry.
2. Security Graph — PakShield upserts identity, device, application, resource,
   permission, and policy nodes + relationships so the graph maintains a live
   map of who has what access to which assets.
3. Mask Network — PakShield redacts sensitive identity and access data
   (credentials, session tokens, PII) via Mask's TrafficMasker before returning
   API responses or emitting event payloads.

Cross-app join key: asset_id (PakShield populates it from the owning device).
Event schema: shared envelope (timestamp_ms, asset_id, source, event_type,
severity, payload) — see wolf_pak_security.events and the intake server.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("pakshield.integration")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

EVENT_FABRIC_URL = os.environ.get(
    "WOLF_PAK_EVENT_FABRIC_URL", "http://localhost:8090/api/event-fabric/intake"
)
EVENT_FABRIC_ENABLED = os.environ.get("PAKSHIELD_EVENT_FABRIC", "1").lower() not in ("0", "false", "no")
SOURCE = "PAKSHIELD"
SOURCE_VERSION = os.environ.get("PAKSHIELD_VERSION", "0.1.0")

# Try to import Wolf-Pak Security Core components. PakShield runs standalone,
# so these are optional — integration is a no-op when they're absent.
try:
    from wolf_pak_security.events import DetectionEvent, AuditEvent
    from wolf_pak_security.event_fabric.core import EventEnvelope
    _HAS_EVENT_FABRIC = True
except ImportError:
    _HAS_EVENT_FABRIC = False

try:
    from wolf_pak_security.security_graph.core import GraphEntity, GraphRelationship, SecurityGraph
    _HAS_SECURITY_GRAPH = True
except ImportError:
    _HAS_SECURITY_GRAPH = False

try:
    from mask_network.portal import TrafficMasker, AnonymisationPipeline
    _HAS_MASK = True
except ImportError:
    _HAS_MASK = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def _emit_to_fabric(envelope: dict[str, Any]) -> bool:
    """POST an event envelope to the Event Fabric intake server.

    Fire-and-forget: log-and-continue so the API request that triggered the
    event still succeeds even if the fabric is unreachable.
    """
    if not EVENT_FABRIC_ENABLED:
        return False
    payload = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        EVENT_FABRIC_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"PakShield/{SOURCE_VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status != 202:
                logger.warning(
                    "Event Fabric returned %s for event %s",
                    resp.status, envelope.get("event_id", "?"),
                )
                return False
            logger.debug("Event Fabric accepted event %s", envelope.get("event_id"))
            return True
    except urllib.error.URLError as exc:
        logger.warning("Event Fabric unreachable (%s) — event dropped: %s", EVENT_FABRIC_URL, exc)
        return False
    except Exception as exc:
        logger.warning("Unexpected error posting to Event Fabric: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Event Fabric publisher
# ---------------------------------------------------------------------------

class PakShieldEventPublisher:
    """Publishes PakShield domain events to the Wolf-Pak Event Fabric.

    Mapped to the shared envelope schema so Network Guardian and Mask can
    correlate PakShield identity/access signals with their own telemetry.
    """

    def __init__(self) -> None:
        self._enabled = EVENT_FABRIC_ENABLED

    def publish_access_event(
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
        """Emit an access decision as a DetectionEvent."""
        if not self._enabled:
            return False
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
            "actor": "PAKSHIELD",
            "action": "access_evaluation",
            "outcome": decision,
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
        return _emit_to_fabric(envelope)

    def publish_risk_event(
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
        """Emit a risk signal as a DetectionEvent."""
        if not self._enabled:
            return False
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
        return _emit_to_fabric(envelope)

    def publish_finding(
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
        """Emit a security finding as a DetectionEvent."""
        if not self._enabled:
            return False
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
        return _emit_to_fabric(envelope)

    def publish_violation(
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
        """Emit a policy violation as a DetectionEvent."""
        if not self._enabled:
            return False
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
        return _emit_to_fabric(envelope)

    def publish_remediation(
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
        if not self._enabled:
            return False
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
        return _emit_to_fabric(envelope)


# ---------------------------------------------------------------------------
# Security Graph feeder
# ---------------------------------------------------------------------------

class PakShieldGraphFeeder:
    """Upserts PakShield entities and relationships into the Security Graph.

    The graph uses PakShield entity IDs as node keys so cross-app correlation
    (Network Guardian network flows <-> PakShield identities <-> Mask host
    state) always joins on stable identifiers.
    """

    def __init__(self) -> None:
        if _HAS_SECURITY_GRAPH:
            self._graph = SecurityGraph()
        else:
            self._graph = None

    def _upsert(self, entity_type: str, entity_id: str, properties: dict[str, Any]) -> bool:
        if self._graph is None:
            return False
        entity = GraphEntity(entity_type=entity_type, entity_id=entity_id, properties=properties)
        self._graph.upsert_entity(entity=entity)
        return True

    def upsert_identity(self, *, identity_id: str, identity_type: str, name: str, tenant_id: str, **extra: Any) -> bool:
        props = {"name": name, "tenant_id": tenant_id, "type": identity_type}
        props.update(extra)
        return self._upsert("identity", identity_id, props)

    def upsert_device(self, *, device_id: str, name: str, device_type: str, ip_address: str, tenant_id: str, **extra: Any) -> bool:
        props = {"name": name, "tenant_id": tenant_id, "type": device_type, "ip_address": ip_address}
        props.update(extra)
        return self._upsert("device", device_id, props)

    def upsert_application(self, *, application_id: str, name: str, application_type: str, base_url: str, tenant_id: str, **extra: Any) -> bool:
        props = {"name": name, "tenant_id": tenant_id, "type": application_type, "base_url": base_url}
        props.update(extra)
        return self._upsert("application", application_id, props)

    def upsert_resource(self, *, resource_id: str, name: str, resource_type: str, tenant_id: str, parent_id: str | None = None, **extra: Any) -> bool:
        props = {"name": name, "tenant_id": tenant_id, "type": resource_type}
        if parent_id:
            props["parent_id"] = parent_id
        props.update(extra)
        return self._upsert("resource", resource_id, props)

    def upsert_permission(self, *, permission_id: str, name: str, action: str, resource_type: str, tenant_id: str, **extra: Any) -> bool:
        props = {"name": name, "tenant_id": tenant_id, "action": action, "resource_type": resource_type}
        props.update(extra)
        return self._upsert("permission", permission_id, props)

    def upsert_policy(self, *, policy_id: str, name: str, policy_type: str, effect: str, tenant_id: str, **extra: Any) -> bool:
        props = {"name": name, "tenant_id": tenant_id, "type": policy_type, "effect": effect}
        props.update(extra)
        return self._upsert("policy", policy_id, props)

    def link(self, source_id: str, target_id: str, relationship_type: str) -> bool:
        if self._graph is None:
            return False
        rel = GraphRelationship(source_id=source_id, target_id=target_id, relationship_type=relationship_type)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_identity_device(self, *, identity_id: str, device_id: str) -> bool:
        return self.link(identity_id, device_id, "owns")

    def link_identity_resource(self, *, identity_id: str, resource_id: str) -> bool:
        return self.link(identity_id, resource_id, "can_access")

    def link_identity_application(self, *, identity_id: str, application_id: str) -> bool:
        return self.link(identity_id, application_id, "accesses")

    def link_identity_permission(self, *, identity_id: str, permission_id: str) -> bool:
        return self.link(identity_id, permission_id, "has_permission")

    def link_device_application(self, *, device_id: str, application_id: str) -> bool:
        return self.link(device_id, application_id, "runs")

    def link_application_resource(self, *, application_id: str, resource_id: str) -> bool:
        return self.link(application_id, resource_id, "protects")

    def link_policy_resource(self, *, policy_id: str, resource_id: str) -> bool:
        return self.link(policy_id, resource_id, "governs")


# ---------------------------------------------------------------------------
# Mask redaction wrapper
# ---------------------------------------------------------------------------

# Sensitive field rules for PakShield API responses and event payloads.
PAKSHIELD_REDACTION_RULES = [
    {"path": "password", "action": "mask", "replace": "***REDACTED***"},
    {"path": "secret", "action": "mask", "replace": "***REDACTED***"},
    {"path": "token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "api_key", "action": "mask", "replace": "***REDACTED***"},
    {"path": "session_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "refresh_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "access_token", "action": "mask", "replace": "***REDACTED***"},
    {"path": "private_key", "action": "mask", "replace": "***REDACTED***"},
    {"path": "credential_hash", "action": "mask", "replace": "***REDACTED***"},
    {"path": "email", "action": "partial", "keep": 3, "separator": "***@***.***"},
    {"path": "phone", "action": "mask", "replace": "***REDACTED***"},
    {"path": "ssn", "action": "mask", "replace": "***REDACTED***"},
]


class PakShieldMaskRedactor:
    """Redacts sensitive identity and access data via Mask's TrafficMasker.

    Falls back to a local rule engine when Mask is unavailable — PakShield
    always runs, even without Mask installed.
    """

    def __init__(self) -> None:
        self._masker = None
        self._pipeline = None
        if _HAS_MASK:
            try:
                self._masker = TrafficMasker()
                self._pipeline = AnonymisationPipeline(
                    anonymizers=[self._masker], rules=PAKSHIELD_REDACTION_RULES
                )
            except Exception as exc:
                logger.warning("Mask redaction init failed (%s) — using fallback", exc)

    def redact(self, payload: dict[str, Any], rule_set: str | list = "api_response") -> dict[str, Any]:
        """Redact sensitive fields from a payload dict.

        Args:
            payload: The dict to redact (copied, not mutated).
            rule_set: One of 'api_response', 'event_payload', 'audit_log' or a
                      custom list of rule dicts.

        Returns:
            A new dict with matched fields redacted.
        """
        if self._pipeline is not None:
            try:
                return self._pipeline.run(payload)
            except Exception as exc:
                logger.warning("Mask pipeline failed, using fallback: %s", exc)

        # Fallback: apply rules directly.
        if isinstance(rule_set, str):
            rules = {
                "api_response": PAKSHIELD_REDACTION_RULES,
                "event_payload": PAKSHIELD_REDACTION_RULES,
                "audit_log": PAKSHIELD_REDACTION_RULES,
            }.get(rule_set, PAKSHIELD_REDACTION_RULES)
        elif isinstance(rule_set, list):
            rules = rule_set
        else:
            rules = PAKSHIELD_REDACTION_RULES
        return _apply_rules(payload, rules)


def _apply_rules(obj: Any, rules: list[dict[str, Any]]) -> Any:
    """Apply redaction rules to a nested dict/list structure (fallback)."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            # Check for a direct rule on this key.
            masked = False
            for rule in rules:
                path = rule.get("path", "")
                if path == key:
                    out[key] = _apply_rule(value, rule)
                    masked = True
                    break
            if not masked:
                # Check for wildcard rules that apply to children.
                child_rules = [r for r in rules if r.get("path", "").startswith("*.")]
                if child_rules:
                    out[key] = _apply_rules(value, child_rules)
                else:
                    out[key] = _apply_rules(value, rules)
        return out
    if isinstance(obj, list):
        return [_apply_rules(item, rules) for item in obj]
    return obj


def _apply_rule(value: Any, rule: dict[str, Any]) -> Any:
    """Apply a single redaction rule to a scalar value."""
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


# ---------------------------------------------------------------------------
# Module-level singletons (lazy — created on first use)
# ---------------------------------------------------------------------------

_publisher: PakShieldEventPublisher | None = None
_feeder: PakShieldGraphFeeder | None = None
_redactor: PakShieldMaskRedactor | None = None


def event_publisher() -> PakShieldEventPublisher:
    global _publisher
    if _publisher is None:
        _publisher = PakShieldEventPublisher()
    return _publisher


def graph_feeder() -> PakShieldGraphFeeder:
    global _feeder
    if _feeder is None:
        _feeder = PakShieldGraphFeeder()
    return _feeder


def mask_redactor() -> PakShieldMaskRedactor:
    global _redactor
    if _redactor is None:
        _redactor = PakShieldMaskRedactor()
    return _redactor


def enrich_context(
    conn: Any,
    *,
    device_ip: str = "",
    device_id: str = "",
    identity_id: str = "",
    tenant_id: str = "TENANT-WOLF-PAK",
) -> dict[str, Any]:
    """Enrich a network alert with PakShield identity/access/risk context.

    This is the primary integration surface Network Guardian calls to turn a
    network event (IP, device) into identity context: who owns the device,
    what they can access, how risky that access is.
    """
    identity: dict[str, Any] | None = None
    device: dict[str, Any] | None = None
    resolved_device_id = device_id or None

    # Resolve device by IP or ID.
    if device_ip and not device_id:
        row = conn.execute(
            "SELECT id, name, device_type, ip_address, posture_score, status"
            " FROM devices WHERE ip_address = ? AND tenant_id = ?",
            (device_ip, tenant_id),
        ).fetchone()
        if row:
            device = {
                "device_id": row["id"],
                "name": row["name"],
                "device_type": row["device_type"],
                "ip_address": row["ip_address"],
                "posture": row["posture_score"],
                "status": row["status"],
                "attributes": {},
            }
            resolved_device_id = row["id"]

    if device_id and not device:
        row = conn.execute(
            "SELECT id, name, device_type, ip_address, posture_score, status"
            " FROM devices WHERE id = ? AND tenant_id = ?",
            (device_id, tenant_id),
        ).fetchone()
        if row:
            device = {
                "device_id": row["id"],
                "name": row["name"],
                "device_type": row["device_type"],
                "ip_address": row["ip_address"],
                "posture": row["posture_score"],
                "status": row["status"],
                "attributes": {},
            }
            resolved_device_id = row["id"]

    # Resolve identity by ID, or by device ownership.
    if identity_id:
        row = conn.execute(
            "SELECT id, type, display_name, status, description, metadata"
            " FROM identities WHERE id = ? AND tenant_id = ?",
            (identity_id, tenant_id),
        ).fetchone()
        if row:
            meta_raw = row["metadata"]
            meta = json.loads(meta_raw) if meta_raw and isinstance(meta_raw, str) else (meta_raw or {})
            identity = {
                "identity_id": row["id"],
                "identity_type": row["type"],
                "name": row["display_name"],
                "status": row["status"],
                "email": meta.get("email", ""),
                "phone": meta.get("phone", ""),
                "role": meta.get("role", ""),
                "attributes": meta,
            }
    elif resolved_device_id:
        row = conn.execute(
            "SELECT i.id, i.type, i.display_name, i.status, i.description, i.metadata"
            " FROM devices d"
            " JOIN identities i ON i.id = d.identity_id"
            " WHERE d.id = ? AND d.tenant_id = ?",
            (resolved_device_id, tenant_id),
        ).fetchone()
        if row:
            meta_raw = row["metadata"]
            meta = json.loads(meta_raw) if meta_raw and isinstance(meta_raw, str) else (meta_raw or {})
            identity = {
                "identity_id": row["id"],
                "identity_type": row["type"],
                "name": row["display_name"],
                "status": row["status"],
                "email": meta.get("email", ""),
                "phone": meta.get("phone", ""),
                "role": meta.get("role", ""),
                "attributes": meta,
            }

    # Effective access.
    effective_access: list[dict[str, Any]] = []
    if identity and identity.get("identity_id"):
        rows = conn.execute(
            "SELECT p.id, p.name, p.action, p.resource_type, p.resource_id, r.name, r.resource_type, r.parent_id"
            " FROM permissions p"
            " JOIN resources r ON r.id = p.resource_id"
            " WHERE p.tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        for row in rows:
            effective_access.append({
                "permission_id": row["id"],
                "name": row["name"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "resource_name": row["name"],
                "resource_parent": row["parent_id"],
            })

    # Risk surface.
    risk_surface: dict[str, Any] = {}
    if identity and identity.get("identity_id"):
        iid = identity["identity_id"]
        total_risk = conn.execute(
            "SELECT COALESCE(SUM(risk_score), 0) FROM risk_events WHERE identity_id = ? AND tenant_id = ?",
            (iid, tenant_id),
        ).fetchone()[0]
        risk_count = conn.execute(
            "SELECT COUNT(*) FROM risk_events WHERE identity_id = ? AND tenant_id = ?",
            (iid, tenant_id),
        ).fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM risk_events WHERE identity_id = ? AND tenant_id = ? AND risk_score >= 65",
            (iid, tenant_id),
        ).fetchone()[0]
        risk_surface = {
            "identity_id": iid,
            "total_risk_score": int(total_risk),
            "risk_event_count": int(risk_count),
            "high_risk_event_count": int(high_risk),
            "risk_level": "high" if (total_risk or 0) >= 65 else "medium" if (total_risk or 0) >= 30 else "low",
        }

    # Active sessions.
    sessions: list[dict[str, Any]] = []
    if identity and identity.get("identity_id"):
        rows = conn.execute(
            "SELECT id, identity_id, device_id, application_id, started_at, last_active_at, expires_at, status, ip_address, user_agent"
            " FROM sessions WHERE identity_id = ? AND tenant_id = ? AND status = 'active'",
            (identity["identity_id"], tenant_id),
        ).fetchall()
        for row in rows:
            sessions.append({
                "session_id": row["id"],
                "identity_id": row["identity_id"],
                "device_id": row["device_id"],
                "application_id": row["application_id"],
                "start_time": row["started_at"],
                "last_active": row["last_active_at"],
                "expires_at": row["expires_at"],
                "status": row["status"],
                "ip_address": row["ip_address"],
            })

    # Recent access events.
    access_events: list[dict[str, Any]] = []
    if identity and identity.get("identity_id"):
        rows = conn.execute(
            "SELECT id, identity_id, device_id, application_id, resource_id, permission_id, action, outcome, source_ip, recorded_at"
            " FROM access_events"
            " WHERE identity_id = ? AND tenant_id = ?"
            " ORDER BY recorded_at DESC LIMIT 5",
            (identity["identity_id"], tenant_id),
        ).fetchall()
        for row in rows:
            access_events.append({
                "event_id": row["id"],
                "identity_id": row["identity_id"],
                "device_id": row["device_id"],
                "application_id": row["application_id"],
                "resource_id": row["resource_id"],
                "permission_id": row["permission_id"],
                "decision": row["outcome"],
                "reason": "",
                "ip_address": row["source_ip"],
                "timestamp": row["recorded_at"],
            })

    # Findings.
    findings: list[dict[str, Any]] = []
    if identity and identity.get("identity_id"):
        rows = conn.execute(
            "SELECT id, identity_id, device_id, category, severity, title, description, recommendation, status, created_at, updated_at"
            " FROM findings WHERE identity_id = ? AND tenant_id = ?"
            " ORDER BY created_at DESC LIMIT 5",
            (identity["identity_id"], tenant_id),
        ).fetchall()
        for row in rows:
            findings.append({
                "finding_id": row["id"],
                "identity_id": row["identity_id"],
                "device_id": row["device_id"],
                "category": row["category"],
                "severity": row["severity"],
                "title": row["title"],
                "description": row["description"],
                "recommendation": row["recommendation"],
                "status": row["status"],
                "created_at": row["created_at"],
                "resolved_at": row["updated_at"],
            })

    # Violations.
    violations: list[dict[str, Any]] = []
    if identity and identity.get("identity_id"):
        rows = conn.execute(
            "SELECT id, identity_id, device_id, policy_id, resource_id, action, violation_type, severity, description, detected_at, status, created_at"
            " FROM violations WHERE identity_id = ? AND tenant_id = ?"
            " ORDER BY detected_at DESC LIMIT 5",
            (identity["identity_id"], tenant_id),
        ).fetchall()
        for row in rows:
            violations.append({
                "violation_id": row["id"],
                "identity_id": row["identity_id"],
                "device_id": row["device_id"],
                "policy_id": row["policy_id"],
                "resource_id": row["resource_id"],
                "action": row["action"],
                "severity": row["severity"],
                "description": row["description"],
                "detected_at": row["detected_at"],
                "status": row["status"],
                "acknowledged_at": "",
                "resolved_at": "",
            })

    return {
        "enriched_at": datetime.now(tz=timezone.utc).isoformat(),
        "source": SOURCE,
        "tenant_id": tenant_id,
        "identity": identity,
        "device": device,
        "effective_access": effective_access,
        "risk_surface": risk_surface,
        "sessions": sessions,
        "access_events": access_events,
        "findings": findings,
        "violations": violations,
    }
