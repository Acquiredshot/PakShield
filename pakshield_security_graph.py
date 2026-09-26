"""
PakShield → Wolf-Pak Security Graph integration.

Upserts PakShield domain entities (Identity, Device, Application, Resource,
Permission, Policy) into the Wolf-Pak Security Graph so the graph maintains
a live map of who has what access to which assets.

The graph uses PakShield entity IDs as node keys so cross-app correlation
(Network Guardian network flows ↔ PakShield identities ↔ Mask host state)
always joins on stable identifiers.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("pakshield.security_graph")

# Local imports — fall back to stubs if the graph is unavailable.
try:
    from wolf_pak_security.security_graph.core import GraphEntity, GraphRelationship, SecurityGraph
    _GRAPH_AVAILABLE = True
except ImportError:
    _GRAPH_AVAILABLE = False
    GraphEntity = GraphRelationship = SecurityGraph = object  # type: ignore[misc, assignment]


class PakShieldSecurityGraph:
    """Maintains PakShield entities in the Wolf-Pak Security Graph.

    Nodes:
        - identity: a User, Service Account, Group, or Role
        - device: a managed device
        - application: a protected application
        - resource: a protected resource
        - permission: a permission definition
        - policy: a policy document

    Edges (PakShield → Graph):
        - identity -> device         : owns (identity owns a device)
        - identity -> application    : accesses (identity can access an app)
        - identity -> resource       : can_access (identity can access a resource)
        - identity -> permission     : has_permission
        - identity -> identity       : member_of (user in group / group in role)
        - device -> application      : runs (device runs an application)
        - application -> resource    : protects (app protects a resource)
        - policy -> resource         : governs (policy governs a resource)
    """

    def __init__(self) -> None:
        if _GRAPH_AVAILABLE:
            self._graph = SecurityGraph()
        else:
            self._graph = None
            logger.warning(
                "Wolf-Pak Security Graph unavailable — PakShield identity graph "
                "will not be populated. Install wolf_pak_security or run the "
                "Event Fabric intake server to enable graph correlation."
            )

    def _entity(self, entity_type: str, entity_id: str, properties: dict[str, Any] | None = None) -> GraphEntity | None:
        if not _GRAPH_AVAILABLE:
            return None
        return GraphEntity(entity_type=entity_type, entity_id=entity_id, properties=properties or {})

    def upsert_identity(self, *, identity_id: str, identity_type: str, name: str, tenant_id: str, properties: dict[str, Any] | None = None) -> bool:
        """Upsert an identity node."""
        if not _GRAPH_AVAILABLE:
            return False
        props = {"name": name, "tenant_id": tenant_id, "type": identity_type}
        props.update(properties or {})
        entity = GraphEntity(entity_type="identity", entity_id=identity_id, properties=props)
        self._graph.upsert_entity(entity=entity)
        logger.debug("Security Graph: upserted identity %s (%s)", identity_id, identity_type)
        return True

    def upsert_device(self, *, device_id: str, name: str, device_type: str, ip_address: str, tenant_id: str, properties: dict[str, Any] | None = None) -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        props = {"name": name, "tenant_id": tenant_id, "type": device_type, "ip_address": ip_address}
        props.update(properties or {})
        entity = GraphEntity(entity_type="device", entity_id=device_id, properties=props)
        self._graph.upsert_entity(entity=entity)
        logger.debug("Security Graph: upserted device %s", device_id)
        return True

    def upsert_application(self, *, application_id: str, name: str, application_type: str, base_url: str, tenant_id: str, properties: dict[str, Any] | None = None) -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        props = {"name": name, "tenant_id": tenant_id, "type": application_type, "base_url": base_url}
        props.update(properties or {})
        entity = GraphEntity(entity_type="application", entity_id=application_id, properties=props)
        self._graph.upsert_entity(entity=entity)
        logger.debug("Security Graph: upserted application %s", application_id)
        return True

    def upsert_resource(self, *, resource_id: str, name: str, resource_type: str, parent_id: str | None, tenant_id: str, properties: dict[str, Any] | None = None) -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        props = {"name": name, "tenant_id": tenant_id, "type": resource_type}
        if parent_id:
            props["parent_id"] = parent_id
        props.update(properties or {})
        entity = GraphEntity(entity_type="resource", entity_id=resource_id, properties=props)
        self._graph.upsert_entity(entity=entity)
        logger.debug("Security Graph: upserted resource %s", resource_id)
        return True

    def upsert_permission(self, *, permission_id: str, name: str, action: str, resource_type: str, tenant_id: str, properties: dict[str, Any] | None = None) -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        props = {"name": name, "tenant_id": tenant_id, "action": action, "resource_type": resource_type}
        props.update(properties or {})
        entity = GraphEntity(entity_type="permission", entity_id=permission_id, properties=props)
        self._graph.upsert_entity(entity=entity)
        logger.debug("Security Graph: upserted permission %s", permission_id)
        return True

    def upsert_policy(self, *, policy_id: str, name: str, policy_type: str, effect: str, tenant_id: str, properties: dict[str, Any] | None = None) -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        props = {"name": name, "tenant_id": tenant_id, "type": policy_type, "effect": effect}
        props.update(properties or {})
        entity = GraphEntity(entity_type="policy", entity_id=policy_id, properties=props)
        self._graph.upsert_entity(entity=entity)
        logger.debug("Security Graph: upserted policy %s", policy_id)
        return True

    def link_identity_to_device(self, *, identity_id: str, device_id: str, relationship: str = "owns") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=identity_id, target_id=device_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_identity_to_resource(self, *, identity_id: str, resource_id: str, permission_id: str | None = None, relationship: str = "can_access") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        props = {}
        if permission_id:
            props["via_permission"] = permission_id
        rel = GraphRelationship(source_id=identity_id, target_id=resource_id, relationship_type=relationship, properties=props)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_identity_to_application(self, *, identity_id: str, application_id: str, relationship: str = "accesses") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=identity_id, target_id=application_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_identity_to_permission(self, *, identity_id: str, permission_id: str, relationship: str = "has_permission") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=identity_id, target_id=permission_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_identity_to_identity(self, *, source_id: str, target_id: str, relationship: str = "member_of") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=source_id, target_id=target_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_device_to_application(self, *, device_id: str, application_id: str, relationship: str = "runs") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=device_id, target_id=application_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_application_to_resource(self, *, application_id: str, resource_id: str, relationship: str = "protects") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=application_id, target_id=resource_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True

    def link_policy_to_resource(self, *, policy_id: str, resource_id: str, relationship: str = "governs") -> bool:
        if not _GRAPH_AVAILABLE:
            return False
        rel = GraphRelationship(source_id=policy_id, target_id=resource_id, relationship_type=relationship)
        self._graph.upsert_relationship(relationship=rel)
        return True
