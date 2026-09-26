"""
PakShield enrichment endpoint — Network Guardian calls this to enrich a
network alert with identity, device, access, and risk context.

Endpoint: POST /api/enrich/context
Request:  {"device_ip": "...", "device_id": "...", "identity_id": "..."}
Response: {"identity": {...}, "device": {...}, "effective_access": [...],
           "risk_surface": {...}, "sessions": [...], "access_events": [...],
           "findings": [...], "violations": [...]}

This is the primary cross-app integration surface: when Network Guardian sees
a network event on device X, it calls this to learn who owns X, what they can
access, and how risky that access is — then correlates with its own telemetry.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, Response, jsonify, request

from core import get_db
from pakshield_integration import enrich_context as _enrich

logger = logging.getLogger("pakshield.enrichment")

enrichment = Blueprint("enrichment", __name__)


@enrichment.route("/api/enrich/context", methods=["POST"])
def enrich_context_route() -> tuple[Response, int]:
    """Enrich a network alert with PakShield identity/access/risk context.

    Network Guardian sends one of: device_ip, device_id, or identity_id.
    PakShield returns the full identity context graph for that anchor.
    """
    conn = get_db()

    body = request.get_json(silent=True) or {}
    device_ip = (body.get("device_ip") or "").strip()
    device_id = (body.get("device_id") or "").strip()
    identity_id = (body.get("identity_id") or "").strip()
    tenant_id = (body.get("tenant_id") or "TENANT-WOLF-PAK").strip()

    if not any([device_ip, device_id, identity_id]):
        return jsonify({"error": "one of device_ip, device_id, or identity_id is required"}), 400

    try:
        ctx = _enrich(
            conn,
            device_ip=device_ip,
            device_id=device_id,
            identity_id=identity_id,
            tenant_id=tenant_id,
        )
        return jsonify(ctx), 200
    except Exception as exc:
        logger.error("enrich_context failed: %s", exc, exc_info=True)
        return jsonify({"error": "enrichment failed", "detail": str(exc)}), 500
    finally:
        conn.close()


@enrichment.route("/api/enrich/context/health", methods=["GET"])
def enrich_health() -> tuple[Response, int]:
    """Health check for the enrichment endpoint."""
    return jsonify({
        "status": "ok",
        "service": "pakshield-enrichment",
        "version": "0.1.0",
    }), 200


# ---------------------------------------------------------------------------
# Auto-register on import when core.app is available — used as fallback when
# app.py does not register the blueprint itself. The registration in app.py
# wins; this block is a safety net for standalone imports.
# ---------------------------------------------------------------------------
try:
    from core import app as _flask_app  # noqa: F811
    if "enrichment" not in getattr(_flask_app, "blueprints", {}):
        _flask_app.register_blueprint(enrichment)
except Exception:
    pass  # app.py registers manually if this fails
