"""
PakShield — REST API surface (part 2 of 2).
Devices, Applications, Resources, Permissions, Policies, 
Credentials, Sessions, Access/Risk Events, Findings, Violations,
Remediation, Dashboard, Access Evaluation.
"""

from flask import Flask, abort, jsonify, request, render_template
from core import (
    app as _app,
    now_iso,
    id_from,
    get_db,
)

app = _app


def _json(row):
    if row is None:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, str):
            try:
                parsed = __import__("json").loads(v)
            except (ValueError, TypeError):
                continue
            if isinstance(parsed, (dict, list)):
                d[k] = parsed
    return d


def _paginate(rows, size=50):
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = max(1, min(200, int(request.args.get("limit", size))))
    except (TypeError, ValueError):
        page, limit = 1, size
    offset = (page - 1) * limit
    rows = list(rows)
    total = len(rows)
    return {
        "data": [dict(r) for r in rows[offset:offset + limit]],
        "page": page,
        "limit": limit,
        "total": total,
    }


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

DEVICE_STATUSES = {"active", "quarantined", "retired", "lost"}


@app.route("/api/tenants/<tenant_id>/devices", methods=["GET"])
def list_devices(tenant_id):
    conn = get_db()
    status = request.args.get("status", "active")
    if status not in DEVICE_STATUSES:
        abort(400, f"status must be one of {DEVICE_STATUSES}")
    rows = conn.execute(
        "SELECT * FROM devices WHERE tenant_id=? AND status=? ORDER BY name",
        (tenant_id, status),
    ).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/devices", methods=["POST"])
def create_device(tenant_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort(400, "name is required")
    now = now_iso()
    did = id_from("DEV", name)
    conn = get_db()
    conn.execute(
        """INSERT INTO devices (id,tenant_id,identity_id,name,device_type,os,os_version,hostname,
                                ip_address,mac_address,serial,platform,posture_score,
                                compliance_status,encrypted,mfa_capable,status,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (did, tenant_id,
         data.get("identity_id", ""),
         name,
         data.get("device_type", "workstation"),
         data.get("os", ""),
         data.get("os_version", ""),
         data.get("hostname", ""),
         data.get("ip_address", ""),
         data.get("mac_address", ""),
         data.get("serial", ""),
         data.get("platform", "unknown"),
         data.get("posture_score", 1.0),
         data.get("compliance_status", "unknown"),
         data.get("encrypted", 0),
         data.get("mfa_capable", 0),
         data.get("status", "active"),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/devices/<device_id>", methods=["GET"])
def get_device(tenant_id, device_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "device not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/devices/<device_id>", methods=["PATCH"])
def patch_device(tenant_id, device_id):
    data = request.get_json(silent=True) or {}
    d = data.get("device", data)
    conn = get_db()
    updates, vals = [], []
    for col in (
        "name", "device_type", "os", "os_version", "hostname", "ip_address",
        "mac_address", "serial", "platform", "posture_score", "compliance_status",
        "encrypted", "mfa_capable", "status",
    ):
        if col in d:
            updates.append(f"{col}=?")
            vals.append(d[col])
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(device_id)
        conn.execute(f"UPDATE devices SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/devices/<device_id>", methods=["DELETE"])
def delete_device(tenant_id, device_id):
    conn = get_db()
    conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": device_id})


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/applications", methods=["GET"])
def list_applications(tenant_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM applications WHERE tenant_id=? ORDER BY name",
        (tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/applications", methods=["POST"])
def create_application(tenant_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort(400, "name is required")
    now = now_iso()
    aid = id_from("APP", name)
    conn = get_db()
    conn.execute(
        """INSERT INTO applications (id,tenant_id,name,description,type,vendor,version,url,protocol,
                                    auth_method,risk_rating,status,metadata,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (aid, tenant_id,
         name,
         data.get("description", ""),
         data.get("type", "web"),
         data.get("vendor", ""),
         data.get("version", ""),
         data.get("url", ""),
         data.get("protocol", "none"),
         data.get("auth_method", "none"),
         data.get("risk_rating", "medium"),
         data.get("status", "active"),
         __import__("json").dumps(data.get("metadata", {})),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM applications WHERE id=?", (aid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/applications/<application_id>", methods=["GET"])
def get_application(tenant_id, application_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "application not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/applications/<application_id>", methods=["PATCH"])
def patch_application(tenant_id, application_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in (
        "name", "description", "type", "vendor", "version", "url",
        "protocol", "auth_method", "risk_rating", "status",
    ):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "metadata" in data:
        updates.append("metadata=?")
        vals.append(__import__("json").dumps(data["metadata"]))
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(application_id)
        conn.execute(f"UPDATE applications SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/applications/<application_id>", methods=["DELETE"])
def delete_application(tenant_id, application_id):
    conn = get_db()
    conn.execute("DELETE FROM applications WHERE id=?", (application_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": application_id})
