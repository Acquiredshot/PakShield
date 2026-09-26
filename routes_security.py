"""
PakShield — Routes: Risk Events, Findings, Violations, Remediation.
"""

from flask import abort, jsonify, request
from core import (
    app,
    now_iso,
    id_from,
    get_db,
)


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


def _sev_check(v, valid):
    if v not in valid:
        abort(400, f"value must be one of {valid}")


# ---------------------------------------------------------------------------
# Risk Events
# ---------------------------------------------------------------------------

VALID_SEVERITY_RISK = {"info", "low", "medium", "high", "critical"}


@app.route("/api/tenants/<tenant_id>/risk-events", methods=["GET"])
def list_risk_events(tenant_id):
    conn = get_db()
    severity = request.args.get("severity")
    source = request.args.get("source")
    status = request.args.get("status", "open")
    sql = "SELECT * FROM risk_events WHERE tenant_id=?"
    vals = [tenant_id]
    if severity:
        _sev_check(severity, VALID_SEVERITY_RISK)
        sql += " AND severity=?"
        vals.append(severity)
    if source:
        sql += " AND source=?"
        vals.append(source)
    sql += " AND status=?"
    vals.append(status)
    sql += " ORDER BY created_at DESC"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/risk-events", methods=["POST"])
def create_risk_event(tenant_id):
    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "manual").strip()
    severity = (data.get("severity") or "low").strip()
    risk_score = float(data.get("risk_score", 0.0))
    title = (data.get("title") or "").strip()
    if not title:
        abort(400, "title is required")
    _sev_check(severity, VALID_SEVERITY_RISK)
    now = now_iso()
    rid = id_from("RISK", f"{title}{now[:19]}")
    conn = get_db()
    conn.execute(
        """INSERT INTO risk_events (id,tenant_id,identity_id,device_id,application_id,source,severity,risk_score,
                                    title,description,indicators,related_event_id,status,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, tenant_id,
         data.get("identity_id", ""),
         data.get("device_id", ""),
         data.get("application_id", ""),
         source,
         severity,
         risk_score,
         title,
         data.get("description", ""),
         __import__("json").dumps(data.get("indicators", {})),
         data.get("related_event_id", ""),
         data.get("status", "open"),
         now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM risk_events WHERE id=?", (rid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/risk-events/<risk_event_id>", methods=["PATCH"])
def patch_risk_event(tenant_id, risk_event_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in ("severity", "title", "description", "status", "source"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "risk_score" in data:
        updates.append("risk_score=?")
        vals.append(float(data["risk_score"]))
    if "indicators" in data:
        updates.append("indicators=?")
        vals.append(__import__("json").dumps(data["indicators"]))
    if "related_event_id" in data:
        updates.append("related_event_id=?")
        vals.append(data.get("related_event_id", ""))
    if updates:
        vals.append(risk_event_id)
        conn.execute(f"UPDATE risk_events SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM risk_events WHERE id=?", (risk_event_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/risk-events/<risk_event_id>", methods=["DELETE"])
def delete_risk_event(tenant_id, risk_event_id):
    conn = get_db()
    conn.execute("DELETE FROM risk_events WHERE id=?", (risk_event_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": risk_event_id})


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

VALID_SEVERITY_FIND = {"info", "low", "medium", "high", "critical"}


@app.route("/api/tenants/<tenant_id>/findings", methods=["GET"])
def list_findings(tenant_id):
    conn = get_db()
    category = request.args.get("category")
    severity = request.args.get("severity")
    status = request.args.get("status", "open")
    sql = "SELECT * FROM findings WHERE tenant_id=?"
    vals = [tenant_id]
    if category:
        sql += " AND category=?"
        vals.append(category)
    if severity:
        _sev_check(severity, VALID_SEVERITY_FIND)
        sql += " AND severity=?"
        vals.append(severity)
    sql += " AND status=?"
    vals.append(status)
    sql += " ORDER BY created_at DESC"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/findings", methods=["POST"])
def create_finding(tenant_id):
    data = request.get_json(silent=True) or {}
    category = (data.get("category") or "other").strip()
    severity = (data.get("severity") or "low").strip()
    title = (data.get("title") or "").strip()
    if not title:
        abort(400, "title is required")
    _sev_check(severity, VALID_SEVERITY_FIND)
    now = now_iso()
    fid = id_from("FIND", f"{title}{now[:19]}")
    conn = get_db()
    conn.execute(
        """INSERT INTO findings (id,tenant_id,risk_event_id,identity_id,device_id,title,description,
                                 category,severity,confidence,status,recommendation,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fid, tenant_id,
         data.get("risk_event_id") or None,
         data.get("identity_id") or None,
         data.get("device_id") or None,
         title,
         data.get("description", ""),
         category,
         severity,
         float(data.get("confidence", 1.0)),
         data.get("status", "open"),
         data.get("recommendation", ""),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/findings/<finding_id>", methods=["GET"])
def get_finding(tenant_id, finding_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "finding not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/findings/<finding_id>", methods=["PATCH"])
def patch_finding(tenant_id, finding_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in ("title", "description", "category", "severity", "status", "recommendation"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "confidence" in data:
        updates.append("confidence=?")
        vals.append(float(data["confidence"]))
    if "risk_event_id" in data:
        updates.append("risk_event_id=?")
        vals.append(data.get("risk_event_id", ""))
    if "identity_id" in data:
        updates.append("identity_id=?")
        vals.append(data.get("identity_id", ""))
    if "device_id" in data:
        updates.append("device_id=?")
        vals.append(data.get("device_id", ""))
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(finding_id)
        conn.execute(f"UPDATE findings SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/findings/<finding_id>", methods=["DELETE"])
def delete_finding(tenant_id, finding_id):
    conn = get_db()
    conn.execute("DELETE FROM findings WHERE id=?", (finding_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": finding_id})


# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------

VALID_SEVERITY_VIOL = {"low", "medium", "high", "critical"}


@app.route("/api/tenants/<tenant_id>/violations", methods=["GET"])
def list_violations(tenant_id):
    conn = get_db()
    severity = request.args.get("severity")
    violation_type = request.args.get("violation_type")
    status = request.args.get("status", "active")
    sql = "SELECT * FROM violations WHERE tenant_id=?"
    vals = [tenant_id]
    if severity:
        _sev_check(severity, VALID_SEVERITY_VIOL)
        sql += " AND severity=?"
        vals.append(severity)
    if violation_type:
        sql += " AND violation_type=?"
        vals.append(violation_type)
    sql += " AND status=?"
    vals.append(status)
    sql += " ORDER BY detected_at DESC"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/violations", methods=["POST"])
def create_violation(tenant_id):
    data = request.get_json(silent=True) or {}
    violation_type = (data.get("violation_type") or "other").strip()
    severity = (data.get("severity") or "low").strip()
    action = (data.get("action") or "").strip()
    if not action:
        abort(400, "action is required")
    _sev_check(severity, VALID_SEVERITY_VIOL)
    now = now_iso()
    vid = id_from("VIOL", f"{action}{now[:19]}")
    conn = get_db()
    conn.execute(
        """INSERT INTO violations (id,tenant_id,finding_id,policy_id,identity_id,device_id,resource_id,
                                   action,violation_type,severity,evidence,description,detected_at,status,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (vid, tenant_id,
         data.get("finding_id", ""),
         data.get("policy_id", ""),
         data.get("identity_id", ""),
         data.get("device_id", ""),
         data.get("resource_id", ""),
         action,
         violation_type,
         severity,
         __import__("json").dumps(data.get("evidence", {})),
         data.get("description", ""),
         data.get("detected_at") or now,
         data.get("status", "active"),
         now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM violations WHERE id=?", (vid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/violations/<violation_id>", methods=["GET"])
def get_violation(tenant_id, violation_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM violations WHERE id=?", (violation_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "violation not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/violations/<violation_id>", methods=["PATCH"])
def patch_violation(tenant_id, violation_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in ("action", "violation_type", "severity", "description", "status"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "evidence" in data:
        updates.append("evidence=?")
        vals.append(__import__("json").dumps(data["evidence"]))
    for col in ("policy_id", "finding_id", "identity_id", "device_id", "resource_id", "detected_at"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if updates:
        vals.append(violation_id)
        conn.execute(f"UPDATE violations SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM violations WHERE id=?", (violation_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/violations/<violation_id>", methods=["DELETE"])
def delete_violation(tenant_id, violation_id):
    conn = get_db()
    conn.execute("DELETE FROM violations WHERE id=?", (violation_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": violation_id})


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

VALID_REMEDIATION_TYPES = {
    "revoke_access", "disable_account", "rotate_credential", "quarantine_device",
    "enforce_mfa", "apply_policy", "escalate", "accept_risk", "close", "other",
}


@app.route("/api/tenants/<tenant_id>/remediations", methods=["GET"])
def list_remediations(tenant_id):
    conn = get_db()
    status = request.args.get("status", "pending")
    sql = "SELECT * FROM remediation WHERE tenant_id=?"
    vals = [tenant_id]
    if status:
        sql += " AND status=?"
        vals.append(status)
    sql += " ORDER BY requested_at DESC"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/remediations", methods=["POST"])
def create_remediation(tenant_id):
    data = request.get_json(silent=True) or {}
    action_type = (data.get("action_type") or "other").strip()
    if not action_type:
        abort(400, "action_type is required")
    if action_type not in VALID_REMEDIATION_TYPES:
        abort(400, f"action_type must be one of {VALID_REMEDIATION_TYPES}")
    now = now_iso()
    rid = id_from("REM", f"{action_type}{now[:19]}")
    conn = get_db()
    conn.execute(
        """INSERT INTO remediation (id,tenant_id,violation_id,finding_id,risk_event_id,identity_id,assigned_to,
                                    action_type,action_details,status,requested_at,completed_at,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, tenant_id,
         data.get("violation_id", ""),
         data.get("finding_id", ""),
         data.get("risk_event_id", ""),
         data.get("identity_id", ""),
         data.get("assigned_to", ""),
         action_type,
         data.get("action_details", ""),
         data.get("status", "pending"),
         now,
         data.get("completed_at", ""),
         now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM remediation WHERE id=?", (rid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/remediations/<remediation_id>", methods=["GET"])
def get_remediation(tenant_id, remediation_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM remediation WHERE id=?", (remediation_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "remediation not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/remediations/<remediation_id>", methods=["PATCH"])
def patch_remediation(tenant_id, remediation_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in ("action_type", "action_details", "status", "assigned_to"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "completed_at" in data:
        updates.append("completed_at=?")
        vals.append(data.get("completed_at") or now_iso())
    for col in ("violation_id", "finding_id", "risk_event_id", "identity_id"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(remediation_id)
        conn.execute(f"UPDATE remediation SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM remediation WHERE id=?", (remediation_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/remediations/<remediation_id>", methods=["DELETE"])
def delete_remediation(tenant_id, remediation_id):
    conn = get_db()
    conn.execute("DELETE FROM remediation WHERE id=?", (remediation_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": remediation_id})
