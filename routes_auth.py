"""
PakShield — Routes: Credentials, Sessions, Access Events.
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


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/credentials", methods=["GET"])
def list_credentials(tenant_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM credentials WHERE tenant_id=? ORDER BY created_at DESC",
        (tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/credentials", methods=["POST"])
def create_credential(tenant_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    credential_type = data.get("credential_type", "password")
    if not name:
        abort(400, "name is required")
    now = now_iso()
    cid = id_from("CRED", name + now[:19])
    conn = get_db()
    conn.execute(
        """INSERT INTO credentials (id,tenant_id,identity_id,device_id,name,credential_type,status,strength_score,
                                    encrypted,last_rotated_at,expires_at,next_rotation_at,fingerprint,metadata,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cid, tenant_id,
         data.get("identity_id", ""),
         data.get("device_id", ""),
         name,
         credential_type,
         data.get("status", "active"),
         data.get("strength_score", 0.0),
         data.get("encrypted", 0),
         data.get("last_rotated_at", now),
         data.get("expires_at", ""),
         data.get("next_rotation_at", ""),
         data.get("fingerprint", ""),
         __import__("json").dumps(data.get("metadata", {})),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (cid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/credentials/<credential_id>", methods=["GET"])
def get_credential(tenant_id, credential_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "credential not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/credentials/<credential_id>", methods=["PATCH"])
def patch_credential(tenant_id, credential_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in (
        "name", "credential_type", "status", "strength_score", "encrypted",
        "expires_at", "next_rotation_at", "fingerprint",
    ):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "last_rotated_at" in data:
        updates.append("last_rotated_at=?")
        vals.append(data["last_rotated_at"])
    if "metadata" in data:
        updates.append("metadata=?")
        vals.append(__import__("json").dumps(data["metadata"]))
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(credential_id)
        conn.execute(f"UPDATE credentials SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/credentials/<credential_id>/rotate", methods=["POST"])
def rotate_credential(tenant_id, credential_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    n = now_iso()
    conn.execute(
        "UPDATE credentials SET status='active', last_rotated_at=?, next_rotation_at=?, updated_at=? WHERE id=?",
        (n, data.get("next_rotation_at", n), n, credential_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/sessions", methods=["GET"])
def list_sessions(tenant_id):
    conn = get_db()
    status = request.args.get("status", "active")
    identity_id = request.args.get("identity_id")
    sql = "SELECT * FROM sessions WHERE tenant_id=? AND status=?"
    vals = [tenant_id, status]
    if identity_id:
        sql += " AND identity_id=?"
        vals.append(identity_id)
    sql += " ORDER BY started_at DESC"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/sessions", methods=["POST"])
def create_session(tenant_id):
    data = request.get_json(silent=True) or {}
    identity_id = (data.get("identity_id") or "").strip()
    if not identity_id:
        abort(400, "identity_id is required")
    now = now_iso()
    sid = id_from("SESS", f"{identity_id}{now}")
    conn = get_db()
    conn.execute(
        """INSERT INTO sessions (id,tenant_id,identity_id,device_id,credential_id,application_id,auth_method,
                                started_at,last_active_at,expires_at,ip_address,user_agent,status,risk_score,mfa_verified,properties)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (sid, tenant_id,
         identity_id,
         data.get("device_id", ""),
         data.get("credential_id", ""),
         data.get("application_id", ""),
         data.get("auth_method", "oidc"),
         now, now,
         data.get("expires_at") or now,
         data.get("ip_address", ""),
         data.get("user_agent", ""),
         data.get("status", "active"),
         data.get("risk_score", 0.0),
         int(data.get("mfa_verified", 1)),
         __import__("json").dumps(data.get("properties", {})),
         ),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/sessions/<session_id>", methods=["GET"])
def get_session(tenant_id, session_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "session not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/sessions/<session_id>", methods=["PATCH"])
def patch_session(tenant_id, session_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in ("status", "risk_score", "mfa_verified", "ip_address", "user_agent"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "expires_at" in data:
        updates.append("expires_at=?")
        vals.append(data["expires_at"])
    if "last_active_at" in data:
        updates.append("last_active_at=?")
        vals.append(data["last_active_at"] or now_iso())
    if "properties" in data:
        updates.append("properties=?")
        vals.append(__import__("json").dumps(data["properties"]))
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(session_id)
        conn.execute(f"UPDATE sessions SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/sessions/<session_id>", methods=["DELETE"])
def revoke_session(tenant_id, session_id):
    conn = get_db()
    conn.execute("UPDATE sessions SET status='revoked', updated_at=? WHERE id=?", (now_iso(), session_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "revoked", "session_id": session_id})


# ---------------------------------------------------------------------------
# Access Events
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/access-events", methods=["GET"])
def list_access_events(tenant_id):
    conn = get_db()
    identity_id = request.args.get("identity_id")
    resource_id = request.args.get("resource_id")
    outcome = request.args.get("outcome")
    after = request.args.get("after")
    before = request.args.get("before")
    sql = "SELECT * FROM access_events WHERE tenant_id=?"
    vals = [tenant_id]
    if identity_id:
        sql += " AND identity_id=?"
        vals.append(identity_id)
    if resource_id:
        sql += " AND resource_id=?"
        vals.append(resource_id)
    if outcome:
        sql += " AND outcome=?"
        vals.append(outcome)
    if after:
        sql += " AND recorded_at>=?"
        vals.append(after)
    if before:
        sql += " AND recorded_at<=?"
        vals.append(before)
    sql += " ORDER BY recorded_at DESC LIMIT 1000"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify([_json(r) for r in rows])


@app.route("/api/tenants/<tenant_id>/access-events", methods=["POST"])
def create_access_event(tenant_id):
    data = request.get_json(silent=True) or {}
    identity_id = (data.get("identity_id") or "").strip()
    action = (data.get("action") or "").strip()
    outcome = (data.get("outcome") or "granted").strip()
    if not identity_id or not action:
        abort(400, "identity_id and action are required")
    if outcome not in ("granted", "denied", "granted_with_warning", "partially_granted"):
        abort(400, "outcome must be granted|denied|granted_with_warning|partially_granted")
    now = now_iso()
    eid = id_from("ACC", f"{identity_id}{action}{now[:19]}")
    conn = get_db()
    conn.execute(
        """INSERT INTO access_events (id,tenant_id,identity_id,device_id,application_id,resource_id,permission_id,
                                      action,outcome,source_ip,user_agent,session_id,policy_decisions,context,recorded_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (eid, tenant_id,
         identity_id,
         data.get("device_id", ""),
         data.get("application_id", ""),
         data.get("resource_id", ""),
         data.get("permission_id", ""),
         action,
         outcome,
         data.get("source_ip", ""),
         data.get("user_agent", ""),
         data.get("session_id", ""),
         __import__("json").dumps(data.get("policy_decisions", [])),
         __import__("json").dumps(data.get("context", {})),
         now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM access_events WHERE id=?", (eid,)).fetchone()
    result = jsonify(_json(row)), 201

    # --- Wire to Wolf-Pak Security Core ---
    try:
        from pakshield_integration import event_publisher, graph_feeder, mask_redactor

        d = dict(row)
        for k, v in list(d.items()):
            if isinstance(v, str):
                try:
                    parsed = __import__("json").loads(v)
                except (ValueError, TypeError):
                    continue
                if isinstance(parsed, (dict, list)):
                    d[k] = parsed

        dev_id = d.get("device_id") or ""
        pub = event_publisher()
        pub.publish_access_event(
            event_id=d.get("id", eid),
            identity_id=d.get("identity_id", ""),
            device_id=dev_id,
            application_id=d.get("application_id", ""),
            resource_id=d.get("resource_id", ""),
            permission_id=d.get("permission_id", ""),
            decision=d.get("outcome", "granted"),
            reason=d.get("context", {}).get("reason", ""),
            ip_address=d.get("source_ip", ""),
        )

        fed = graph_feeder()
        if identity_id:
            fed.link_identity_device(identity_id=identity_id, device_id=dev_id or "unknown")

        red = mask_redactor()
        _ = red.redact(d)
    except Exception as exc:
        import logging
        logging.getLogger("pakshield.integration").warning(
            "Wolf-Pak Security Core integration skipped for access event %s: %s", eid, exc
        )

    return result


@app.route("/api/tenants/<tenant_id>/access-events/<event_id>", methods=["GET"])
def get_access_event(tenant_id, event_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM access_events WHERE id=?", (event_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "access event not found")
    return jsonify(_json(row))
