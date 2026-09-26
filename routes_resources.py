"""
PakShield — Routes: Resources, Permissions, Policies.
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
# Resources
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/resources", methods=["GET"])
def list_resources(tenant_id):
    conn = get_db()
    classification = request.args.get("classification")
    sql = "SELECT * FROM resources WHERE tenant_id=?"
    vals = [tenant_id]
    if classification:
        sql += " AND classification=?"
        vals.append(classification)
    sql += " ORDER BY name"
    rows = conn.execute(sql, vals).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/resources", methods=["POST"])
def create_resource(tenant_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort(400, "name is required")
    now = now_iso()
    rid = id_from("RES", name)
    conn = get_db()
    conn.execute(
        """INSERT INTO resources (id,tenant_id,name,description,resource_type,parent_id,classification,
                                  owner_id,application_id,data_class,retention_days,status,metadata,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, tenant_id,
         name,
         data.get("description", ""),
         data.get("resource_type", "other"),
         data.get("parent_id", ""),
         data.get("classification", "internal"),
         data.get("owner_id", ""),
         data.get("application_id", ""),
         data.get("data_class", ""),
         data.get("retention_days", 90),
         data.get("status", "active"),
         __import__("json").dumps(data.get("metadata", {})),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM resources WHERE id=?", (rid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/resources/<resource_id>", methods=["GET"])
def get_resource(tenant_id, resource_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "resource not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/resources/<resource_id>", methods=["PATCH"])
def patch_resource(tenant_id, resource_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in (
        "name", "description", "resource_type", "classification",
        "owner_id", "application_id", "data_class", "retention_days", "status",
    ):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "parent_id" in data:
        updates.append("parent_id=?")
        vals.append(data["parent_id"] or None)
    if "metadata" in data:
        updates.append("metadata=?")
        vals.append(__import__("json").dumps(data["metadata"]))
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(resource_id)
        conn.execute(f"UPDATE resources SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/resources/<resource_id>", methods=["DELETE"])
def delete_resource(tenant_id, resource_id):
    conn = get_db()
    conn.execute("DELETE FROM resources WHERE id=?", (resource_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": resource_id})


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/permissions", methods=["GET"])
def list_permissions(tenant_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM permissions WHERE tenant_id=? ORDER BY name",
        (tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/permissions", methods=["POST"])
def create_permission(tenant_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        abort(400, "name is required")
    now = now_iso()
    pid = id_from("PERM", name)
    conn = get_db()
    conn.execute(
        """INSERT INTO permissions (id,tenant_id,name,description,action,resource_type,resource_id,
                                    scope_expression,risk_weight,status,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, tenant_id,
         name,
         data.get("description", ""),
         data.get("action", "read"),
         data.get("resource_type", ""),
         data.get("resource_id", ""),
         data.get("scope_expression", ""),
         data.get("risk_weight", 1.0),
         data.get("status", "active"),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM permissions WHERE id=?", (pid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/permissions/<permission_id>", methods=["GET"])
def get_permission(tenant_id, permission_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM permissions WHERE id=?", (permission_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "permission not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/permissions/<permission_id>", methods=["PATCH"])
def patch_permission(tenant_id, permission_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in (
        "name", "description", "action", "resource_type", "resource_id",
        "scope_expression", "risk_weight", "status",
    ):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(permission_id)
        conn.execute(f"UPDATE permissions SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM permissions WHERE id=?", (permission_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/permissions/<permission_id>", methods=["DELETE"])
def delete_permission(tenant_id, permission_id):
    conn = get_db()
    conn.execute("DELETE FROM permissions WHERE id=?", (permission_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": permission_id})


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/policies", methods=["GET"])
def list_policies(tenant_id):
    enabled = request.args.get("enabled")
    conn = get_db()
    if enabled is not None:
        rows = conn.execute(
            "SELECT * FROM policies WHERE tenant_id=? AND enabled=? ORDER BY priority, id",
            (tenant_id, int(enabled.lower() in ("1", "true", "yes"))),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM policies WHERE tenant_id=? ORDER BY priority, id",
            (tenant_id,),
        ).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/policies", methods=["POST"])
def create_policy(tenant_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    policy_type = data.get("policy_type", "custom")
    effect = data.get("effect", "allow")
    condition = data.get("condition", "")
    if not name or not condition:
        abort(400, "name and condition are required")
    if effect not in ("allow", "deny", "audit", "remediate"):
        abort(400, "effect must be allow|deny|audit|remediate")
    now = now_iso()
    pid = id_from("POL", name + now[:19])
    conn = get_db()
    conn.execute(
        """INSERT INTO policies (id,tenant_id,name,description,policy_type,effect,condition,action,
                                resource_type,priority,enabled,version,status,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, tenant_id,
         name,
         data.get("description", ""),
         policy_type,
         effect,
         __import__("json").dumps(condition) if not isinstance(condition, str) else condition,
         data.get("action", ""),
         data.get("resource_type", ""),
         data.get("priority", 100),
         1,
         "1.0.0",
         data.get("status", "active"),
         now, now),
    )
    conn.commit()
    conn.close()
    row = conn.execute("SELECT * FROM policies WHERE id=?", (pid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/policies/<policy_id>", methods=["GET"])
def get_policy(tenant_id, policy_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "policy not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/policies/<policy_id>", methods=["PATCH"])
def patch_policy(tenant_id, policy_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    updates, vals = [], []
    for col in (
        "name", "description", "policy_type", "effect", "action",
        "resource_type", "priority", "enabled", "version", "status",
    ):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col])
    if "condition" in data:
        updates.append("condition=?")
        vals.append(
            __import__("json").dumps(data["condition"])
            if not isinstance(data["condition"], str)
            else data["condition"]
        )
    if updates:
        updates.append("updated_at=?")
        vals.append(now_iso())
        vals.append(policy_id)
        conn.execute(f"UPDATE policies SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/policies/<policy_id>", methods=["DELETE"])
def delete_policy(tenant_id, policy_id):
    conn = get_db()
    conn.execute("DELETE FROM policies WHERE id=?", (policy_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": policy_id})
