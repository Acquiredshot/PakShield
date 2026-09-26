"""
PakShield — REST API surface.
Replaces the CRM skeleton with the Identity, Access & Privilege Intelligence Engine.
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
# Tenant
# ---------------------------------------------------------------------------

@app.route("/api/tenants", methods=["GET"])
def list_tenants():
    conn = get_db()
    rows = conn.execute("SELECT * FROM tenants ORDER BY created_at").fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants", methods=["POST"])
def create_tenant():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    slug = (data.get("slug") or "").strip().lower()
    domain = (data.get("domain") or "").strip()
    settings = __import__("json").dumps(data.get("settings", {}))
    if not name or not slug:
        abort(400, "name and slug are required")
    now = now_iso()
    tid = id_from("TENANT", slug)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO tenants (id,name,slug,domain,settings,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            (tid, name, slug, domain, settings, now, now),
        )
        conn.commit()
    except Exception:
        conn.close()
        abort(409, "slug already exists")
    conn.close()
    row = conn.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>", methods=["GET"])
def get_tenant(tenant_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
    conn.close()
    if not row:
        abort(404, "tenant not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>", methods=["PATCH"])
def patch_tenant(tenant_id):
    data = request.get_json(silent=True) or {}
    updates, vals = [], []
    for col in ("name", "domain", "status"):
        if col in data:
            updates.append(f"{col}=?")
            vals.append(data[col] if data[col] is not None else None)
    if "settings" in data:
        updates.append("settings=?")
        vals.append(__import__("json").dumps(data["settings"]))
    if not updates:
        abort(400, "no fields to update")
    updates.append("updated_at=?")
    vals.append(now_iso())
    vals.append(tenant_id)
    conn = get_db()
    conn.execute(f"UPDATE tenants SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    row = conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
    conn.close()
    return jsonify(_json(row))


# ---------------------------------------------------------------------------
# Identities — Users / Service Accounts / Groups / Roles
# ---------------------------------------------------------------------------

IDENTITY_TYPES = {"user", "service_account", "group", "role"}


@app.route("/api/tenants/<tenant_id>/identities", methods=["GET"])
def list_identities(tenant_id):
    conn = get_db()
    rows = conn.execute(
        """SELECT i.*, u.email, u.department, u.job_title, u.manager_id,
                  u.failed_logins, u.locked_until, u.last_seen_at,
                  sa.account_type, sa.owner_id, sa.expiry_at, sa.last_used_at, sa.rotation_required,
                  g.parent_group_id, g.group_type,
                  r.role_type, r.scope, r.inherit_from
           FROM identities i
           LEFT JOIN users u ON u.identity_id=i.id
           LEFT JOIN service_accounts sa ON sa.identity_id=i.id
           LEFT JOIN groups g ON g.identity_id=i.id
           LEFT JOIN roles r ON r.identity_id=i.id
           WHERE i.tenant_id=? ORDER BY i.type, i.display_name""",
        (tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify(_paginate(rows))


@app.route("/api/tenants/<tenant_id>/identities/<identity_type>", methods=["POST"])
def create_identity(tenant_id, identity_type):
    if identity_type not in IDENTITY_TYPES:
        abort(400, f"identity_type must be one of {IDENTITY_TYPES}")
    data = request.get_json(silent=True) or {}
    display_name = (data.get("display_name") or "").strip()
    description = data.get("description", "")
    if not display_name:
        abort(400, "display_name is required")
    now = now_iso()
    iid = id_from("ID", display_name + now[:19])
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO identities (id,tenant_id,type,display_name,description,status,metadata,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (iid, tenant_id, identity_type, display_name, description, "active", "{}", now, now),
        )
        if identity_type == "user":
            conn.execute(
                "INSERT INTO users (id,identity_id,email,phone,department,job_title,last_seen_at,failed_logins) VALUES (?,?,?,?,?,?,?,?)",
                (iid, iid,
                 (data.get("email") or "").strip(),
                 (data.get("phone") or "").strip(),
                 (data.get("department") or "").strip(),
                 (data.get("job_title") or "").strip(),
                 now, 0),
            )
        elif identity_type == "service_account":
            conn.execute(
                "INSERT INTO service_accounts (id,identity_id,account_type,owner_id,expiry_at,rotation_required) VALUES (?,?,?,?,?,?)",
                (iid, iid,
                 data.get("account_type", "machine"),
                 data.get("owner_id", ""),
                 data.get("expiry_at", ""),
                 1 if data.get("rotation_required") else 0),
            )
        elif identity_type == "group":
            conn.execute(
                "INSERT INTO groups (id,identity_id,parent_group_id,group_type) VALUES (?,?,?,?)",
                (iid, iid,
                 data.get("parent_group_id", ""),
                 data.get("group_type", "security")),
            )
        elif identity_type == "role":
            conn.execute(
                "INSERT INTO roles (id,identity_id,role_type,scope) VALUES (?,?,?,?)",
                (iid, iid,
                 data.get("role_type", "custom"),
                 data.get("scope", "")),
            )
        conn.commit()
    except Exception:
        conn.close()
        abort(409, "display_name collision or invalid reference")
    conn.close()
    row = conn.execute(
        """SELECT i.*, u.email, u.department, u.job_title, u.manager_id,
                  u.failed_logins, u.locked_until, u.last_seen_at,
                  sa.account_type, sa.owner_id, sa.expiry_at, sa.last_used_at, sa.rotation_required,
                  g.parent_group_id, g.group_type,
                  r.role_type, r.scope, r.inherit_from
           FROM identities i
           LEFT JOIN users u ON u.identity_id=i.id
           LEFT JOIN service_accounts sa ON sa.identity_id=i.id
           LEFT JOIN groups g ON g.identity_id=i.id
           LEFT JOIN roles r ON r.identity_id=i.id
           WHERE i.id=?""",
        (iid,),
    ).fetchone()
    return jsonify(_json(row)), 201


@app.route("/api/tenants/<tenant_id>/identities/<identity_id>", methods=["GET"])
def get_identity(tenant_id, identity_id):
    conn = get_db()
    row = conn.execute(
        """SELECT i.*, u.email, u.department, u.job_title, u.manager_id,
                  u.failed_logins, u.locked_until, u.last_seen_at,
                  sa.account_type, sa.owner_id, sa.expiry_at, sa.last_used_at, sa.rotation_required,
                  g.parent_group_id, g.group_type,
                  r.role_type, r.scope, r.inherit_from
           FROM identities i
           LEFT JOIN users u ON u.identity_id=i.id
           LEFT JOIN service_accounts sa ON sa.identity_id=i.id
           LEFT JOIN groups g ON g.identity_id=i.id
           LEFT JOIN roles r ON r.identity_id=i.id
           WHERE i.id=?""",
        (identity_id,),
    ).fetchone()
    conn.close()
    if not row:
        abort(404, "identity not found")
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/identities/<identity_id>", methods=["PATCH"])
def patch_identity(tenant_id, identity_id):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    irow = conn.execute("SELECT type FROM identities WHERE id=?", (identity_id,)).fetchone()
    if not irow:
        conn.close()
        abort(404, "identity not found")
    itype = irow["type"]

    core_upd = []
    core_val = []
    for col in ("display_name", "description", "status"):
        if col in data and data[col] is not None:
            core_upd.append(f"{col}=?")
            core_val.append(data[col])
    if "metadata" in data:
        core_upd.append("metadata=?")
        core_val.append(__import__("json").dumps(data["metadata"]))
    if core_upd:
        core_upd.append("updated_at=?")
        core_val.append(now_iso())
        core_val.append(identity_id)
        conn.execute(f"UPDATE identities SET {','.join(core_upd)} WHERE id=?", core_val)

    sub = data.get(itype, data) or {}
    if itype == "user":
        for col in ("email", "phone", "department", "job_title", "locked_until", "last_seen_at", "manager_id"):
            if col in sub:
                conn.execute(f"UPDATE users SET {col}=? WHERE identity_id=?", (sub[col], identity_id))
        if "failed_logins" in sub:
            conn.execute("UPDATE users SET failed_logins=? WHERE identity_id=?", (sub["failed_logins"], identity_id))
    elif itype == "service_account":
        for col in ("account_type", "owner_id", "expiry_at", "rotation_required", "last_used_at"):
            if col in sub:
                conn.execute(f"UPDATE service_accounts SET {col}=? WHERE identity_id=?", (sub[col], identity_id))
    elif itype == "group":
        for col in ("parent_group_id", "group_type"):
            if col in sub:
                conn.execute(f"UPDATE groups SET {col}=? WHERE identity_id=?", (sub[col], identity_id))
    elif itype == "role":
        for col in ("role_type", "scope", "inherit_from"):
            if col in sub:
                conn.execute(f"UPDATE roles SET {col}=? WHERE identity_id=?", (sub[col], identity_id))

    conn.commit()
    row = conn.execute(
        """SELECT i.*, u.email, u.department, u.job_title, u.manager_id,
                  u.failed_logins, u.locked_until, u.last_seen_at,
                  sa.account_type, sa.owner_id, sa.expiry_at, sa.last_used_at, sa.rotation_required,
                  g.parent_group_id, g.group_type,
                  r.role_type, r.scope, r.inherit_from
           FROM identities i
           LEFT JOIN users u ON u.identity_id=i.id
           LEFT JOIN service_accounts sa ON sa.identity_id=i.id
           LEFT JOIN groups g ON g.identity_id=i.id
           LEFT JOIN roles r ON r.identity_id=i.id
           WHERE i.id=?""",
        (identity_id,),
    ).fetchone()
    conn.close()
    return jsonify(_json(row))


@app.route("/api/tenants/<tenant_id>/identities/<identity_id>", methods=["DELETE"])
def delete_identity(tenant_id, identity_id):
    conn = get_db()
    conn.execute("DELETE FROM identities WHERE id=?", (identity_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": identity_id})


# ---------------------------------------------------------------------------
# Group membership
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/groups/<group_id>/members", methods=["GET"])
def list_group_members(tenant_id, group_id):
    conn = get_db()
    rows = conn.execute(
        """SELECT img.group_id, img.member_id, img.joined_at,
                  i.type, i.display_name, i.status
           FROM identity_group_members img
           JOIN identities i ON i.id=img.member_id
           WHERE img.group_id=? ORDER BY img.joined_at""",
        (group_id,),
    ).fetchall()
    conn.close()
    return jsonify([_json(r) for r in rows])


@app.route("/api/tenants/<tenant_id>/groups/<group_id>/members", methods=["POST"])
def add_group_member(tenant_id, group_id):
    data = request.get_json(silent=True) or {}
    member_id = (data.get("member_id") or "").strip()
    if not member_id:
        abort(400, "member_id is required")
    now = now_iso()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO identity_group_members (group_id,member_id,joined_at) VALUES (?,?,?)",
            (group_id, member_id, now),
        )
        conn.commit()
    except Exception:
        conn.close()
        abort(409, "member already in group")
    conn.close()
    return jsonify({"status": "added", "group_id": group_id, "member_id": member_id, "joined_at": now}), 201


@app.route("/api/tenants/<tenant_id>/groups/<group_id>/members/<member_id>", methods=["DELETE"])
def remove_group_member(tenant_id, group_id, member_id):
    conn = get_db()
    conn.execute("DELETE FROM identity_group_members WHERE group_id=? AND member_id=?", (group_id, member_id))
    if conn.total_changes == 0:
        conn.close()
        abort(404, "member not in group")
    conn.commit()
    conn.close()
    return jsonify({"status": "removed", "group_id": group_id, "member_id": member_id})


# ---------------------------------------------------------------------------
# Role membership & permission grants
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/roles/<role_id>/permissions", methods=["GET"])
def list_role_permissions(tenant_id, role_id):
    conn = get_db()
    rows = conn.execute(
        """SELECT rp.role_id, rp.permission_id, rp.granted_at,
                  p.name, p.action, p.resource_type, p.risk_weight
           FROM role_permissions rp
           JOIN permissions p ON p.id=rp.permission_id
           WHERE rp.role_id=? ORDER BY p.name""",
        (role_id,),
    ).fetchall()
    conn.close()
    return jsonify([_json(r) for r in rows])


@app.route("/api/tenants/<tenant_id>/roles/<role_id>/permissions", methods=["POST"])
def grant_permission_to_role(tenant_id, role_id):
    data = request.get_json(silent=True) or {}
    perm_id = (data.get("permission_id") or "").strip()
    if not perm_id:
        abort(400, "permission_id is required")
    now = now_iso()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO role_permissions (role_id,permission_id,granted_at) VALUES (?,?,?)",
            (role_id, perm_id, now),
        )
        conn.commit()
    except Exception:
        conn.close()
        abort(409, "permission already granted")
    conn.close()
    return jsonify({"status": "granted", "role_id": role_id, "permission_id": perm_id}), 201


@app.route("/api/tenants/<tenant_id>/roles/<role_id>/permissions/<perm_id>", methods=["DELETE"])
def revoke_permission_from_role(tenant_id, role_id, perm_id):
    conn = get_db()
    conn.execute(
        "DELETE FROM role_permissions WHERE role_id=? AND permission_id=?",
        (role_id, perm_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "revoked", "role_id": role_id, "permission_id": perm_id})


@app.route("/api/tenants/<tenant_id>/identities/<identity_id>/roles", methods=["GET"])
def list_identity_roles(tenant_id, identity_id):
    conn = get_db()
    rows = conn.execute(
        """SELECT ir.identity_id, ir.role_id, ir.granted_at, ir.granted_by, ir.expires_at,
                  r.display_name as role_name, r.role_type, r.scope
           FROM identity_roles ir
           JOIN identities r ON r.id=ir.role_id
           WHERE ir.identity_id=? ORDER BY ir.granted_at""",
        (identity_id,),
    ).fetchall()
    conn.close()
    return jsonify([_json(r) for r in rows])


@app.route("/api/tenants/<tenant_id>/identities/<identity_id>/roles", methods=["POST"])
def grant_role_to_identity(tenant_id, identity_id):
    data = request.get_json(silent=True) or {}
    role_id = (data.get("role_id") or "").strip()
    if not role_id:
        abort(400, "role_id is required")
    now = now_iso()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO identity_roles (identity_id,role_id,granted_at,granted_by,expires_at) VALUES (?,?,?,?,?)",
            (identity_id, role_id, now,
             data.get("granted_by", ""),
             data.get("expires_at", "")),
        )
        conn.commit()
    except Exception:
        conn.close()
        abort(409, "role already granted")
    conn.close()
    return jsonify({"status": "granted", "identity_id": identity_id, "role_id": role_id, "granted_at": now}), 201


@app.route("/api/tenants/<tenant_id>/identities/<identity_id>/roles/<role_id>", methods=["DELETE"])
def revoke_role_from_identity(tenant_id, identity_id, role_id):
    conn = get_db()
    conn.execute(
        "DELETE FROM identity_roles WHERE identity_id=? AND role_id=?",
        (identity_id, role_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "revoked", "identity_id": identity_id, "role_id": role_id})


@app.route("/api/tenants/<tenant_id>/groups/<group_id>/roles", methods=["GET"])
def list_group_roles(tenant_id, group_id):
    conn = get_db()
    rows = conn.execute(
        """SELECT gr.group_id, gr.role_id, gr.granted_at,
                  r.display_name as role_name, r.role_type
           FROM group_roles gr
           JOIN identities r ON r.id=gr.role_id
           WHERE gr.group_id=? ORDER BY r.display_name""",
        (group_id,),
    ).fetchall()
    conn.close()
    return jsonify([_json(r) for r in rows])


@app.route("/api/tenants/<tenant_id>/groups/<group_id>/roles", methods=["POST"])
def grant_role_to_group(tenant_id, group_id):
    data = request.get_json(silent=True) or {}
    role_id = (data.get("role_id") or "").strip()
    if not role_id:
        abort(400, "role_id is required")
    now = now_iso()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO group_roles (group_id,role_id,granted_at) VALUES (?,?,?)",
            (group_id, role_id, now),
        )
        conn.commit()
    except Exception:
        conn.close()
        abort(409, "role already granted")
    conn.close()
    return jsonify({"status": "granted", "group_id": group_id, "role_id": role_id}), 201


@app.route("/api/tenants/<tenant_id>/groups/<group_id>/roles/<role_id>", methods=["DELETE"])
def revoke_role_from_group(tenant_id, group_id, role_id):
    conn = get_db()
    conn.execute("DELETE FROM group_roles WHERE group_id=? AND role_id=?", (group_id, role_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "revoked", "group_id": group_id, "role_id": role_id})


