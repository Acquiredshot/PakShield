"""
PakShield — Routes: Dashboard, Risk Surface, Effective Access, PDP Evaluate.
"""

from datetime import datetime, timedelta, timezone as _tz

from flask import abort, jsonify, request
from core import app, now_iso, id_from, get_db


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


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/dashboard", methods=["GET"])
def dashboard(tenant_id):
    conn = get_db()
    now = now_iso()
    try:
        day_ago = (datetime.now(_tz.utc) - timedelta(days=1)).isoformat()
    except Exception:
        day_ago = ""

    def cnt(sql, params=()):
        if params:
            return conn.execute(sql, params).fetchone()[0]
        return conn.execute(sql).fetchone()[0]

    counts = {
        "identities": cnt("SELECT COUNT(*) FROM identities WHERE tenant_id=?", (tenant_id,)),
        "users": cnt("SELECT COUNT(*) FROM users"),
        "service_accounts": cnt("SELECT COUNT(*) FROM service_accounts"),
        "groups": cnt("SELECT COUNT(*) FROM groups"),
        "roles": cnt("SELECT COUNT(*) FROM roles"),
        "devices": cnt("SELECT COUNT(*) FROM devices WHERE tenant_id=? AND status='active'", (tenant_id,)),
        "applications": cnt("SELECT COUNT(*) FROM applications WHERE tenant_id=?", (tenant_id,)),
        "resources": cnt("SELECT COUNT(*) FROM resources WHERE tenant_id=?", (tenant_id,)),
        "policies": cnt("SELECT COUNT(*) FROM policies WHERE tenant_id=? AND enabled=1", (tenant_id,)),
        "active_sessions": cnt("SELECT COUNT(*) FROM sessions WHERE tenant_id=? AND status='active'", (tenant_id,)),
        "open_findings": cnt(
            "SELECT COUNT(*) FROM findings WHERE tenant_id=? AND status IN ('open','acknowledged')",
            (tenant_id,),
        ),
        "open_risk_events": cnt(
            "SELECT COUNT(*) FROM risk_events WHERE tenant_id=? AND status='open'",
            (tenant_id,),
        ),
        "active_violations": cnt(
            "SELECT COUNT(*) FROM violations WHERE tenant_id=? AND status='active'",
            (tenant_id,),
        ),
        "pending_remediations": cnt(
            "SELECT COUNT(*) FROM remediation WHERE tenant_id=? AND status='pending'",
            (tenant_id,),
        ),
        "access_events_24h": cnt(
            "SELECT COUNT(*) FROM access_events WHERE tenant_id=? AND recorded_at>=?",
            (tenant_id, day_ago),
        ) if day_ago else 0,
        "denied_access_24h": cnt(
            "SELECT COUNT(*) FROM access_events WHERE tenant_id=? AND outcome='denied' AND recorded_at>=?",
            (tenant_id, day_ago),
        ) if day_ago else 0,
    }

    top_findings = conn.execute(
        """SELECT * FROM findings WHERE tenant_id=? AND status IN ('open','acknowledged')
           ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                    created_at DESC LIMIT 5""",
        (tenant_id,),
    ).fetchall()
    top_violations = conn.execute(
        """SELECT * FROM violations WHERE tenant_id=? AND status='active'
           ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
                    detected_at DESC LIMIT 5""",
        (tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify({
        "counts": counts,
        "top_findings": [_json(r) for r in top_findings],
        "top_violations": [_json(r) for r in top_violations],
    })


# ---------------------------------------------------------------------------
# Risk surface
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/risk-surface", methods=["GET"])
def risk_surface(tenant_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM risk_events WHERE tenant_id=? AND status='open' ORDER BY risk_score DESC LIMIT 50",
        (tenant_id,),
    ).fetchall()
    high_risk_identities = conn.execute(
        """SELECT i.*, u.email, u.failed_logins, u.locked_until
           FROM identities i
           JOIN users u ON u.identity_id=i.id
           WHERE i.type='user' AND (u.failed_logins>=5 OR u.locked_until IS NOT NULL)
           ORDER BY u.failed_logins DESC""",
    ).fetchall()
    stale_credentials = conn.execute(
        """SELECT * FROM credentials WHERE tenant_id=?
           AND (expires_at IS NOT NULL AND expires_at<?) AND status='active'
           ORDER BY expires_at""",
        (tenant_id, now_iso()),
    ).fetchall()
    non_compliant_devices = conn.execute(
        "SELECT * FROM devices WHERE tenant_id=? AND compliance_status='non_compliant' ORDER BY posture_score",
        (tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify({
        "open_risk_events": [_json(r) for r in rows],
        "high_risk_identities": [_json(r) for r in high_risk_identities],
        "stale_credentials": [_json(r) for r in stale_credentials],
        "non_compliant_devices": [_json(r) for r in non_compliant_devices],
    })


# ---------------------------------------------------------------------------
# Effective access — who can do what
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/identity/<identity_id>/effective-access", methods=["GET"])
def effective_access(tenant_id, identity_id):
    conn = get_db()
    r = conn.execute("SELECT * FROM identities WHERE id=?", (identity_id,)).fetchone()
    if not r:
        conn.close()
        abort(404, "identity not found")

    role_ids = set()
    group_ids = set()

    for row in conn.execute(
        "SELECT role_id FROM identity_roles WHERE identity_id=?", (identity_id,),
    ).fetchall():
        role_ids.add(row["role_id"])

    for g in conn.execute(
        """SELECT g.id FROM groups g
           JOIN identity_group_members img ON img.group_id=g.id
           WHERE img.member_id=?""",
        (identity_id,),
    ).fetchall():
        group_ids.add(g["id"])

    if group_ids:
        placeholders = ",".join("?" for _ in group_ids)
        for gr in conn.execute(
            f"SELECT role_id FROM group_roles WHERE group_id IN ({placeholders})",
            list(group_ids),
        ).fetchall():
            role_ids.add(gr["role_id"])

    perm_rows = conn.execute(
        """SELECT DISTINCT p.* FROM permissions p
           JOIN role_permissions rp ON rp.permission_id=p.id
           WHERE rp.role_id IN ({}) ORDER BY p.name""".format(
            ",".join("?" for _ in role_ids)
        ),
        list(role_ids),
    ).fetchall()

    resource_assignments = conn.execute(
        """SELECT p.id, p.name, p.action, p.resource_type, p.resource_id, p.risk_weight
           FROM permissions p
           JOIN role_permissions rp ON rp.permission_id=p.id
           WHERE rp.role_id IN ({}) AND p.resource_id!='' ORDER BY p.name""".format(
            ",".join("?" for _ in role_ids)
        ),
        list(role_ids),
    ).fetchall()
    conn.close()
    return jsonify({
        "identity": _json(r),
        "effective_permissions": [_json(p) for p in perm_rows],
        "assigned_resources": [_json(a) for a in resource_assignments],
    })


# ---------------------------------------------------------------------------
# PDP — Evaluate an access request against policies
# ---------------------------------------------------------------------------

@app.route("/api/tenants/<tenant_id>/evaluate", methods=["POST"])
def evaluate_access(tenant_id):
    data = request.get_json(silent=True) or {}
    identity_id = (data.get("identity_id") or "").strip()
    action = (data.get("action") or "").strip()
    resource_id = (data.get("resource_id") or "").strip()
    if not identity_id or not action:
        abort(400, "identity_id and action are required")

    conn = get_db()
    result = _evaluate(conn, tenant_id, identity_id, action, resource_id, data)
    conn.close()
    return jsonify(result)


def _evaluate(conn, tenant_id, identity_id, action, resource_id, request_data):
    now_dt = datetime.now(_tz.utc)

    irow = conn.execute("SELECT id,type,status FROM identities WHERE id=?", (identity_id,)).fetchone()
    if not irow or irow["status"] != "active":
        return {
            "decision": "denied",
            "reason": "identity not active",
            "identity_id": identity_id,
            "action": action,
            "resource_id": resource_id,
        }

    device_id = request_data.get("device_id") or ""
    posture_score = 1.0
    if device_id:
        drow = conn.execute(
            "SELECT posture_score, compliance_status, encrypted, mfa_capable FROM devices WHERE id=?",
            (device_id,),
        ).fetchone()
        if drow:
            posture_score = drow["posture_score"]
            if drow["compliance_status"] == "non_compliant":
                return {
                    "decision": "denied",
                    "reason": f"device {device_id} is non-compliant",
                    "identity_id": identity_id,
                    "action": action,
                    "resource_id": resource_id,
                    "device_posture": posture_score,
                }
            if drow["encrypted"] == 0:
                posture_score -= 0.2

    role_ids, group_ids = set(), set()
    for r in conn.execute(
        "SELECT role_id FROM identity_roles WHERE identity_id=?", (identity_id,),
    ).fetchall():
        role_ids.add(r["role_id"])
    for g in conn.execute(
        """SELECT g.id FROM groups g
           JOIN identity_group_members img ON img.group_id=g.id
           WHERE img.member_id=?""",
        (identity_id,),
    ).fetchall():
        group_ids.add(g["id"])
    if group_ids:
        ph = ",".join("?" for _ in group_ids)
        for gr in conn.execute(
            f"SELECT role_id FROM group_roles WHERE group_id IN ({ph})", list(group_ids),
        ).fetchall():
            role_ids.add(gr["role_id"])

    effective_perms = set()
    for r in role_ids:
        for p in conn.execute(
            "SELECT permission_id FROM role_permissions WHERE role_id=?", (r,),
        ).fetchall():
            effective_perms.add(p["permission_id"])

    perm_match = False
    perm_detail = None
    if resource_id:
        for pid in effective_perms:
            prow = conn.execute("SELECT * FROM permissions WHERE id=?", (pid,)).fetchone()
            if prow and prow["action"] == action and (
                prow["resource_type"] == "" or prow["resource_type"] is None
                or prow["resource_id"] == resource_id or prow["resource_id"] == ""
            ):
                perm_match = True
                perm_detail = {"permission_id": pid, "name": prow["name"], "action": prow["action"]}
                break

    decisions = []
    for pol in conn.execute(
        "SELECT * FROM policies WHERE tenant_id=? AND enabled=1 ORDER BY priority, id",
        (tenant_id,),
    ).fetchall():
        condition = pol["condition"]
        if isinstance(condition, str):
            try:
                condition = __import__("json").loads(condition)
            except (ValueError, TypeError):
                continue

        d = _eval_policy(
            conn, pol, condition, identity_id, action, resource_id,
            device_id, posture_score, now_dt, request_data,
            effective_perms, role_ids, group_ids,
        )
        decisions.append(d)
        if d["effect"] == "deny":
            return {
                "decision": "denied",
                "reason": f"policy '{pol['name']}' blocked access",
                "policy": {"id": pol["id"], "name": pol["name"], "type": pol["policy_type"], "effect": "deny"},
                "policy_decisions": decisions,
                "identity_id": identity_id,
                "action": action,
                "resource_id": resource_id,
                "device_posture": posture_score,
                "effective_permissions": list(effective_perms),
            }

    if perm_match or not resource_id:
        return {
            "decision": "granted",
            "reason": "access granted",
            "policy_decisions": decisions,
            "identity_id": identity_id,
            "action": action,
            "resource_id": resource_id,
            "device_posture": posture_score,
            "effective_permissions": list(effective_perms),
            "matched_permission": perm_detail,
        }

    return {
        "decision": "denied",
        "reason": f"no permission covers {action} on {resource_id}",
        "identity_id": identity_id,
        "action": action,
        "resource_id": resource_id,
        "policy_decisions": decisions,
        "device_posture": posture_score,
        "effective_permissions": list(effective_perms),
    }


def _eval_policy(conn, pol, condition, identity_id, action, resource_id,
                 device_id, posture_score, now_dt, request_data,
                 effective_perms, role_ids, group_ids):
    effect = pol["effect"]
    pol_type = pol["policy_type"]

    if pol_type == "mfa":
        mfa_verified = bool(request_data.get("mfa_verified", True))
        privilege_actions = {"admin", "write", "manage", "delete", "impersonate", "execute"}
        is_privileged = (
            action in privilege_actions
            or (resource_id and conn.execute(
                "SELECT classification FROM resources WHERE id=?", (resource_id,)
            ).fetchone())
        )
        if is_privileged and not mfa_verified:
            return {
                "policy_id": pol["id"],
                "name": pol["name"],
                "effect": "deny",
                "matched": True,
                "reason": "MFA required for privileged access",
            }

    if pol_type == "access_control":
        if "role" in condition:
            allowed = condition["role"]
            if isinstance(allowed, str):
                allowed = [allowed]
            if role_ids.isdisjoint(set(allowed)):
                return {
                    "policy_id": pol["id"],
                    "name": pol["name"],
                    "effect": "deny",
                    "matched": True,
                    "reason": f"role not allowed ({allowed})",
                }

        if "classification" in condition and resource_id:
            res = conn.execute("SELECT classification FROM resources WHERE id=?", (resource_id,)).fetchone()
            if res and res["classification"] != condition["classification"]:
                return {
                    "policy_id": pol["id"],
                    "name": pol["name"],
                    "effect": "deny",
                    "matched": True,
                    "reason": "resource classification mismatch",
                }

        if "hour" in condition:
            h = now_dt.hour
            hc = condition["hour"]
            blocked = False
            if "ge" in hc and h < hc["ge"]:
                blocked = True
            if "le" in hc and h > hc["le"]:
                blocked = True
            if "or" in hc:
                inner = hc["or"]
                if ("ge" in inner and h < inner["ge"]) or ("le" in inner and h > inner["le"]):
                    blocked = True
            if blocked:
                return {
                    "policy_id": pol["id"],
                    "name": pol["name"],
                    "effect": effect,
                    "matched": True,
                    "reason": f"outside allowed hours ({h}:00)",
                }

        if "resource_type" in condition and resource_id:
            res_type = conn.execute("SELECT resource_type FROM resources WHERE id=?", (resource_id,)).fetchone()
            if res_type and res_type["resource_type"] != condition["resource_type"]:
                return {
                    "policy_id": pol["id"],
                    "name": pol["name"],
                    "effect": effect,
                    "matched": True,
                    "reason": "resource type not in scope",
                }

        if effect == "deny":
            return {
                "policy_id": pol["id"],
                "name": pol["name"],
                "effect": "deny",
                "matched": False,
                "reason": "policy did not apply",
            }

    if pol_type == "device_posture":
        threshold = condition.get("posture_score", {}).get("lt", 0)
        if posture_score < threshold:
            return {
                "policy_id": pol["id"],
                "name": pol["name"],
                "effect": "deny",
                "matched": True,
                "reason": f"device posture {posture_score:.2f} < {threshold}",
            }

    if pol_type == "password":
        identity_creds = conn.execute(
            "SELECT id, last_rotated_at FROM credentials WHERE identity_id=?",
            (identity_id,),
        ).fetchall()
        age_threshold = condition.get("credential_age_days", {}).get("gt", 90)
        for c in identity_creds:
            if c["last_rotated_at"]:
                try:
                    rotated = datetime.fromisoformat(c["last_rotated_at"])
                    age_days = (now_dt - rotated).days
                    if age_days > age_threshold:
                        return {
                            "policy_id": pol["id"],
                            "name": pol["name"],
                            "effect": "audit",
                            "matched": True,
                            "reason": f"credential aged > {age_threshold} days",
                            "credential_ids": [c["id"] for c in identity_creds],
                        }
                except (ValueError, TypeError):
                    pass

    if effect == "allow" and pol_type == "access_control":
        return {
            "policy_id": pol["id"],
            "name": pol["name"],
            "effect": "allow",
            "matched": False,
            "reason": "policy conditions not met",
        }

    return {
        "policy_id": pol["id"],
        "name": pol["name"],
        "effect": effect,
        "matched": True,
        "reason": "policy evaluated",
    }
