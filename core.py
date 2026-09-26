"""
PakShield — Wolf-Pak's Identity, Access & Privilege Intelligence Engine.

Answers: "Who is responsible, what can they access, what should they be able
to access, and how risky is that identity/access relationship?"

Data model (all per-tenant):
  Tenant
  ├── Identity → User | ServiceAccount | Group | Role
  ├── Device
  ├── Application
  ├── Resource
  ├── Permission
  ├── Policy
  ├── Credential
  ├── Session
  ├── AccessEvent
  ├── RiskEvent
  ├── Finding
  ├── Violation
  └── Remediation
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, List, Optional

from flask import Flask, abort, jsonify, request, render_template

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pakshield.db")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def id_from(prefix: str, raw: str) -> str:
    """Stable short id from arbitrary input (deterministic, not Guessable)."""
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Schema — created once, idempotent
# ---------------------------------------------------------------------------

def init_db() -> None:
    conn = get_db()
    _create_tables(conn)
    if conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0] == 0:
        _seed_tenant(conn)
    if DEMO_MODE:
        _seed_demo(conn)
    conn.close()


def _create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        DROP TABLE IF EXISTS remediation;
        DROP TABLE IF EXISTS violations;
        DROP TABLE IF EXISTS findings;
        DROP TABLE IF EXISTS risk_events;
        DROP TABLE IF EXISTS access_events;
        DROP TABLE IF EXISTS sessions;
        DROP TABLE IF EXISTS credentials;
        DROP TABLE IF EXISTS policies;
        DROP TABLE IF EXISTS permissions;
        DROP TABLE IF EXISTS resources;
        DROP TABLE IF EXISTS applications;
        DROP TABLE IF EXISTS devices;
        DROP TABLE IF EXISTS identity_group_members;
        DROP TABLE IF EXISTS group_roles;
        DROP TABLE IF EXISTS role_permissions;
        DROP TABLE IF EXISTS identity_roles;
        DROP TABLE IF EXISTS service_accounts;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS groups;
        DROP TABLE IF EXISTS roles;
        DROP TABLE IF EXISTS identities;
        DROP TABLE IF EXISTS tenants;

        CREATE TABLE tenants (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            slug         TEXT UNIQUE NOT NULL,
            domain       TEXT,
            status       TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','deleted')),
            settings     TEXT,                       -- JSON blob
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );

        CREATE TABLE identities (
            id           TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            type         TEXT NOT NULL CHECK(type IN ('user','service_account','group','role')),
            display_name TEXT NOT NULL,
            description  TEXT,
            status       TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),
            metadata     TEXT,                       -- JSON blob
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );

        CREATE TABLE users (
            id              TEXT PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
            identity_id     TEXT NOT NULL UNIQUE REFERENCES identities(id) ON DELETE CASCADE,
            email           TEXT UNIQUE,
            phone           TEXT,
            department      TEXT,
            job_title       TEXT,
            manager_id      TEXT REFERENCES identities(id),
            last_seen_at    TEXT,
            failed_logins   INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT
        );

        CREATE TABLE service_accounts (
            id              TEXT PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
            identity_id     TEXT NOT NULL UNIQUE REFERENCES identities(id) ON DELETE CASCADE,
            account_type    TEXT NOT NULL,          -- 'machine', 'api_key', 'oauth_app', 'workload'
            owner_id        TEXT REFERENCES identities(id),
            expiry_at       TEXT,
            last_used_at    TEXT,
            rotation_required INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE groups (
            id              TEXT PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
            identity_id     TEXT NOT NULL UNIQUE REFERENCES identities(id) ON DELETE CASCADE,
            parent_group_id TEXT REFERENCES groups(id),
            group_type      TEXT NOT NULL DEFAULT 'security' CHECK(group_type IN ('security','distribution','dynamic'))
        );

        CREATE TABLE roles (
            id              TEXT PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
            identity_id     TEXT NOT NULL UNIQUE REFERENCES identities(id) ON DELETE CASCADE,
            role_type       TEXT NOT NULL DEFAULT 'custom' CHECK(role_type IN ('builtin','custom','scoped','hybrid')),
            scope           TEXT,                    -- e.g. 'tenant','/app/foo','resource:xyz'
            inherit_from    TEXT REFERENCES roles(id)
        );

        CREATE TABLE identity_group_members (
            group_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            member_id   TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
            joined_at   TEXT NOT NULL,
            PRIMARY KEY (group_id, member_id)
        );

        CREATE TABLE group_roles (
            group_id     TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            role_id      TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            granted_at   TEXT NOT NULL,
            PRIMARY KEY (group_id, role_id)
        );

        CREATE TABLE role_permissions (
            role_id         TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            permission_id   TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
            granted_at      TEXT NOT NULL,
            PRIMARY KEY (role_id, permission_id)
        );

        CREATE TABLE identity_roles (
            identity_id  TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
            role_id      TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            granted_at   TEXT NOT NULL,
            granted_by   TEXT,
            expires_at   TEXT,
            PRIMARY KEY (identity_id, role_id)
        );

        CREATE TABLE devices (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
            name            TEXT NOT NULL,
            device_type     TEXT NOT NULL CHECK(device_type IN ('workstation','mobile','server','iot','network','cloud_vm','container','virtual')),
            os              TEXT,
            os_version      TEXT,
            hostname        TEXT,
            ip_address      TEXT,
            mac_address     TEXT,
            serial          TEXT,
            platform        TEXT,                    -- 'windows','linux','macos','ios','android','unknown'
            posture_score   REAL NOT NULL DEFAULT 1.0,
            compliance_status TEXT NOT NULL DEFAULT 'unknown' CHECK(compliance_status IN ('compliant','non_compliant','unknown','remediated')),
            encrypted       INTEGER NOT NULL DEFAULT 0,
            mfa_capable     INTEGER NOT NULL DEFAULT 0,
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','quarantined','retired','lost')),
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE applications (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            description     TEXT,
            type            TEXT NOT NULL CHECK(type IN ('web','api','desktop','mobile','cli','service','saas')),
            vendor          TEXT,
            version         TEXT,
            url             TEXT,
            protocol        TEXT,                    -- 'oauth2','saml','kerberos','ldap','none'
            auth_method     TEXT,                    -- 'oidc','saml','basic','certificate','none'
            risk_rating     TEXT NOT NULL DEFAULT 'unknown' CHECK(risk_rating IN ('critical','high','medium','low','unknown')),
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','decommissioned','deprecated')),
            metadata        TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE resources (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            description     TEXT,
            resource_type   TEXT NOT NULL CHECK(resource_type IN ('database','api','filesystem','bucket','queue','topic','kms_key','secret','vm','container','network','registry','function','other')),
            parent_id       TEXT REFERENCES resources(id),
            classification  TEXT NOT NULL DEFAULT 'internal' CHECK(classification IN ('public','internal','confidential','restricted','privileged')),
            owner_id        TEXT REFERENCES identities(id),
            application_id  TEXT REFERENCES applications(id),
            data_class      TEXT,
            retention_days  INTEGER,
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived','deleted')),
            metadata        TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE permissions (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            description     TEXT,
            action          TEXT NOT NULL,           -- 'read','write','delete','admin','execute','manage','impersonate'
            resource_type   TEXT,                    -- scopes the permission to a resource type
            resource_id     TEXT,                    -- optional specific resource
            scope_expression TEXT,                   -- CEL-like or regex scope
            risk_weight     REAL NOT NULL DEFAULT 1.0,
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','deprecated','revoked')),
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE policies (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            description     TEXT,
            policy_type     TEXT NOT NULL CHECK(policy_type IN ('access_control','password','mfa','device_posture','data_classification','session','dangerous_action','anomaly','retention','custom')),
            effect          TEXT NOT NULL CHECK(effect IN ('allow','deny','audit','remediate')),
            condition       TEXT NOT NULL,           -- JSON or CEL expression
            action          TEXT,                     -- which action types this governs
            resource_type   TEXT,
            priority        INTEGER NOT NULL DEFAULT 100,
            enabled         INTEGER NOT NULL DEFAULT 1,
            version         TEXT NOT NULL DEFAULT '1.0.0',
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deprecated','draft')),
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE credentials (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
            device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
            name            TEXT NOT NULL,
            credential_type TEXT NOT NULL CHECK(credential_type IN ('password','ssh_key','x509_cert','api_key','oauth_token','saml_assertion','kerberos_ticket','hardware_token','recovery_code','badge','certificate_chain')),
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','expired','revoked','compromised')),
            strength_score  REAL,
            encrypted       INTEGER NOT NULL DEFAULT 0,
            last_rotated_at TEXT,
            expires_at      TEXT,
            next_rotation_at TEXT,
            fingerprint     TEXT,                    -- sha256/sshfp for keys
            metadata        TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE sessions (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            identity_id     TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
            device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
            credential_id   TEXT REFERENCES credentials(id) ON DELETE SET NULL,
            application_id  TEXT REFERENCES applications(id) ON DELETE SET NULL,
            auth_method     TEXT,
            started_at      TEXT NOT NULL,
            last_active_at  TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            ip_address      TEXT,
            user_agent      TEXT,
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','revoked','suspended','locked')),
            risk_score      REAL NOT NULL DEFAULT 0.0,
            mfa_verified    INTEGER NOT NULL DEFAULT 0,
            properties      TEXT
        );

        CREATE TABLE access_events (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            identity_id     TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
            device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
            application_id  TEXT REFERENCES applications(id) ON DELETE SET NULL,
            resource_id     TEXT REFERENCES resources(id) ON DELETE SET NULL,
            permission_id   TEXT REFERENCES permissions(id) ON DELETE SET NULL,
            action          TEXT NOT NULL,
            outcome         TEXT NOT NULL CHECK(outcome IN ('granted','denied','granted_with_warning','partially_granted')),
            source_ip       TEXT,
            user_agent      TEXT,
            session_id      TEXT,
            policy_decisions TEXT,                   -- JSON array of policy evaluations
            context         TEXT,                    -- JSON blob
            recorded_at     TEXT NOT NULL
        );

        CREATE TABLE risk_events (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
            device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
            application_id  TEXT REFERENCES applications(id) ON DELETE SET NULL,
            source          TEXT NOT NULL,           -- 'anomaly_score','policy_violation','credential_leak','impossible_travel','impossible_time','privilege_escalation','lateral_movement',' anomalous_behavior','threat_intel','manual'
            severity        TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
            risk_score      REAL NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT,
            indicators      TEXT,                    -- JSON
            related_event_id TEXT,
            status          TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','mitigated','accepted','false_positive','closed')),
            created_at      TEXT NOT NULL
        );

        CREATE TABLE findings (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            risk_event_id   TEXT REFERENCES risk_events(id) ON DELETE SET NULL,
            identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
            device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
            title           TEXT NOT NULL,
            description     TEXT,
            category        TEXT NOT NULL CHECK(category IN ('overprivileged','stale_credential','dormant_account','mfa_gap','unencrypted_device','policy_violation','anomalous_access','orphan_resource','separation_of_duties','credential_exposure','shadow_it','other')),
            severity        TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
            confidence      REAL NOT NULL DEFAULT 1.0,
            status          TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','investigating','remediated','accepted','false_positive','closed')),
            recommendation  TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE violations (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            finding_id      TEXT REFERENCES findings(id) ON DELETE SET NULL,
            policy_id       TEXT REFERENCES policies(id) ON DELETE SET NULL,
            identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
            device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL,
            resource_id     TEXT REFERENCES resources(id) ON DELETE SET NULL,
            action          TEXT NOT NULL,
            violation_type  TEXT NOT NULL CHECK(violation_type IN ('policy_violation','access_denied_bypass','privilege_escalation','credential_misuse','device_compromise','data_exfiltration','anomalous_behavior','impossible_travel','off_hours_access','separation_of_duties','other')),
            severity        TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
            evidence        TEXT,                     -- JSON
            description     TEXT,
            detected_at     TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','contained','remediated','accepted','closed')),
            created_at      TEXT NOT NULL
        );

        CREATE TABLE remediation (
            id              TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            violation_id    TEXT REFERENCES violations(id) ON DELETE SET NULL,
            finding_id      TEXT REFERENCES findings(id) ON DELETE SET NULL,
            risk_event_id   TEXT REFERENCES risk_events(id) ON DELETE SET NULL,
            identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
            assigned_to     TEXT REFERENCES identities(id),
            action_type     TEXT NOT NULL CHECK(action_type IN ('revoke_access','disable_account','rotate_credential','quarantine_device','enforce_mfa','apply_policy','escalate','accept_risk','close','other')),
            action_details  TEXT,
            status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','in_progress','completed','failed','reopened')),
            requested_at    TEXT NOT NULL,
            completed_at    TEXT,
            created_at      TEXT NOT NULL
        );
    """)


def _seed_tenant(conn: sqlite3.Connection) -> None:
    now = now_iso()
    tid = "TENANT-WOLF-PAK"
    conn.execute(
        "INSERT INTO tenants (id,name,slug,domain,settings,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
        (tid, "Wolf-Pak", "wolf-pak", "wolf-pak.local", "{}", now, now),
    )
    conn.commit()


def _seed_demo(conn: sqlite3.Connection) -> None:
    """One tenant, a handful of identities, devices, apps, resources, policies,
    and a few seeded events/findings/violations/remediations to make the UI useful."""
    now = now_iso()
    trow = conn.execute("SELECT id FROM tenants LIMIT 1").fetchone()
    if not trow:
        return
    tid = trow["id"]

    # --- Identities ---
    def make_identity(itype: str, display_name: str, **extra) -> str:
        iid = id_from("ID", display_name)
        conn.execute(
            "INSERT INTO identities (id,tenant_id,type,display_name,description,status,metadata,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (iid, tid, itype, display_name, extra.get("description",""), "active", "{}", now, now),
        )
        if itype == "user":
            conn.execute(
                "INSERT INTO users (id,identity_id,email,phone,department,job_title,last_seen_at,failed_logins) VALUES (?,?,?,?,?,?,?,?)",
                (iid, iid, extra.get("email",""), extra.get("phone",""), extra.get("department",""), extra.get("job_title",""), now, 0),
            )
        elif itype == "service_account":
            conn.execute(
                "INSERT INTO service_accounts (id,identity_id,account_type,owner_id,expiry_at,rotation_required) VALUES (?,?,?,?,?,?)",
                (iid, iid, extra.get("account_type","machine"), extra.get("owner_id",""), extra.get("expiry_at",""), 0),
            )
        elif itype == "group":
            conn.execute(
                "INSERT INTO groups (id,identity_id,parent_group_id,group_type) VALUES (?,?,?,?)",
                (iid, iid, extra.get("parent_group_id") or None, extra.get("group_type","security")),
            )
        elif itype == "role":
            conn.execute(
                "INSERT INTO roles (id,identity_id,role_type,scope) VALUES (?,?,?,?)",
                (iid, iid, extra.get("role_type","custom"), extra.get("scope","")),
            )
        return iid

    # Users
    andrew   = make_identity("user", "Andrew Chen",       email="andrew@wolf-pak.local",    department="Security Operations", job_title="SOC Analyst",      phone="555-0101")
    priya    = make_identity("user", "Priya Sharma",      email="priya@wolf-pak.local",    department="Engineering",          job_title="Platform Engineer", phone="555-0102")
    marcus   = make_identity("user", "Marcus O'Neill",    email="marcus@wolf-pak.local",   department="IT",                   job_title="SysAdmin",          phone="555-0103")
    lisa     = make_identity("user", "Lisa Park",         email="lisa@wolf-pak.local",     department="Finance",              job_title="Controller",        phone="555-0104")
    dora     = make_identity("user", "Dora Espinoza",     email="dora@wolf-pak.local",     department="Engineering",          job_title="Senior Dev",        phone="555-0105")

    # Service accounts
    ci_bot   = make_identity("service_account", "CI/CD Pipeline", account_type="machine", owner_id=priya,  expiry_at="")
    backup_svc = make_identity("service_account", "Backup Service",  account_type="machine", owner_id=marcus, expiry_at="")

    # Groups
    soc_analysts = make_identity("group", "SOC Analysts", parent_group_id="", group_type="security")
    engineers    = make_identity("group", "Engineering",  parent_group_id="", group_type="security")
    finance      = make_identity("group", "Finance",      parent_group_id="", group_type="security")

    conn.execute("INSERT INTO identity_group_members (group_id,member_id,joined_at) VALUES (?,?,?)", (soc_analysts, andrew,  now))
    conn.execute("INSERT INTO identity_group_members (group_id,member_id,joined_at) VALUES (?,?,?)", (engineers,    priya, now))
    conn.execute("INSERT INTO identity_group_members (group_id,member_id,joined_at) VALUES (?,?,?)", (engineers,    dora,  now))
    conn.execute("INSERT INTO identity_group_members (group_id,member_id,joined_at) VALUES (?,?,?)", (finance,      lisa,  now))
    conn.execute("INSERT INTO identity_group_members (group_id,member_id,joined_at) VALUES (?,?,?)", (engineers,    marcus,now))

    # Roles
    reader_role   = make_identity("role", "Reader",               role_type="builtin", scope="")
    writer_role   = make_identity("role", "Writer",               role_type="builtin", scope="")
    admin_role    = make_identity("role", "Resource Admin",       role_type="custom",   scope="")
    secops_role   = make_identity("role", "SecOps",               role_type="custom",   scope="")
    backup_role   = make_identity("role", "Backup Operator",      role_type="custom",   scope="")

    # Role → Permission wiring is done after permissions exist.

    # --- Devices ---
    def make_device(name, dtype, **extra) -> str:
        did = id_from("DEV", name)
        conn.execute(
            "INSERT INTO devices (id,tenant_id,identity_id,name,device_type,os,os_version,hostname,ip_address,platform,posture_score,compliance_status,encrypted,mfa_capable,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, tid, extra.get("identity_id") or None, name, dtype,
             extra.get("os",""), extra.get("os_version",""), extra.get("hostname",""),
             extra.get("ip_address",""), extra.get("platform","unknown"),
             extra.get("posture_score",1.0), extra.get("compliance_status","unknown"),
             extra.get("encrypted",0), extra.get("mfa_capable",0),
             extra.get("status","active"), now, now),
        )
        return did

    dev_wk1 = make_device("WKS-ANDREW-01", "workstation", identity_id=andrew,   os="Windows",        os_version="11",    hostname="wks-andrew-01", ip_address="10.1.1.50", platform="windows", posture_score=0.95, compliance_status="compliant",  encrypted=1, mfa_capable=1)
    dev_wk2 = make_device("WKS-PRIYA-01", "workstation", identity_id=priya,    os="macOS",          os_version="14",    hostname="wks-priya-01",  ip_address="10.1.1.51", platform="macos",   posture_score=0.88, compliance_status="compliant",  encrypted=1, mfa_capable=1)
    dev_wk3 = make_device("WKS-LISA-01",  "workstation", identity_id=lisa,     os="Windows",        os_version="10",    hostname="wks-lisa-01",   ip_address="10.1.1.52", platform="windows", posture_score=0.55, compliance_status="non_compliant", encrypted=0, mfa_capable=0)
    dev_srv1 = make_device("SRV-BACKUP-01","server",      identity_id=backup_svc, os="Linux",        os_version="22.04", hostname="srv-backup-01", ip_address="10.2.0.10", platform="linux",   posture_score=0.92, compliance_status="compliant",  encrypted=1, mfa_capable=0)
    dev_mob1 = make_device("MBL-DORA-01",  "mobile",      identity_id=dora,     os="iOS",            os_version="17.1",  hostname="mbl-dora-01",   ip_address="10.1.2.9",  platform="ios",     posture_score=0.70, compliance_status="unknown",    encrypted=1, mfa_capable=1)

    # --- Applications ---
    def make_app(name, **extra) -> str:
        aid = id_from("APP", name)
        conn.execute(
            "INSERT INTO applications (id,tenant_id,name,description,type,vendor,version,url,protocol,auth_method,risk_rating,status,metadata,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, tid, name, extra.get("description",""), extra.get("type","web"),
             extra.get("vendor",""), extra.get("version",""), extra.get("url",""),
             extra.get("protocol","none"), extra.get("auth_method","none"),
             extra.get("risk_rating","medium"), extra.get("status","active"),
             extra.get("metadata","{}"), now, now),
        )
        return aid

    app_erp   = make_app("ERP Portal",   description="Financial systems & procurement", type="web",    vendor="AcmeCorp",   risk_rating="high",    auth_method="saml",    url="https://erp.wolf-pak.local")
    app_git   = make_app("GitLab",       description="Source code & CI",               type="saas",   vendor="GitLab",     risk_rating="medium",   auth_method="oidc",    url="https://gitlab.wolf-pak.local")
    app_k8s   = make_app("Kubernetes API", description="Cluster management",           type="api",    vendor="CNCF",       risk_rating="critical", auth_method="certificate", url="https://k8sapi.wolf-pak.local:6443")
    app_splunk= make_app("Splunk",       description="SIEM & log analytics",          type="web",    vendor="Splunk",     risk_rating="high",     auth_method="oidc",    url="https://splunk.wolf-pak.local")
    app_slack = make_app("Slack",        description="Team messaging",                type="saas",   vendor="Slack",      risk_rating="low",      auth_method="oidc",    url="https://wolf-pak.slack.com")

    # --- Resources ---
    def make_resource(name, rtype, classification="internal", **extra) -> str:
        rid = id_from("RES", name)
        conn.execute(
            "INSERT INTO resources (id,tenant_id,name,description,resource_type,parent_id,classification,owner_id,application_id,data_class,retention_days,status,metadata,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, tid, name, extra.get("description",""), rtype,
             extra.get("parent_id") or None, classification,
             extra.get("owner_id") or None, extra.get("application_id") or None,
             extra.get("data_class",""), extra.get("retention_days",90),
             extra.get("status","active"), extra.get("metadata","{}"),
             now, now),
        )
        return rid

    res_prod_db   = make_resource("Prod DB",          "database",    "restricted",   owner_id=marcus,     application_id=app_erp,   description="Primary customer database")
    res_prod_api  = make_resource("Prod API",         "api",         "confidential", owner_id=priya,      application_id=app_git,   description="Production REST API")
    res_splunk_idx= make_resource("Splunk Indexers",  "other",       "confidential", owner_id=andrew,     application_id=app_splunk,description="SIEM data tier")
    res_k8s_secrets= make_resource("K8s Secrets",     "secret",      "privileged",   owner_id=marcus,     application_id=app_k8s,   description="Cluster secrets store")
    res_backups   = make_resource("Backup Storage",    "bucket",      "confidential", owner_id=backup_svc, application_id=None,       description="Nightly backup bucket")
    res_namingsv  = make_resource("Naming Service",   "api",         "internal",     owner_id=priya,      application_id=app_k8s,   description="Internal service discovery")

    # --- Permissions ---
    def make_perm(name, action, **extra) -> str:
        pid = id_from("PERM", name)
        conn.execute(
            "INSERT INTO permissions (id,tenant_id,name,description,action,resource_type,resource_id,scope_expression,risk_weight,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, tid, name, extra.get("description",""), action,
            extra.get("resource_type",""), extra.get("resource_id") or None,
             extra.get("scope_expression",""), extra.get("risk_weight",1.0),
             extra.get("status","active"), now, now),
        )
        return pid

    p_read_db    = make_perm("Read Production DB",     "read",     resource_type="database",  risk_weight=0.6)
    p_write_db   = make_perm("Write Production DB",    "write",    resource_type="database",  risk_weight=0.9)
    p_admin_db   = make_perm("Admin Production DB",    "admin",    resource_type="database",  risk_weight=1.0)
    p_read_api   = make_perm("Read API",               "read",     resource_type="api",       risk_weight=0.3)
    p_write_api  = make_perm("Write API",              "write",    resource_type="api",       risk_weight=0.6)
    p_deploy     = make_perm("Deploy to Production",   "execute",  resource_type="api",       risk_weight=1.0)
    p_read_secrets = make_perm("Read Secrets",         "read",     resource_type="secret",    risk_weight=0.9)
    p_write_secrets= make_perm("Write Secrets",        "write",    resource_type="secret",    risk_weight=1.0)
    p_list_backups = make_perm("List Backups",         "read",     resource_type="bucket",    risk_weight=0.2)
    p_write_backups= make_perm("Write Backups",        "write",    resource_type="bucket",    risk_weight=0.8)
    p_full_backup  = make_perm("Full Backup Operator",  "manage",   resource_type="bucket",    risk_weight=1.0)

    # Role → Permission
    def grant(role_id, perm_id):
        conn.execute("INSERT INTO role_permissions (role_id,permission_id,granted_at) VALUES (?,?,?)", (role_id, perm_id, now))

    grant(reader_role,  p_read_db)
    grant(reader_role,  p_read_api)
    grant(writer_role,  p_write_db)
    grant(writer_role,  p_write_api)
    grant(admin_role,   p_admin_db)
    grant(admin_role,   p_read_secrets)
    grant(admin_role,   p_write_secrets)
    grant(admin_role,   p_deploy)
    grant(secops_role,  p_read_secrets)
    grant(secops_role,  p_list_backups)
    grant(backup_role,  p_list_backups)
    grant(backup_role,  p_write_backups)
    grant(backup_role,  p_full_backup)

    # Identity → Role
    def assign_role(identity_id, role_id, **extra):
        conn.execute("INSERT INTO identity_roles (identity_id,role_id,granted_at,granted_by,expires_at) VALUES (?,?,?,?,?)",
                     (identity_id, role_id, now, extra.get("granted_by",""), extra.get("expires_at","")))

    assign_role(andrew,  secops_role)
    assign_role(priya,   writer_role)
    assign_role(priya,   reader_role)
    assign_role(marcus,  admin_role)
    assign_role(marcus,  backup_role)
    assign_role(lisa,    reader_role)
    assign_role(dora,    writer_role)
    assign_role(dora,    reader_role)
    assign_role(ci_bot,  writer_role)

    # Group → Role
    def grant_group_role(group_id, role_id):
        conn.execute("INSERT INTO group_roles (group_id,role_id,granted_at) VALUES (?,?,?)", (group_id, role_id, now))

    grant_group_role(soc_analysts, secops_role)
    grant_group_role(engineers,    reader_role)
    grant_group_role(engineers,    writer_role)
    grant_group_role(finance,      reader_role)

    # --- Policies ---
    def make_policy(name, ptype, effect, condition, **extra) -> str:
        pid = id_from("POL", name)
        conn.execute(
            "INSERT INTO policies (id,tenant_id,name,description,policy_type,effect,condition,action,resource_type,priority,enabled,version,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, tid, name, extra.get("description",""), ptype, effect, condition,
             extra.get("action",""), extra.get("resource_type",""),
             extra.get("priority",100), 1, "1.0.0", "active", now, now),
        )
        return pid

    pol_mfa_required = make_policy(
        "MFA Required for Privileged", "mfa", "deny",
        json.dumps({"mfa_verified": False, "risk_score": 0.5}),
        action="any", resource_type="", priority=10,
        description="Deny access to privileged resources when MFA not verified.",
    )
    pol_no_offhours = make_policy(
        "No Off-Hours Access to Prod DB", "access_control", "deny",
        json.dumps({"hour": {"ge": 22, "or": {"le": 5}}, "resource_type": "database", "classification": "restricted"}),
        action="write", resource_type="database", priority=20,
        description="Prevent write access to restricted databases between 22:00-05:00 local.",
    )
    pol_secops_only = make_policy(
        "SecOps Only — Secrets Read", "access_control", "allow",
        json.dumps({"role": "SecOps", "resource_type": "secret"}),
        action="read", resource_type="secret", priority=30,
        description="Only SecOps group members may read secrets.",
    )
    pol_device_posture = make_policy(
        "Device Posture >= 0.7", "device_posture", "deny",
        json.dumps({"posture_score": {"lt": 0.7}}),
        action="any", resource_type="", priority=15,
        description="Block access from devices with posture score below 0.7.",
    )
    pol_rotation = make_policy(
        "Credentials Older Than 90 Days", "password", "audit",
        json.dumps({"credential_age_days": {"gt": 90}}),
        action="any", resource_type="", priority=50,
        description="Flag credentials not rotated in 90+ days.",
    )

    # --- Credentials ---
    def make_cred(name, ctype, **extra) -> str:
        cid = id_from("CRED", name)
        conn.execute(
            "INSERT INTO credentials (id,tenant_id,identity_id,device_id,name,credential_type,status,strength_score,encrypted,last_rotated_at,expires_at,next_rotation_at,fingerprint,metadata,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cid, tid, extra.get("identity_id") or None, extra.get("device_id") or None,
             name, ctype, extra.get("status","active"), extra.get("strength_score",0.0),
             extra.get("encrypted",0), extra.get("last_rotated_at",now), extra.get("expires_at",""),
             extra.get("next_rotation_at",""), extra.get("fingerprint",""), extra.get("metadata","{}"),
             now, now),
        )
        return cid

    cred_andrew = make_cred("Andrew Password", "password", identity_id=andrew,   device_id=dev_wk1, strength_score=0.72, encrypted=1, last_rotated_at=now, next_rotation_at="")
    cred_priya  = make_cred("Priya SSH Key",   "ssh_key",  identity_id=priya,    device_id=dev_wk2, strength_score=0.95, encrypted=1, fingerprint="SHA256:abc...")
    cred_marcus = make_cred("Marcus Password", "password", identity_id=marcus,   device_id=dev_wk3, strength_score=0.41, encrypted=0, last_rotated_at="2026-06-01T00:00:00+00:00", next_rotation_at="")
    cred_backup = make_cred("Backup API Key",  "api_key",  identity_id=backup_svc, device_id=dev_srv1, strength_score=0.88, encrypted=1)

    # --- Sessions ---
    def make_session(identity_id, **extra) -> str:
        sid = id_from("SESS", identity_id + now[:19])
        conn.execute(
            "INSERT INTO sessions (id,tenant_id,identity_id,device_id,credential_id,application_id,auth_method,started_at,last_active_at,expires_at,ip_address,user_agent,status,risk_score,mfa_verified,properties) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, tid, identity_id, extra.get("device_id") or None, extra.get("credential_id") or None,
             extra.get("application_id") or None, extra.get("auth_method","oidc"), now, now,
             extra.get("expires_at", now), extra.get("ip_address",""), extra.get("user_agent",""),
             extra.get("status","active"), extra.get("risk_score",0.0),
             extra.get("mfa_verified",1), extra.get("properties","{}")),
        )
        return sid

    sess_andrew  = make_session(andrew,  device_id=dev_wk1, credential_id=cred_andrew, application_id=app_splunk, ip_address="10.1.1.50")
    sess_priya   = make_session(priya,   device_id=dev_wk2, credential_id=cred_priya,  application_id=app_git,   ip_address="10.1.1.51")
    sess_marcus  = make_session(marcus,  device_id=dev_wk3, credential_id=cred_marcus, application_id=app_erp,   ip_address="10.1.1.52")
    sess_ci_bot  = make_session(ci_bot,  device_id=dev_srv1,credential_id=cred_backup, application_id=app_k8s,   ip_address="10.2.0.10", auth_method="api_key", mfa_verified=0, risk_score=0.3)

    # --- Access Events ---
    def make_access_event(identity_id, action, outcome, **extra) -> str:
        eid = id_from("ACC", identity_id + action + now[:19])
        conn.execute(
            "INSERT INTO access_events (id,tenant_id,identity_id,device_id,application_id,resource_id,permission_id,action,outcome,source_ip,user_agent,session_id,policy_decisions,context,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, tid, identity_id,
             extra.get("device_id") or None, extra.get("application_id") or None, extra.get("resource_id") or None,
             extra.get("permission_id") or None, action, outcome,
             extra.get("source_ip",""), extra.get("user_agent",""), extra.get("session_id") or None,
             extra.get("policy_decisions","[]"), extra.get("context","{}"), now),
        )
        return eid

    make_access_event(andrew,  "read",   "granted",                  device_id=dev_wk1,  application_id=app_splunk, resource_id=res_splunk_idx, session_id=sess_andrew, context='{"reason":"investigating risk event #R-001"}')
    make_access_event(priya,   "write",  "granted",                  device_id=dev_wk2,  application_id=app_git,   resource_id=res_prod_api,   session_id=sess_priya,  context='{"branch":"main","sha":"a1b2c3"}')
    make_access_event(marcus,  "write",  "denied",                   device_id=dev_wk3,  application_id=app_erp,   resource_id=res_prod_db,    session_id=sess_marcus, context='{"policy":"No Off-Hours Access","hour":23}',
                      policy_decisions=json.dumps([{"policy":"No Off-Hours Access","decision":"deny","reason":"outside allowed hours"}]))
    make_access_event(marcus,  "read",   "granted",                  device_id=dev_wk3,  application_id=app_erp,   resource_id=res_prod_db,    session_id=sess_marcus)
    make_access_event(backup_svc, "write", "granted",                device_id=dev_srv1, application_id=app_k8s,  resource_id=res_backups,    session_id=sess_ci_bot, context='{"backup_job":"nightly-full"}')
    make_access_event(dora,    "read",   "granted",                  device_id=dev_mob1, application_id=app_git,   resource_id=res_prod_api,   session_id=None,         context='{"mfa_verified":0}')

    # --- Risk Events ---
    def make_risk_event(source, severity, risk_score, title, **extra) -> str:
        rid = id_from("RISK", title + now[:19])
        conn.execute(
            "INSERT INTO risk_events (id,tenant_id,identity_id,device_id,application_id,source,severity,risk_score,title,description,indicators,related_event_id,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, tid, extra.get("identity_id") or None, extra.get("device_id") or None,
             extra.get("application_id") or None, source, severity, risk_score, title,
             extra.get("description",""), extra.get("indicators",""), extra.get("related_event_id") or None,
             extra.get("status","open"), now),
        )
        return rid

    r1 = make_risk_event("device_posture", "medium", 0.45, "Non-compliant workstation accessing ERP",
                         identity_id=marcus, device_id=dev_wk3,
                         description="Device posture 0.55 with encryption disabled accessing restricted DB.",
                         indicators=json.dumps({"posture_score":0.55,"encrypted":0,"mfa_capable":0}))
    r2 = make_risk_event("anomaly_score", "high", 0.72, "Off-hours write attempt to Prod DB",
                         identity_id=marcus, device_id=dev_wk3, application_id=app_erp, resource_id=res_prod_db,
                         description="Write access attempted at 23:00 against restricted database, blocked by policy.",
                         related_event_id=None, indicators=json.dumps({"hour":23,"action":"write","outcome":"denied"}))
    r3 = make_risk_event("credential_leak", "critical", 0.92, "Possible credential exposure — backup API key",
                         identity_id=backup_svc, device_id=dev_srv1,
                         description="Backup service API key detected in a public repository scan (simulated).",
                         indicators=json.dumps({"credential_id":cred_backup,"source":"github_scan","matched":True}))

    # --- Findings ---
    def make_finding(category, severity, title, **extra) -> str:
        fid = id_from("FIND", title + now[:19])
        conn.execute(
            "INSERT INTO findings (id,tenant_id,risk_event_id,identity_id,device_id,title,description,category,severity,confidence,status,recommendation,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, tid, extra.get("risk_event_id") or None, extra.get("identity_id") or None, extra.get("device_id") or None,
             title, extra.get("description",""), category, severity,
             extra.get("confidence",1.0), extra.get("status","open"), extra.get("recommendation",""),
             now, now),
        )
        return fid

    f1 = make_finding("unencrypted_device", "medium", "Non-compliant device: WKS-LISA-01",
                      risk_event_id=r1, identity_id=marcus, device_id=dev_wk3,
                      description="Workstation posture 0.55; disk encryption disabled; MFA not capable.",
                      recommendation="Enable BitLocker/FileVault, enroll in MDM, enable MFA.")
    f2 = make_finding("anomalous_access", "high", "Off-hours privileged write blocked",
                      risk_event_id=r2, identity_id=marcus, device_id=dev_wk3,
                      description="SysAdmin attempted write to restricted DB at 23:00 — policy denied.",
                      recommendation="Review off-hours access policy; consider just-in-time elevation.")
    f3 = make_finding("credential_exposure", "critical", "Backup API key potentially exposed",
                      risk_event_id=r3, identity_id=backup_svc, device_id=dev_srv1,
                      description="Backup service API key flagged by external scan.",
                      recommendation="Rotate API key immediately; audit recent backup access.")

    # --- Violations ---
    def make_violation(violation_type, severity, action, **extra) -> str:
        vid = id_from("VIOL", action + now[:19])
        conn.execute(
            "INSERT INTO violations (id,tenant_id,finding_id,policy_id,identity_id,device_id,resource_id,action,violation_type,severity,evidence,description,detected_at,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (vid, tid, extra.get("finding_id") or None, extra.get("policy_id") or None,
             extra.get("identity_id") or None, extra.get("device_id") or None, extra.get("resource_id") or None,
             action, violation_type, severity, extra.get("evidence",""), extra.get("description",""),
             now, extra.get("status","active"), now),
        )
        return vid

    make_violation("access_denied_bypass","high","write", finding_id=f2, policy_id=pol_no_offhours,
                   identity_id=marcus, device_id=dev_wk3, resource_id=res_prod_db,
                   description="Off-hours write to restricted DB denied by policy.", evidence=json.dumps({"policy":"No Off-Hours Access"}))
    make_violation("credential_misuse","critical","read", finding_id=f3,
                   identity_id=backup_svc, device_id=dev_srv1, resource_id=res_backups,
                   description="Backup API key possibly exposed in public repo.", evidence=json.dumps({"source":"github_scan","key_id":cred_backup}))

    # --- Remediation ---
    def make_remediation(action_type, **extra) -> str:
        rdid = id_from("REM", action_type + now[:19])
        conn.execute(
            "INSERT INTO remediation (id,tenant_id,violation_id,finding_id,risk_event_id,identity_id,assigned_to,action_type,action_details,status,requested_at,completed_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rdid, tid, extra.get("violation_id") or None, extra.get("finding_id") or None, extra.get("risk_event_id") or None,
             extra.get("identity_id") or None, extra.get("assigned_to") or None, action_type, extra.get("action_details",""),
             extra.get("status","pending"), now, extra.get("completed_at") or None, now),
        )
        return rdid

    make_remediation("rotate_credential", finding_id=f3, identity_id=backup_svc, assigned_to=marcus,
                     action_details="Rotate backup API key; re-issue to CI/CD pipeline; revoke old key.",
                     status="in_progress")
    make_remediation("apply_policy", finding_id=f2, assigned_to=priya,
                     action_details="Review and tighten off-hours access policy; consider JIT elevation for sysadmins.",
                     status="pending")
    make_remediation("quarantine_device", finding_id=f1, identity_id=marcus, assigned_to=marcus,
                     action_details="Quarantine WKS-LISA-01 until encryption and MFA are remediated.",
                     status="pending")

    conn.commit()
