

# PakShield — Identity, Access & Privilege Intelligence Engine

**Copyright (c) 2026 Wolf-Pak Innovations LLC. All rights reserved.**

PakShield is part of the Wolf-Pak security platform alongside Network Guardian and Mask.

**Wolf-Pak's Identity, Access & Privilege Intelligence Engine.**

PakShield answers four questions for every access decision in the Wolf-Pak security platform:

- **Who is responsible?** — the identity (user, service account, group, or role) requesting access
- **What can they access?** — the effective permissions and resources available to that identity
- **What should they be able to access?** — the policy-driven ideal state compared against actual access
- **How risky is that identity/access relationship?** — the risk score, posture, and anomalies attached to the identity and its devices

Network Guardian answers *"What is happening on the network?"* PakShield answers *"Who is responsible, what can they access, and how risky is that?"* Together they produce contextual security intelligence.

## What this application does

PakShield is a tenant-scoped identity and access management (IAM) engine with a 13-entity data model, a full REST API, and a policy decision point (PDP) that evaluates access requests against permissions, roles, groups, and policies.

### Core capabilities

- **Tenant isolation** — every entity lives under a tenant; multi-tenant ready
- **Identity model** — Users, Service Accounts, Groups, and Roles with group membership and role assignment
- **Device management** — devices with posture scores, compliance status, encryption, MFA capability, and IP/hostname tracking; devices are linked to owning identities
- **Application catalog** — registered applications with type, vendor, version, URL, auth protocol, and risk rating
- **Resource hierarchy** — hierarchical resources (folders, documents, fields) with classification, ownership, and data retention policies
- **Permission system** — permissions grant actions (read, write, delete, administer, share, export, audit) on resource types; assignable to roles and identities directly
- **Policy engine** — conditional policies (MFA required, device posture thresholds, off-hours restrictions, role restrictions) with allow/deny/audit effects; policies can block or flag access decisions
- **Credential lifecycle** — password and key credentials with strength scoring, rotation tracking, expiration, and status
- **Session tracking** — sessions with start time, last activity, expiration, IP, user agent, MFA verification state, and risk score
- **Access event logging** — every access request recorded with identity, device, application, resource, permission, outcome, source IP, and policy decisions
- **Risk event detection** — risk events scored 0-100 with severity, source, indicators, and status
- **Finding management** — security findings with category, severity, confidence, recommendation, and lifecycle
- **Violation tracking** — policy violations with type, severity, evidence, and lifecycle
- **Remediation workflow** — remediations tied to findings/violations/risk events, with action types (revoke_access, disable_account, rotate_credential, quarantine_device, enforce_mfa, apply_policy, escalate, accept_risk, close)
- **Policy Decision Point (PDP)** — evaluate endpoint accepts identity + action + resource + device + context; returns grant/deny, effective permissions, policy violations, and reason
- **Dashboard** — aggregate counts, top findings, top violations, open risk events, stale credentials, non-compliant devices
- **Risk surface** — open risk events, high-risk identities, stale credentials, non-compliant devices, total risk score
- **Effective access** — what a given identity can access across resources, permissions, and applications
- **Enrichment endpoint** — Network Guardian calls this to turn a device IP or identity ID into full identity/access/risk context for correlation with network telemetry

### Data model

All entities are per-tenant:

```
Tenant
├── Identity → User | ServiceAccount | Group | Role
│   ├── Group membership (identity ↔ group)
│   ├── Role assignment (identity ↔ role)
│   └── Permission assignment (identity ↔ permission)
├── Device (linked to owning identity)
├── Application
├── Resource (hierarchical: parent_id)
├── Permission (action + resource_type)
├── Policy (conditional, with effect: allow|deny|audit)
├── Credential (password | key, with lifecycle)
├── Session (with MFA state, risk score, expiration)
├── AccessEvent (every access decision recorded)
├── RiskEvent (scored 0-100, with severity and indicators)
├── Finding (category, severity, recommendation)
├── Violation (policy violation, with evidence)
└── Remediation (action type, assigned to, status)
```

### REST API surface

Base path: `/api/tenants/{tenant_id}`

Resources: tenants, identities (user/service_account/group/role), groups (members/roles), roles (permissions), devices, applications, resources, permissions, policies, credentials (with rotate), sessions, access-events, risk-events, findings, violations, remediations, dashboard, risk-surface, effective-access, evaluate, enrich/context.

### Policy Decision Point (evaluate)

`POST /api/tenants/{tenant}/evaluate` accepts identity_id, action, resource_id, device_id, mfa_verified, context — returns decision (grant/deny), reason, effective_permissions, policy violations that fired, risk_score, mfa_required.

The PDP checks: identity active → permission grants action on resource type → deny policies (MFA, posture, off-hours, role restrictions) → audit policies (credential age).

### Enrichment endpoint (Network Guardian integration)

`POST /api/enrich/context` with device_ip or identity_id returns full identity context: device owner, effective access, risk surface, sessions, access events, findings, violations. This is the primary cross-app integration surface — Network Guardian correlates its network telemetry with PakShield's identity/access/risk context.

## Tech stack

Python 3.10+, Flask, SQLite (pakshield.db), stdlib hashlib.

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1  /  .venv\Scripts\activate.bat
# Linux/macOS: source .venv/bin/activate
pip install flask
```

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000/ — API at http://127.0.0.1:5000/api/tenants/TENANT-WOLF-PAK/...

## Demo mode

Set `DEMO_MODE=true` to auto-create seed tenant + sample data on startup. Seed includes: 1 tenant, 15 identities (5 users, 3 service accounts, 3 groups, 2 roles), 5 devices, 5 applications, 6 resources, 11 permissions, 5 policies, 3 credentials, 3 sessions, 3 access events, 3 risk events, 3 findings, 3 violations, 3 remediations.

## Smoke test

```bash
python smoke_test.py
```

Verifies dashboard, identities, groups, roles, devices, apps, resources, permissions, policies, PDP evaluate (grant + deny), risk surface, finding+remediation CRUD, access events, sessions, effective access.

## Integration with Network Guardian and Mask Network

### Network Guardian → PakShield

NG calls `POST /api/enrich/context` with device IP or identity ID → gets identity/access/risk context for network event correlation.

### PakShield → Wolf-Pak Event Fabric

PakShield emits access events, risk events, findings, violations, remediations to the Event Fabric intake server (default `http://localhost:8090/api/event-fabric/intake`). Set `WOLF_PAK_EVENT_FABRIC_URL` to configure. Fire-and-forget — failures logged and swallowed.

### PakShield → Wolf-Pak Security Graph

PakShield upserts identity, device, application, resource, permission, policy nodes and relationships into the Security Graph — keeps identity→device, identity→resource, device→application edges current.

### PakShield → Mask Network redaction

PakShield redacts sensitive fields (passwords, tokens, API keys, PII) via Mask's `TrafficMasker`/`AnonymisationPipeline` before API responses and event payloads. Falls back to local rule engine when Mask unavailable.

### Shared event schema

```json
{
  "timestamp_ms": 1760000000000,
  "asset_id": "DEV-...",
  "source": "PAKSHIELD",
  "source_version": "0.1.0",
  "event_type": "access_decision|risk_signal|security_finding|policy_violation|remediation",
  "severity": "low|medium|high|critical",
  "category": "access|risk|finding|violation|remediation|credential|session",
  "description": "...",
  "family": "detection|audit",
  "event_id": "...",
  "payload": {...}
}
```

Cross-app join key: `asset_id` (PakShield populates from owning device ID).

## Project structure

```
PakShield/
├── app.py                 # Flask bootstrapper
├── core.py                # IAM engine — schema, helpers, Flask app, seed data
├── app_p1.py              # Tenant, Identity, Group, Role routes
├── app_p2.py              # Device, Application routes
├── routes_resources.py    # Resource, Permission, Policy routes
├── routes_auth.py         # Credential, Session, Access Event routes
├── routes_security.py     # Risk Event, Finding, Violation, Remediation routes
├── routes_dashboard.py    # Dashboard, Risk Surface, Effective Access, PDP Evaluate
├── routes_enrichment.py   # NG enrichment endpoint
├── pakshield_integration.py  # Event Fabric + Security Graph + Mask redaction + enrichment
├── smoke_test.py          # Smoke test
├── requirements.txt       # flask
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```

## License

Internal and educational use.
