import os, json
os.environ["DEMO_MODE"] = "true"
from app import app, init_db
init_db()
c = app.test_client()
from core import get_db

def rid(name):
    conn = get_db()
    r = conn.execute("SELECT id FROM identities WHERE display_name=?", (name,)).fetchone()
    conn.close()
    return r["id"] if r else None

def rdev(name):
    conn = get_db()
    r = conn.execute("SELECT id FROM devices WHERE name=?", (name,)).fetchone()
    conn.close()
    return r["id"] if r else None

def rres(name):
    conn = get_db()
    r = conn.execute("SELECT id FROM resources WHERE name=?", (name,)).fetchone()
    conn.close()
    return r["id"] if r else None

A = None  # Andrew removed from seed data
P = rid("Priya Sharma")
M = rid("Marcus O'Neill")
L = rid("Lisa Park")
D = rid("Dora Espinoza")
DA = rdev("WKS-ANDREW-01"); DL = rdev("WKS-LISA-01"); DD = rdev("MBL-DORA-01")
DM = rdev("WKS-INSPECT")
RS = rres("Splunk Indexers"); RP = rres("Prod DB"); RA = rres("Prod API"); RK = rres("K8s Secrets")
print(f"A={A} P={P} M={M} L={L} D={D}")
print(f"DA={DA} DL={DL} DD={DD} DM={DM}")
print(f"RS={RS} RP={RP} RA={RA} RK={RK}")

def chk(label, resp, asserts):
    d = resp.get_json()
    ok = True
    for fn in asserts:
        try:
            if not fn(d):
                raise AssertionError(f"assertion returned False")
        except AssertionError as e: print(f"  FAIL: {e}"); ok = False
        except Exception as e: print(f"  ERROR: {e}"); ok = False
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}")
    return ok, d

print("=== 1. Dashboard ===")
ok, d = chk("dashboard", c.get("/api/tenants/TENANT-WOLF-PAK/dashboard"), [
    lambda d: d["counts"]["users"] >= 3,
    lambda d: d["counts"]["identities"] >= 10,
    lambda d: d["counts"]["applications"] >= 3,
    lambda d: d["counts"]["resources"] >= 3,
    lambda d: d["counts"]["policies"] >= 3,
    lambda d: d["counts"]["devices"] >= 3,
    lambda d: d["counts"]["groups"] >= 2,
    lambda d: d["counts"]["roles"] >= 2,
    lambda d: len(d["top_findings"]) >= 1,
    lambda d: len(d["top_violations"]) >= 1,
    lambda d: d["counts"]["open_findings"] >= 1,
    lambda d: d["counts"]["open_risk_events"] >= 1,
])

print("=== 2. Identities ===")
ok, d = chk("identities", c.get("/api/tenants/TENANT-WOLF-PAK/identities?limit=3"), [
    lambda d: len(d["data"]) == 3])

print("=== 3. Evaluate Dora write Prod DB (should be grant) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id": D, "action": "write", "resource_id": RP,
    "device_id": DD, "mfa_verified": True})
print(f"  status={r.status_code}")
print(f"  decision={r.get_json().get('decision','?')!r}")
print(f"  reason={r.get_json().get('reason','?')!r}")
ok, d = chk("grant-write", r, [
    lambda d: d["decision"] == "grant",
    lambda d: len(d.get("effective_permissions", [])) >= 1])

print("=== 4. Evaluate Dora read K8s Secrets (should be deny) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id": D, "action": "read", "resource_id": RK,
    "device_id": DD, "mfa_verified": True})
print(f"  status={r.status_code}")
print(f"  decision={r.get_json().get('decision','?')!r}")
print(f"  reason={r.get_json().get('reason','?')!r}")
ok, d = chk("deny", r, [
    lambda d: d["decision"] == "denied",
    lambda d: not d["decision"] == "grant"])

print("=== 5. Evaluate Priya read Prod API (should be grant) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id": P, "action": "read", "resource_id": RA,
    "device_id": DL, "mfa_verified": True})
print(f"  status={r.status_code}")
print(f"  decision={r.get_json().get('decision','?')!r}")
print(f"  reason={r.get_json().get('reason','?')!r}")
ok, d = chk("grant-read", r, [
    lambda d: d["decision"] == "grant",
    lambda d: len(d.get("effective_permissions", [])) >= 1])

print("=== 6. Evaluate Dora write Prod DB WITHOUT MFA (should be deny) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id": D, "action": "write", "resource_id": RP,
    "device_id": DD, "mfa_verified": False})
print(f"  status={r.status_code}")
print(f"  decision={r.get_json().get('decision','?')!r}")
print(f"  reason={r.get_json().get('reason','?')!r}")
ok, d = chk("deny-mfa", r, [
    lambda d: d["decision"] == "denied",
    lambda d: "mfa" in (d.get("reason","") or "").lower()])

print()
print("=" * 60)
print("SMOKE TEST COMPLETE")
print("=" * 60)
