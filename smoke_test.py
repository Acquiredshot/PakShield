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

A = rid("Andrew Chen"); P = rid("Priya Sharma"); M = rid("Marcus O'Neill"); L = rid("Lisa Park")
DA = rdev("WKS-ANDREW-01"); DL = rdev("WKS-LISA-01"); DM = rdev("WKS-INSPECT")
RS = rres("Splunk Indexers"); RP = rres("Prod DB")
print(f"A={A} P={P} M={M} L={L}")
print(f"DA={DA} DL={DL} DM={DM}")
print(f"RS={RS} RP={RP}")

def chk(label, resp, asserts):
    d = resp.get_json()
    ok = True
    for fn in asserts:
        try: fn(d)
        except AssertionError as e: print(f"  FAIL: {e}"); ok = False
        except Exception as e: print(f"  ERROR: {e}"); ok = False
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}")
    return ok, d

print("=== 1. Dashboard ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/dashboard")
chk("dashboard", r, [
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
r = c.get("/api/tenants/TENANT-WOLF-PAK/identities?limit=3")
chk("identities", r, [lambda d: len(d["data"]) == 3])
for i in r.get_json()["data"]: print(f"  {i['type']:20s} {i['display_name']}")

print("=== 3. Users ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/identities?type=user&limit=10")
chk("users", r, [lambda d: all(i["type"]=="user" for i in d["data"])])
for u in r.get_json()["data"]: print(f"  {u['display_name']}")

print("=== 4. Groups ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/identities?type=group")
chk("groups", r, [lambda d: len(d["data"]) >= 2])
for g in r.get_json()["data"]:
    m = c.get("/api/tenants/TENANT-WOLF-PAK/groups/" + g["id"] + "/members").get_json()
    print(f"  {g['display_name']:25s} -> {[x['display_name'] for x in m]}")

print("=== 5. Roles ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/identities?type=role")
chk("roles", r, [lambda d: len(d["data"]) >= 2])
for rl in r.get_json()["data"]:
    p = c.get("/api/tenants/TENANT-WOLF-PAK/roles/" + rl["id"] + "/permissions").get_json()
    print(f"  {rl['display_name']:25s} -> {[x['name'] for x in p]}")

print("=== 6-9. Devices/Apps/Resources/Perms ===")
for label, path in [("devices","/devices"),("applications","/applications"),
                     ("resources","/resources"),("permissions","/permissions")]:
    r = c.get("/api/tenants/TENANT-WOLF-PAK" + path + "?limit=20")
    ok,d = chk(label, r, [lambda d: d["total"] >= 3])
    print(f"  {d['total']} {label}")

print("=== 10. Policies ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/policies?limit=20")
chk("policies", r, [lambda d: d["total"] >= 3])
for p in r.get_json()["data"]: print(f"  {p['name'][:35]:35s} {p['policy_type']:20s} {p['effect']}")

print("=== 11. Evaluate Andrew read Splunk (grant) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id":A,"action":"read","resource_id":RS,
    "device_id":DA,"mfa_verified":True})
chk("grant", r, [lambda d: d["decision"]=="grant",
                   lambda d: len(d.get("effective_permissions",[]))>=1])
print(f"  decision={d['decision']} reason={d.get('reason','')[:80]}")

print("=== 12. Evaluate Lisa write Prod DB at 23:00 (deny) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id":L,"action":"write","resource_id":RP,
    "device_id":DL,"mfa_verified":True})
chk("deny", r, [lambda d: d["decision"]=="deny", lambda d: "policy" in d])
print(f"  decision={d['decision']} reason={d.get('reason','')[:80]}")
if "policy" in d: print(f"  blocked_by={d['policy']['name']}")

print("=== 13. Evaluate Marcus read Prod DB during hours (grant) ===")
r = c.post("/api/tenants/TENANT-WOLF-PAK/evaluate", json={
    "identity_id":M,"action":"read","resource_id":RP,
    "device_id":DM,"mfa_verified":True})
chk("grant_during_hours", r, [lambda d: d["decision"]=="grant"])
print(f"  decision={r.get_json()['decision']}")

print("=== 14. Risk Surface ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/risk-surface")
chk("risk_surface", r, [lambda d: len(d["open_risk_events"])>=1,
                           lambda d: len(d["high_risk_identities"])>=1])
print(f"  open_risk={len(d['open_risk_events'])} high_risk={len(d['high_risk_identities'])}")
print(f"  stale_creds={len(d.get('stale_credentials',[]))} non_compliant_devs={len(d.get('non_compliant_devices',[]))}")

print("=== 15-17. POST finding + remediation + GET both ===")
fr = c.post("/api/tenants/TENANT-WOLF-PAK/findings", json={
    "title":"Smoke test finding","category":"anomalous_access","severity":"high",
    "identity_id":P,"description":"Via REST API"})
chk("finding POST", fr, [lambda d: fr.status_code==201])
fid = fr.get_json()["id"]
print(f"  Finding: {fid}")

rr = c.post("/api/tenants/TENANT-WOLF-PAK/remediations", json={
    "finding_id":fid,"action_type":"apply_policy","action_details":"Review policy",
    "assigned_to":P})
chk("remediation POST", rr, [lambda d: rr.status_code==201, lambda d: d["status"]=="pending"])
rid = rr.get_json()["id"]
print(f"  Remediation: {rid} status={rr.get_json()['status']}")

chk("GET finding", c.get("/api/tenants/TENANT-WOLF-PAK/findings/" + fid), [lambda d: d["id"]==fid])
chk("GET remediation", c.get("/api/tenants/TENANT-WOLF-PAK/remediations/" + rid), [lambda d: d["id"]==rid])

print("=== 18-19. Access events + Sessions ===")
for label, path in [("access_events","/access-events"), ("sessions","/sessions")]:
    r = c.get("/api/tenants/TENANT-WOLF-PAK" + path + "?limit=20")
    chk(label, r, [lambda d: d["total"]>=1])
    print(f"  {d['total']} {label}")

print("=== 20. Effective Access - Andrew ===")
r = c.get("/api/tenants/TENANT-WOLF-PAK/effective-access/" + A)
chk("effective_access", r, [lambda d: "resources" in d])
print(f"  Andrew can access {len(r.get_json().get('resources',[]))} resources")

print()
print("=" * 60)
print("SMOKE TEST COMPLETE")
print("=" * 60)
