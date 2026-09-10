import math
import os
import sqlite3
import time

from flask import Flask, jsonify, request, render_template

from VendorPayloadVerification import (
    BlastRadiusGovernanceGateway,
    MarketplaceFulfillmentGateway,
    MarketplaceLifecycleController,
    build_vendor_strategy_summary,
)

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "crm.db")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def seed_demo_data(conn):
    demo_users = [
        ("admin", "admin123", "admin@example.com"),
        ("nora", "demo123", "nora@acmeprocurement.com"),
        ("marcus", "demo123", "marcus@vendorops.com"),
    ]
    demo_contacts = [
        ("Alicia Moore", "alicia@northwind.com", "555-0101"),
        ("Leo Grant", "leo@harborgrid.com", "555-0102"),
        ("Priya Shah", "priya@redriver.io", "555-0103"),
    ]
    demo_leads = [
        ("Atlas Logistics", "sales@atlaslogistics.com", "555-0210"),
        ("BluePeak Retail", "ops@bluepeakretail.com", "555-0211"),
    ]
    demo_opportunities = [
        ("Q4 Supply Risk Review", "Audit key vendor posture before quarter close.", "2026-10-15"),
        ("Enterprise Procurement Renewal", "Renew premium vendor agreement with secured API integration.", "2026-11-03"),
    ]
    demo_pipeline = [
        ("Verified", "2026-09-12"),
        ("Escalated", "2026-09-18"),
        ("Approvals", "2026-09-25"),
    ]

    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        demo_users,
    )

    conn.execute("DELETE FROM contacts")
    conn.executemany(
        "INSERT INTO contacts (name, email, phone) VALUES (?, ?, ?)",
        demo_contacts,
    )

    conn.execute("DELETE FROM leads")
    conn.executemany(
        "INSERT INTO leads (name, email, phone) VALUES (?, ?, ?)",
        demo_leads,
    )

    conn.execute("DELETE FROM opportunities")
    conn.executemany(
        "INSERT INTO opportunities (name, description, deadline) VALUES (?, ?, ?)",
        demo_opportunities,
    )

    conn.execute("DELETE FROM sales_pipeline")
    conn.executemany(
        "INSERT INTO sales_pipeline (stage, deadline) VALUES (?, ?)",
        demo_pipeline,
    )


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS opportunities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            deadline TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sales_pipeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stage TEXT NOT NULL,
            deadline TEXT NOT NULL
        )
        """
    )

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            ("admin", "admin123", "admin@example.com"),
        )

    if DEMO_MODE:
        seed_demo_data(conn)

    conn.commit()
    conn.close()


@app.before_request
def ensure_db():
    init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/demo")
def demo():
    return render_template("demo.html")


@app.route("/api/vendor-strategy-demo")
def vendor_strategy_demo():
    return jsonify({"vendors": build_vendor_strategy_summary()})


@app.route("/api/blast-radius-demo")
def blast_radius_demo():
    gateway = BlastRadiusGovernanceGateway()
    scenarios = [
        {
            "label": "Low Risk",
            "action_type": "invoice_sync",
            "amount_usd": 500,
            "vendor_trust_score": 0.92,
            "data_access_tier": "internal",
            "anomaly_score": 0.12,
        },
        {
            "label": "Medium Risk",
            "action_type": "inventory_adjustment",
            "amount_usd": 25000,
            "vendor_trust_score": 0.82,
            "data_access_tier": "confidential",
            "anomaly_score": 0.22,
        },
        {
            "label": "High Risk",
            "action_type": "wire_transfer",
            "amount_usd": 850000,
            "vendor_trust_score": 0.71,
            "data_access_tier": "restricted",
            "anomaly_score": 0.41,
        },
    ]
    results = []
    for scenario in scenarios:
        evaluation = gateway.evaluate_action(
            action_type=scenario["action_type"],
            amount_usd=scenario["amount_usd"],
            vendor_trust_score=scenario["vendor_trust_score"],
            data_access_tier=scenario["data_access_tier"],
            anomaly_score=scenario["anomaly_score"],
            vendor_id="VEND-00001",
        )
        results.append({
            "label": scenario["label"],
            **evaluation,
        })
    return jsonify({"scenarios": results})


@app.route("/api/fulfillment-demo")
def fulfillment_demo():
    return jsonify({
        "providers": [
            {
                "name": "Azure",
                "status": "Connected",
                "region": "eastus2",
                "latency_ms": 48,
                "sla": "99.9%",
                "services": ["Azure Functions", "Azure Service Bus", "Azure Blob Storage", "Azure SQL"],
                "summary": "Handles secure workflow orchestration, API-driven order fulfillment, and enterprise event routing.",
            },
            {
                "name": "AWS",
                "status": "Connected",
                "region": "us-east-1",
                "latency_ms": 52,
                "sla": "99.9%",
                "services": ["Lambda", "S3", "SNS", "ECS"],
                "summary": "Provides elastic processing, object storage, and resilient burst capability for fulfillment spikes.",
            },
        ],
        "orchestration": {
            "flow": "Vendor ingest → DLP + policy checks → Azure/AWS fulfillment → ERP sync + audit receipt",
            "status": "Active",
        },
    })


@app.route("/marketplace/aws/onboard", methods=["POST"])
def aws_marketplace_onboard():
    data = request.get_json(silent=True) or request.form.to_dict(flat=True)
    token = str(data.get("x_amzn_marketplace_token") or "").strip()
    if not token:
        return jsonify({"status": "error", "message": "Missing x_amzn_marketplace_token."}), 400

    try:
        result = MarketplaceFulfillmentGateway().onboard_aws_marketplace(token)
        return jsonify({
            "status": "success",
            "message": "AWS Enterprise Subscription Verified",
            "tenant_id": result["tenant_id"],
            "source": result["source"],
        })
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/marketplace/azure/onboard", methods=["POST"])
def azure_marketplace_onboard():
    data = request.get_json(silent=True) or request.form.to_dict(flat=True)
    token = str(data.get("token") or "").strip()
    if not token:
        return jsonify({"status": "error", "message": "Missing token."}), 400

    try:
        result = MarketplaceFulfillmentGateway().onboard_azure_marketplace(token)
        return jsonify({
            "status": "success",
            "message": "Azure Enterprise Subscription Verified",
            "tenant_id": result["tenant_id"],
            "source": result["source"],
        })
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/marketplace/webhooks", methods=["POST"])
def marketplace_webhooks():
    event = request.get_json(silent=True) or request.form.to_dict(flat=True) or {}
    lifecycle = MarketplaceLifecycleController()
    result = lifecycle.process_webhook_event(event)
    return jsonify(result)


@app.route("/marketplace/usage-meter", methods=["POST"])
def marketplace_usage_meter():
    data = request.get_json(silent=True) or request.form.to_dict(flat=True) or {}
    subscription_id = str(data.get("subscription_id") or data.get("subscriptionId") or "").strip()
    metric = str(data.get("metric") or "vendor_payloads_verified").strip()
    quantity = float(data.get("quantity") or 0)
    unit_price = float(data.get("unit_price") or data.get("unitPrice") or 0)
    provider = str(data.get("provider") or "local").strip().lower()

    if not subscription_id:
        return jsonify({"status": "error", "message": "subscription_id is required."}), 400

    lifecycle = MarketplaceLifecycleController()
    lifecycle.register_tenant(subscription_id)

    if provider == "aws":
        usage = lifecycle.meter_aws_usage(subscription_id, quantity, metric, unit_price)
    elif provider == "azure":
        usage = lifecycle.meter_azure_usage(subscription_id, quantity, metric, unit_price)
    else:
        usage = lifecycle.record_usage(subscription_id, metric, quantity, unit_price)

    return jsonify({"status": "accepted", **usage})


@app.route("/marketplace/usage-meter/aws", methods=["POST"])
def marketplace_usage_meter_aws():
    data = request.get_json(silent=True) or request.form.to_dict(flat=True) or {}
    subscription_id = str(data.get("subscription_id") or data.get("subscriptionId") or "").strip()
    metric = str(data.get("metric") or "vendor_payloads_verified").strip()
    quantity = float(data.get("quantity") or 0)
    unit_price = float(data.get("unit_price") or data.get("unitPrice") or 0)
    if not subscription_id:
        return jsonify({"status": "error", "message": "subscription_id is required."}), 400

    lifecycle = MarketplaceLifecycleController()
    lifecycle.register_tenant(subscription_id)
    usage = lifecycle.meter_aws_usage(subscription_id, quantity, metric, unit_price)
    return jsonify({"status": "accepted", **usage})


@app.route("/marketplace/usage-meter/azure", methods=["POST"])
def marketplace_usage_meter_azure():
    data = request.get_json(silent=True) or request.form.to_dict(flat=True) or {}
    subscription_id = str(data.get("subscription_id") or data.get("subscriptionId") or "").strip()
    metric = str(data.get("metric") or "encrypted_gb_moved").strip()
    quantity = float(data.get("quantity") or 0)
    unit_price = float(data.get("unit_price") or data.get("unitPrice") or 0)
    if not subscription_id:
        return jsonify({"status": "error", "message": "subscription_id is required."}), 400

    lifecycle = MarketplaceLifecycleController()
    lifecycle.register_tenant(subscription_id)
    usage = lifecycle.meter_azure_usage(subscription_id, quantity, metric, unit_price)
    return jsonify({"status": "accepted", **usage})


def build_prometheus_series(metric_name, base_value, amplitude, samples=24, step_seconds=300):
    now = int(time.time())
    series = []
    for idx in range(samples):
        timestamp = now - (samples - idx - 1) * step_seconds
        wave = math.sin(idx / 4.0)
        variance = math.cos(idx / 3.0) * amplitude
        value = max(0.0, base_value + variance + wave * amplitude * 0.6)
        series.append([timestamp, f"{value:.3f}"])
    return {"metric": {"__name__": metric_name}, "values": series}


PROMETHEUS_SERIES = {
    "pipeline_throughput": build_prometheus_series("pipeline_throughput", 150.0, 40.0),
    "security_audits": build_prometheus_series("security_audits", 12.0, 6.0),
    "agent_performance": build_prometheus_series("agent_performance", 360.0, 120.0),
    "gateway_latency": build_prometheus_series("gateway_latency", 145.0, 45.0),
    "http_5xx_rate": build_prometheus_series("http_5xx_rate", 2.5, 1.2),
    "cpu_usage": build_prometheus_series("cpu_usage", 58.0, 18.0),
    "memory_usage": build_prometheus_series("memory_usage", 64.0, 16.0),
}


@app.route("/api/prometheus-demo")
def prometheus_demo():
    payload = {"metrics": {key: value for key, value in PROMETHEUS_SERIES.items()}}
    return jsonify(payload)


@app.route("/api/prometheus/query_range")
def prometheus_query_range():
    query = request.args.get("query", "pipeline_throughput")
    q = query.strip()
    if q in PROMETHEUS_SERIES:
        series = [PROMETHEUS_SERIES[q]]
    elif q == "system_health":
        series = [
            PROMETHEUS_SERIES["gateway_latency"],
            PROMETHEUS_SERIES["http_5xx_rate"],
            PROMETHEUS_SERIES["cpu_usage"],
            PROMETHEUS_SERIES["memory_usage"],
        ]
    else:
        series = [PROMETHEUS_SERIES["pipeline_throughput"]]

    return jsonify({"status": "success", "data": {"resultType": "matrix", "result": series}})


@app.route("/api/users", methods=["GET", "POST"])
def users_api():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT id, username, email FROM users ORDER BY id").fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    try:
        cursor = conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password, email),
        )
        conn.commit()
        user = {"id": cursor.lastrowid, "username": username, "email": email}
        return jsonify(user), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already exists"}), 409
    finally:
        conn.close()


@app.route("/api/users/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "invalid username or password"}), 401

    return jsonify({"message": "login successful", "user": dict(row)})


@app.route("/api/contacts", methods=["GET", "POST"])
def contacts_api():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM contacts ORDER BY id").fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()

    if not name or not email:
        return jsonify({"error": "name and email are required"}), 400

    cursor = conn.execute(
        "INSERT INTO contacts (name, email, phone) VALUES (?, ?, ?)",
        (name, email, phone),
    )
    conn.commit()
    contact = {"id": cursor.lastrowid, "name": name, "email": email, "phone": phone}
    conn.close()
    return jsonify(contact), 201


@app.route("/api/contacts/<int:contact_id>", methods=["PUT", "DELETE"])
def contact_detail(contact_id):
    conn = get_db()
    if request.method == "PUT":
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        phone = (data.get("phone") or "").strip()
        if not name or not email:
            return jsonify({"error": "name and email are required"}), 400
        conn.execute(
            "UPDATE contacts SET name = ?, email = ?, phone = ? WHERE id = ?",
            (name, email, phone, contact_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        conn.close()
        return jsonify(dict(row))

    row = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "contact not found"}), 404
    conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "contact deleted"})


@app.route("/api/leads", methods=["GET", "POST"])
def leads_api():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM leads ORDER BY id").fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()

    if not name or not email:
        return jsonify({"error": "name and email are required"}), 400

    cursor = conn.execute(
        "INSERT INTO leads (name, email, phone) VALUES (?, ?, ?)",
        (name, email, phone),
    )
    conn.commit()
    lead = {"id": cursor.lastrowid, "name": name, "email": email, "phone": phone}
    conn.close()
    return jsonify(lead), 201


@app.route("/api/leads/<int:lead_id>", methods=["PUT", "DELETE"])
def lead_detail(lead_id):
    conn = get_db()
    if request.method == "PUT":
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        phone = (data.get("phone") or "").strip()
        if not name or not email:
            return jsonify({"error": "name and email are required"}), 400
        conn.execute(
            "UPDATE leads SET name = ?, email = ?, phone = ? WHERE id = ?",
            (name, email, phone, lead_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
        conn.close()
        return jsonify(dict(row))

    row = conn.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "lead not found"}), 404
    conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "lead deleted"})


@app.route("/api/opportunities", methods=["GET", "POST"])
def opportunities_api():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM opportunities ORDER BY id").fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    deadline = data.get("deadline")

    if not name or not deadline:
        return jsonify({"error": "name and deadline are required"}), 400

    cursor = conn.execute(
        "INSERT INTO opportunities (name, description, deadline) VALUES (?, ?, ?)",
        (name, description, deadline),
    )
    conn.commit()
    opportunity = {"id": cursor.lastrowid, "name": name, "description": description, "deadline": deadline}
    conn.close()
    return jsonify(opportunity), 201


@app.route("/api/opportunities/<int:opportunity_id>", methods=["PUT", "DELETE"])
def opportunity_detail(opportunity_id):
    conn = get_db()
    if request.method == "PUT":
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        description = (data.get("description") or "").strip()
        deadline = data.get("deadline")
        if not name or not deadline:
            return jsonify({"error": "name and deadline are required"}), 400
        conn.execute(
            "UPDATE opportunities SET name = ?, description = ?, deadline = ? WHERE id = ?",
            (name, description, deadline, opportunity_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM opportunities WHERE id = ?", (opportunity_id,)).fetchone()
        conn.close()
        return jsonify(dict(row))

    row = conn.execute("SELECT * FROM opportunities WHERE id = ?", (opportunity_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "opportunity not found"}), 404
    conn.execute("DELETE FROM opportunities WHERE id = ?", (opportunity_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "opportunity deleted"})


@app.route("/api/sales-pipeline", methods=["GET", "POST"])
def pipeline_api():
    conn = get_db()
    if request.method == "GET":
        rows = conn.execute("SELECT * FROM sales_pipeline ORDER BY id").fetchall()
        return jsonify([dict(row) for row in rows])

    data = request.get_json() or {}
    stage = (data.get("stage") or "").strip()
    deadline = data.get("deadline")

    if not stage or not deadline:
        return jsonify({"error": "stage and deadline are required"}), 400

    cursor = conn.execute(
        "INSERT INTO sales_pipeline (stage, deadline) VALUES (?, ?)",
        (stage, deadline),
    )
    conn.commit()
    item = {"id": cursor.lastrowid, "stage": stage, "deadline": deadline}
    conn.close()
    return jsonify(item), 201


@app.route("/api/sales-pipeline/<int:item_id>", methods=["PUT", "DELETE"])
def pipeline_detail(item_id):
    conn = get_db()
    if request.method == "PUT":
        data = request.get_json() or {}
        stage = (data.get("stage") or "").strip()
        deadline = data.get("deadline")
        if not stage or not deadline:
            return jsonify({"error": "stage and deadline are required"}), 400
        conn.execute(
            "UPDATE sales_pipeline SET stage = ?, deadline = ? WHERE id = ?",
            (stage, deadline, item_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM sales_pipeline WHERE id = ?", (item_id,)).fetchone()
        conn.close()
        return jsonify(dict(row))

    row = conn.execute("SELECT * FROM sales_pipeline WHERE id = ?", (item_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "pipeline item not found"}), 404
    conn.execute("DELETE FROM sales_pipeline WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "pipeline item deleted"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
