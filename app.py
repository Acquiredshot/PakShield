"""
PakShield — Identity, Access & Privilege Intelligence Engine.
Flask app bootstrapper: imports all route modules which register on core.app.
"""

from flask import render_template

from core import app as _app, init_db, DEMO_MODE

app = _app

import app_p1      # noqa: F401 — tenant, identities, groups, roles
import app_p2      # noqa: F401 — devices, applications
import routes_resources   # noqa: F401 — resources, permissions, policies
import routes_auth        # noqa: F401 — credentials, sessions, access events
import routes_security    # noqa: F401 — risk events, findings, violations, remediation
import routes_dashboard  # noqa: F401 — dashboard, risk surface, effective access, PDP evaluate
import routes_enrichment # noqa: F401 — NG enrichment endpoint

# Auto-register: routes_enrichment registers itself on import so that
# app.py does not need to. The blueprint is registered by the module's
# own auto-register block when routes_enrichment is imported above.
# from routes_enrichment import enrichment as _enrichment_bp
# _app.register_blueprint(_enrichment_bp, name="enrichment")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/demo")
def demo():
    return render_template("demo.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
