import base64
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from app import app
from VendorPayloadVerification import (
    AES256GCMStrategy,
    AgentSecurityToken,
    AuditLedger,
    ComplianceAuditAgent,
    CryptoEngine,
    DlpAnonymizationEngine,
    HumanApprovalGate,
    MarketplaceFulfillmentGateway,
    MarketplaceLifecycleController,
    ProcurementAgent,
    ReceiptAuthority,
    ThreatDetectionAgent,
    VendorDocumentParsingAgent,
    secure_vendor_ingress,
    sanitize_ingress_data,
    verify_vendor_payload,
)


class VendorSecurityTests(unittest.TestCase):
    def setUp(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes_raw()
        self.payload = {
            "vendor_id": "VEND-00001",
            "batch_number": "BATCH-42",
            "item_sku": "SKU-100",
            "quantity": 12,
            "unit_price_usd": 45.5,
        }
        self.signature = base64.b64encode(
            self.private_key.sign(self._canonical_json_bytes(self.payload))
        ).decode("ascii")

    @staticmethod
    def _canonical_json_bytes(payload):
        import json

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def test_verify_vendor_payload_accepts_valid_signature(self):
        self.assertTrue(
            verify_vendor_payload(self.payload, self.signature, self.public_key_bytes)
        )

    def test_verify_vendor_payload_rejects_tampered_payload(self):
        tampered = dict(self.payload)
        tampered["quantity"] = 13
        self.assertFalse(
            verify_vendor_payload(tampered, self.signature, self.public_key_bytes)
        )

    def test_sanitize_ingress_data_validates_schema(self):
        validated = sanitize_ingress_data(self.payload)
        self.assertEqual(validated.vendor_id, "VEND-00001")
        self.assertEqual(validated.quantity, 12)

    def test_secure_vendor_ingress_approves_valid_request(self):
        token = AgentSecurityToken(
            agent_id="procurement-agent",
            allowed_tools=["vendor_ingest"],
            ttl_seconds=60,
            scope={"vendor_scope": "VEND-00001"},
        )
        ledger = AuditLedger()
        result = secure_vendor_ingress(
            raw_json=self.payload,
            signature_b64=self.signature,
            vendor_public_key_bytes=self.public_key_bytes,
            agent_token=token,
            tool_name="vendor_ingest",
            params={"source": "supplier-api"},
            approval_gate=HumanApprovalGate(threshold_amount_usd=100000.0),
            ledger=ledger,
        )
        self.assertEqual(result["status"], "approved")
        self.assertEqual(len(ledger.entries), 1)

    def test_secure_vendor_ingress_requires_human_approval_for_large_risk(self):
        large_payload = dict(self.payload)
        large_payload["quantity"] = 5000
        large_payload["unit_price_usd"] = 50.0
        token = AgentSecurityToken(
            agent_id="procurement-agent",
            allowed_tools=["vendor_ingest"],
            ttl_seconds=60,
        )
        large_signature = base64.b64encode(
            self.private_key.sign(self._canonical_json_bytes(large_payload))
        ).decode("ascii")
        result = secure_vendor_ingress(
            raw_json=large_payload,
            signature_b64=large_signature,
            vendor_public_key_bytes=self.public_key_bytes,
            agent_token=token,
            tool_name="vendor_ingest",
            params={"source": "supplier-api"},
            approval_gate=HumanApprovalGate(threshold_amount_usd=100000.0),
            ledger=AuditLedger(),
        )
        self.assertEqual(result["status"], "requires_human_approval")

    def test_procurement_agent_rejects_expired_or_unauthorized_tool(self):
        token = AgentSecurityToken(
            agent_id="procurement-agent",
            allowed_tools=["inventory_lookup"],
            ttl_seconds=-1,
        )
        agent = ProcurementAgent("procurement-agent")
        with self.assertRaises(PermissionError):
            agent.execute_tool_call(token, "inventory_lookup", {"vendor_id": "VEND-00001"})

    def test_crypto_engine_round_trip_works_for_aes_gcm(self):
        engine = CryptoEngine("AES-256-GCM")
        key = engine.generate_key()
        payload = engine.encrypt_data("Enterprise Purchase Order #99102", key)
        self.assertEqual(payload["algorithm"], "AES-256-GCM")
        self.assertEqual(engine.decrypt_data(payload, key), "Enterprise Purchase Order #99102")

    def test_crypto_engine_rejects_unsupported_algorithm(self):
        with self.assertRaises(ValueError):
            CryptoEngine("NOT-A-REAL-ALGO")

    def test_aes_strategy_generates_algorithm_specific_payload(self):
        strategy = AES256GCMStrategy()
        key = strategy.generate_key()
        payload = strategy.encrypt("Example payload", key)
        self.assertIn("nonce", payload)
        self.assertIn("ciphertext", payload)
        self.assertEqual(strategy.decrypt(payload, key), "Example payload")

    def test_dlp_engine_redacts_sensitive_fields_and_keeps_tokens(self):
        engine = DlpAnonymizationEngine()
        record = {
            "vendor_id": "VEND-00001",
            "customer_name": "John Doe",
            "ssn": "123-45-6789",
            "internal_api_key": "example_api_key_12345",
            "amount": 2500.0,
        }

        sanitized = engine.sanitize(record)
        self.assertIn("customer_name", sanitized)
        self.assertNotIn("John Doe", sanitized["customer_name"])
        self.assertIn("token", sanitized["customer_name"])
        self.assertIn("token", sanitized["internal_api_key"])
        self.assertEqual(sanitized["amount"], 2500.0)

    def test_receipt_authority_signs_and_validates_execution_proof(self):
        receipt_authority = ReceiptAuthority("enterprise-platform")
        receipt = receipt_authority.issue_receipt(
            vendor_id="VEND-00001",
            action="inventory_sync",
            payload_hash="abc123",
            rule_hash="def456",
            execution_result="approved",
        )

        self.assertIn("receipt_id", receipt)
        self.assertTrue(receipt_authority.verify_receipt(receipt))
        self.assertEqual(receipt["execution_result"], "approved")

    def test_prometheus_query_range_returns_series(self):
        client = app.test_client()
        response = client.get("/api/prometheus/query_range?query=pipeline_throughput")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("data", data)
        self.assertEqual(data["data"]["resultType"], "matrix")
        self.assertTrue(len(data["data"]["result"][0]["values"]) > 0)

    def test_marketplace_fulfillment_gateway_provisions_tenants(self):
        gateway = MarketplaceFulfillmentGateway()

        aws_result = gateway.onboard_aws_marketplace("aws-registration-token-123")
        azure_result = gateway.onboard_azure_marketplace("azure-registration-token-456")

        self.assertEqual(aws_result["status"], "success")
        self.assertEqual(azure_result["status"], "success")
        self.assertIn("tenant_id", aws_result)
        self.assertIn("tenant_id", azure_result)

    def test_marketplace_lifecycle_controller_handles_webhook_events_and_metering(self):
        lifecycle = MarketplaceLifecycleController()

        webhook_result = lifecycle.process_webhook_event({
            "subscriptionId": "sub-123",
            "planId": "pro-plan",
            "action": "ChangePlan",
        })
        self.assertEqual(webhook_result["status"], "acknowledged")
        self.assertEqual(lifecycle.tenants["sub-123"]["plan_id"], "pro-plan")

        deactivate_result = lifecycle.process_webhook_event({
            "subscriptionId": "sub-123",
            "action": "Unsubscribe",
        })
        self.assertEqual(deactivate_result["status"], "acknowledged")
        self.assertFalse(lifecycle.tenants["sub-123"]["active"])

        usage_result = lifecycle.record_usage(
            subscription_id="sub-123",
            metric="vendor_payloads_verified",
            quantity=42,
            unit_price=0.15,
        )
        self.assertEqual(usage_result["quantity"], 42)
        self.assertGreater(usage_result["amount_usd"], 0)

    def test_vendor_document_parsing_agent_extracts_structured_data(self):
        agent = VendorDocumentParsingAgent()
        raw_text = (
            "Vendor ID: VEND-00001\n"
            "Batch Number: BATCH-42\n"
            "SKU: SKU-100\n"
            "Quantity: 12\n"
            "Unit Price USD: 45.5"
        )
        result = agent.process_vendor_document(raw_text)
        self.assertEqual(result["vendor_id"], "VEND-00001")
        self.assertEqual(result["quantity"], 12)
        self.assertEqual(result["unit_price_usd"], 45.5)

    def test_threat_detection_agent_flags_abnormal_vendor_activity(self):
        agent = ThreatDetectionAgent()
        report = agent.inspect_activity([
            {"vendor_id": "VEND-00001", "action": "inventory_sync", "amount_usd": 5000, "count_per_hour": 60},
            {"vendor_id": "VEND-00001", "action": "inventory_sync", "amount_usd": 50000, "count_per_hour": 240},
            {"vendor_id": "VEND-00001", "action": "inventory_sync", "amount_usd": 75000, "count_per_hour": 300},
        ])
        self.assertEqual(report["status"], "alert")
        self.assertGreater(report["risk_score"], 0.5)

    def test_compliance_audit_agent_summarizes_ledger_for_execs(self):
        agent = ComplianceAuditAgent()
        ledger = AuditLedger()
        ledger.append("vendor_ingress", {"vendor_id": "VEND-00001", "amount_usd": 50000, "tool_name": "vendor_ingest"})
        ledger.append("vendor_ingress", {"vendor_id": "VEND-88219", "amount_usd": 150000, "tool_name": "vendor_ingest"})
        summary = agent.summarize_audit_log(ledger)
        self.assertIn("VEND", summary)
        self.assertIn("audit", summary.lower())


if __name__ == "__main__":
    unittest.main()
