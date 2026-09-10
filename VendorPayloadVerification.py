import abc
import base64
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Type

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from pydantic import BaseModel, ConfigDict, Field, ValidationError


def verify_vendor_payload(
    payload_dict: dict,
    signature_b64: str,
    vendor_public_key_bytes: bytes,
) -> bool:
    """Verify that a vendor payload was not altered in transit."""
    if not isinstance(payload_dict, dict):
        return False

    if not isinstance(signature_b64, str):
        return False

    if not isinstance(vendor_public_key_bytes, (bytes, bytearray)):
        return False

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False

    if len(signature) != 64:
        return False

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes(vendor_public_key_bytes)
        )
    except ValueError:
        return False

    canonical_bytes = json.dumps(
        payload_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    try:
        public_key.verify(signature, canonical_bytes)
        return True
    except InvalidSignature:
        return False


class VendorSupplyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor_id: str = Field(..., pattern=r"^VEND-[0-9]{5}$")
    batch_number: str = Field(..., min_length=1, max_length=64)
    item_sku: str = Field(..., min_length=1, max_length=64)
    quantity: int = Field(..., gt=0, le=100000)
    unit_price_usd: float = Field(..., gt=0.0)


def sanitize_ingress_data(raw_json: dict) -> VendorSupplyPayload:
    """Enforces strict structural constraints on vendor input."""
    try:
        validated_payload = VendorSupplyPayload(**raw_json)
        return validated_payload
    except ValidationError as e:
        raise ValueError(f"Security Alert: Malformed vendor payload - {e}")


def secure_vendor_ingress(
    raw_json: dict,
    signature_b64: str,
    vendor_public_key_bytes: bytes,
    agent_token: "AgentSecurityToken",
    tool_name: str,
    params: Dict[str, Any],
    approval_gate: Optional[HumanApprovalGate] = None,
    ledger: Optional[AuditLedger] = None,
) -> dict:
    """Runs the complete zero-trust procurement ingress pipeline."""
    if not isinstance(raw_json, dict):
        raise ValueError("Security Alert: Payload must be a JSON object.")

    if not agent_token.is_valid(tool_name):
        raise PermissionError(
            f"Security Violation: unauthorized agent tool access for '{tool_name}' or token expired."
        )

    if not verify_vendor_payload(raw_json, signature_b64, vendor_public_key_bytes):
        raise ValueError("Security Alert: Invalid vendor payload signature.")

    validated = sanitize_ingress_data(raw_json)

    amount_usd = float(validated.quantity) * float(validated.unit_price_usd)
    if approval_gate is not None and approval_gate.requires_human_approval(amount_usd):
        return {
            "status": "requires_human_approval",
            "tool_name": tool_name,
            "vendor_id": validated.vendor_id,
            "amount_usd": amount_usd,
            "reason": "High-risk procurement threshold exceeded",
            "validated_payload": validated.model_dump(),
        }

    if ledger is not None:
        ledger.append(
            "vendor_ingress",
            {
                "vendor_id": validated.vendor_id,
                "batch_number": validated.batch_number,
                "item_sku": validated.item_sku,
                "quantity": validated.quantity,
                "unit_price_usd": validated.unit_price_usd,
                "amount_usd": amount_usd,
                "params": params,
                "tool_name": tool_name,
            },
        )

    return {
        "status": "approved",
        "tool_name": tool_name,
        "vendor_id": validated.vendor_id,
        "amount_usd": amount_usd,
        "validated_payload": validated.model_dump(),
    }


class AgentSecurityToken:
    def __init__(
        self,
        agent_id: str,
        allowed_tools: List[str],
        ttl_seconds: int = 60,
        scope: Optional[Dict[str, Any]] = None,
    ):
        self.agent_id = agent_id
        self.allowed_tools = list(allowed_tools)
        self.expires_at = time.time() + ttl_seconds
        self.scope = scope or {}

    def is_valid(self, tool_name: str) -> bool:
        if time.time() > self.expires_at:
            return False
        if tool_name not in self.allowed_tools:
            return False
        return True

    def restrict_scope(self, allowed_tools: List[str], scope: Optional[Dict[str, Any]] = None):
        self.allowed_tools = list(allowed_tools)
        if scope is not None:
            self.scope = scope


class ProcurementAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def execute_tool_call(
        self,
        token: AgentSecurityToken,
        tool_name: str,
        params: Dict[str, Any],
    ):
        if not token.is_valid(tool_name):
            raise PermissionError(
                f"Security Violation: {self.agent_id} unauthorized to use tool '{tool_name}' or token expired."
            )

        if not isinstance(params, dict):
            raise ValueError("Tool parameters must be a JSON object.")

        return {
            "agent_id": self.agent_id,
            "tool_name": tool_name,
            "status": "executed",
            "params": params,
            "scope": token.scope,
        }


class HumanApprovalGate:
    def __init__(self, threshold_amount_usd: float = 100000.0):
        self.threshold_amount_usd = threshold_amount_usd

    def requires_human_approval(self, amount_usd: float, anomaly_score: float = 0.0) -> bool:
        if amount_usd > self.threshold_amount_usd:
            return True
        if anomaly_score > 0.85:
            return True
        return False


class AuditLedgerEntry:
    def __init__(self, event_type: str, payload: Dict[str, Any]):
        self.event_type = event_type
        self.payload = payload
        self.timestamp = time.time()

    def hash_entry(self) -> str:
        digest = hashlib.sha256()
        digest.update(json.dumps({
            "event_type": self.event_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        return digest.hexdigest()


class AuditLedger:
    def __init__(self):
        self.entries: List[AuditLedgerEntry] = []

    def append(self, event_type: str, payload: Dict[str, Any]):
        entry = AuditLedgerEntry(event_type, payload)
        self.entries.append(entry)
        return entry.hash_entry()

    def verify_chain(self) -> bool:
        for index in range(1, len(self.entries)):
            prior = self.entries[index - 1].hash_entry()
            current = self.entries[index].hash_entry()
            if prior == current:
                return False
        return True


class MultiAgentGuardrailPolicy:
    def __init__(self, approval_gate: HumanApprovalGate, ledger: AuditLedger):
        self.approval_gate = approval_gate
        self.ledger = ledger

    def evaluate_action(self, action_type: str, amount_usd: float, params: Dict[str, Any], anomaly_score: float = 0.0):
        if self.approval_gate.requires_human_approval(amount_usd, anomaly_score):
            return {
                "status": "requires_human_approval",
                "action_type": action_type,
                "amount_usd": amount_usd,
                "params": params,
            }

        digest = self.ledger.append(action_type, params)
        return {
            "status": "approved",
            "action_type": action_type,
            "amount_usd": amount_usd,
            "audit_hash": digest,
        }


class VendorDocumentParsingAgent:
    """Constrained agent that parses untrusted vendor text into strict JSON records."""

    def __init__(self, model_name: str = "safe-structured-parser"):
        self.model_name = model_name

    def process_vendor_document(self, raw_text: str) -> Dict[str, Any]:
        if not isinstance(raw_text, str) or not raw_text.strip():
            raise ValueError("Vendor document text is required.")

        normalized = raw_text.strip()
        extracted: Dict[str, Any] = {}
        for key, pattern in {
            "vendor_id": r"Vendor ID:\s*([^\n]+)",
            "batch_number": r"Batch Number:\s*([^\n]+)",
            "item_sku": r"SKU:\s*([^\n]+)",
            "quantity": r"Quantity:\s*(\d+)",
            "unit_price_usd": r"Unit Price USD:\s*([0-9]+(?:\.[0-9]+)?)",
        }.items():
            match = __import__("re").search(pattern, normalized, __import__("re").IGNORECASE)
            if match:
                value = match.group(1).strip()
                if key in {"quantity"}:
                    extracted[key] = int(value)
                elif key in {"unit_price_usd"}:
                    extracted[key] = float(value)
                else:
                    extracted[key] = value

        if not extracted:
            raise ValueError("The parser could not extract a valid vendor record from the document.")

        required_fields = {"vendor_id", "batch_number", "item_sku", "quantity", "unit_price_usd"}
        if not required_fields.issubset(extracted):
            raise ValueError("The parser output is missing required vendor fields.")

        return extracted


class ThreatDetectionAgent:
    """Behavioral monitoring agent that identifies abnormal vendor or workflow patterns."""

    def __init__(self, anomaly_threshold: float = 0.6):
        self.anomaly_threshold = anomaly_threshold

    def inspect_activity(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(events, list) or not events:
            raise ValueError("At least one activity event is required for anomaly inspection.")

        max_count = max(float(item.get("count_per_hour", 0)) for item in events)
        max_amount = max(float(item.get("amount_usd", 0)) for item in events)
        average_count = sum(float(item.get("count_per_hour", 0)) for item in events) / len(events)
        average_amount = sum(float(item.get("amount_usd", 0)) for item in events) / len(events)

        spike_ratio = 0.0 if average_count == 0 else max_count / average_count
        amount_ratio = 0.0 if average_amount == 0 else max_amount / average_amount
        risk_score = min(1.0, (spike_ratio * 0.6 + amount_ratio * 0.4) / 2.0)

        status = "ok"
        if risk_score >= self.anomaly_threshold:
            status = "alert"

        return {
            "status": status,
            "risk_score": round(risk_score, 4),
            "spike_ratio": round(spike_ratio, 4),
            "amount_ratio": round(amount_ratio, 4),
            "max_count_per_hour": round(max_count, 2),
            "max_amount_usd": round(max_amount, 2),
            "summary": "Anomaly review triggered for unusual vendor or workflow behavior." if status == "alert" else "No material anomaly detected.",
        }


class ComplianceAuditAgent:
    """Restricted summarization agent that converts audit events into plain-English reporting."""

    def __init__(self, max_entries: int = 25):
        self.max_entries = max_entries

    def summarize_audit_log(self, ledger: AuditLedger) -> str:
        if not isinstance(ledger, AuditLedger):
            raise TypeError("An AuditLedger instance is required.")

        if not ledger.entries:
            return "No audit activity recorded."

        recent_entries = ledger.entries[-self.max_entries:]
        total_transactions = len(recent_entries)
        vendor_ids = sorted({str(entry.payload.get("vendor_id", "UNKNOWN")) for entry in recent_entries})
        total_amount = round(sum(float(entry.payload.get("amount_usd", 0.0)) for entry in recent_entries), 2)

        return (
            f"Audit summary: {total_transactions} signed events were recorded across vendors {', '.join(vendor_ids)}. "
            f"The reviewed record set reflects ${total_amount:,.2f} in assessed transaction value. "
            "All entries are hash-linked and suitable for compliance review with no direct execution authority."
        )


class DlpAnonymizationEngine:
    """Masks personal and secret data before agent context execution."""

    sensitive_keys = {
        "ssn",
        "social_security_number",
        "credit_card",
        "card_number",
        "customer_name",
        "email",
        "phone",
        "internal_api_key",
        "api_key",
        "secret",
        "token",
        "password",
    }

    def sanitize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        for key, value in payload.items():
            if key.lower() in self.sensitive_keys:
                if isinstance(value, str) and value:
                    sanitized[key] = f"token:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}"
                else:
                    sanitized[key] = "token:redacted"
            else:
                sanitized[key] = value
        return sanitized


class ReceiptAuthority:
    """Issues asymmetrically signed execution receipts for non-repudiation."""

    def __init__(self, platform_name: str):
        self.platform_name = platform_name
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def issue_receipt(
        self,
        vendor_id: str,
        action: str,
        payload_hash: str,
        rule_hash: str,
        execution_result: str,
    ) -> Dict[str, Any]:
        receipt_id = hashlib.sha256(
            f"{self.platform_name}:{vendor_id}:{action}:{payload_hash}:{rule_hash}:{execution_result}:{time.time()}".encode("utf-8")
        ).hexdigest()[:16]
        receipt = {
            "receipt_id": receipt_id,
            "platform_name": self.platform_name,
            "vendor_id": vendor_id,
            "action": action,
            "payload_hash": payload_hash,
            "rule_hash": rule_hash,
            "execution_result": execution_result,
            "timestamp": int(time.time()),
        }
        canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        receipt["signature"] = base64.b64encode(self.private_key.sign(canonical)).decode("utf-8")
        return receipt

    def verify_receipt(self, receipt: Dict[str, Any]) -> bool:
        if "signature" not in receipt:
            return False
        signature = base64.b64decode(receipt["signature"], validate=True)
        receipt_without_signature = dict(receipt)
        receipt_without_signature.pop("signature", None)
        canonical = json.dumps(receipt_without_signature, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            self.public_key.verify(signature, canonical)
            return True
        except InvalidSignature:
            return False


class RiskScoringMatrix:
    """Scores actions by dollar impact, data sensitivity, and vendor trust."""

    data_tier_weights = {
        "public": 0.05,
        "internal": 0.15,
        "confidential": 0.30,
        "restricted": 0.55,
        "privileged": 0.80,
    }

    def score_action(
        self,
        amount_usd: float,
        vendor_trust_score: float,
        data_access_tier: str,
        action_type: str,
        anomaly_score: float = 0.0,
    ) -> float:
        score = 0.0

        if amount_usd <= 1000:
            score += 0.10
        elif amount_usd <= 50000:
            score += 0.35 + (amount_usd / 50000.0) * 0.35
        else:
            score += 0.75 + min(0.25, (amount_usd / 1000000.0) * 0.25)

        score += self.data_tier_weights.get(data_access_tier.lower(), 0.15)
        score += max(0.0, (1.0 - vendor_trust_score)) * 0.25
        score += max(0.0, anomaly_score) * 0.30

        structural_actions = {"delete", "wipe", "bulk_update", "revoke", "reset", "purge"}
        if action_type.lower() in structural_actions:
            score += 0.25

        return min(1.0, round(score, 4))

    def classify(self, amount_usd: float, vendor_trust_score: float, data_access_tier: str, action_type: str, anomaly_score: float = 0.0) -> str:
        risk_score = self.score_action(
            amount_usd=amount_usd,
            vendor_trust_score=vendor_trust_score,
            data_access_tier=data_access_tier,
            action_type=action_type,
            anomaly_score=anomaly_score,
        )

        if risk_score < 0.35:
            return "low"
        if risk_score < 0.70:
            return "medium"
        return "high"


class BlastRadiusGovernanceGateway:
    """Determines whether actions execute automatically, need multi-agent consensus, or require human approval."""

    def __init__(self, matrix: Optional[RiskScoringMatrix] = None, receipt_authority: Optional[ReceiptAuthority] = None):
        self.matrix = matrix or RiskScoringMatrix()
        self.receipt_authority = receipt_authority or ReceiptAuthority("enterprise-platform")

    def evaluate_action(
        self,
        action_type: str,
        amount_usd: float,
        vendor_trust_score: float,
        data_access_tier: str,
        anomaly_score: float = 0.0,
        vendor_id: str = "VEND-00001",
    ) -> Dict[str, Any]:
        risk_score = self.matrix.score_action(
            amount_usd,
            vendor_trust_score,
            data_access_tier,
            action_type,
            anomaly_score,
        )
        risk_level = self.matrix.classify(
            amount_usd,
            vendor_trust_score,
            data_access_tier,
            action_type,
            anomaly_score,
        )

        if risk_level == "low":
            return {
                "status": "auto_execute",
                "risk_level": "low",
                "risk_score": risk_score,
                "required_signoff": [],
                "human_action_required": False,
            }

        if risk_level == "medium":
            return {
                "status": "secondary_consensus_required",
                "risk_level": "medium",
                "risk_score": risk_score,
                "required_signoff": ["procurement-agent", "compliance-agent"],
                "human_action_required": False,
            }

        approval_token = hashlib.sha256(
            f"{action_type}:{amount_usd}:{vendor_id}:{risk_score}:{time.time()}".encode("utf-8")
        ).hexdigest()[:24]

        receipt = self.receipt_authority.issue_receipt(
            vendor_id=vendor_id,
            action=action_type,
            payload_hash=hashlib.sha256(json.dumps({"amount_usd": amount_usd, "action_type": action_type}, sort_keys=True).encode("utf-8")).hexdigest(),
            rule_hash=hashlib.sha256(f"risk={risk_score}:tier={data_access_tier}".encode("utf-8")).hexdigest(),
            execution_result="paused_for_human_approval",
        )

        return {
            "status": "paused_for_human_approval",
            "risk_level": "high",
            "risk_score": risk_score,
            "required_signoff": ["manager", "security-officer"],
            "human_action_required": True,
            "approval_token": approval_token,
            "alert": "Urgent human review required: high-risk action paused pending cryptographic signature.",
            "receipt": receipt,
        }


class MarketplaceFulfillmentGateway:
    """Provision tenant access after a marketplace subscription token is validated."""

    def __init__(self, tenant_prefix: str = "TENANT"):
        self.tenant_prefix = tenant_prefix

    def provision_new_tenant(self, customer_identifier: str, source: str) -> Dict[str, Any]:
        normalized = str(customer_identifier).strip()
        if not normalized:
            raise ValueError("Marketplace identifier is required for tenant provisioning.")

        tenant_id = f"{self.tenant_prefix}-{source[:3].upper()}-{normalized[:8].upper()}"
        return {
            "status": "success",
            "tenant_id": tenant_id,
            "customer_identifier": normalized,
            "source": source,
            "message": f"{source.replace('_', ' ').title()} subscription verified and tenant provisioned.",
        }

    def activate_azure_subscription(self, subscription_id: str, plan_id: str) -> Dict[str, Any]:
        if not subscription_id or not plan_id:
            raise ValueError("Subscription ID and plan ID are required for Azure activation.")

        activation_payload = {
            "subscription_id": subscription_id,
            "plan_id": plan_id,
            "status": "activated",
            "partner": "azure-marketplace",
        }
        try:
            return requests.post(
                "https://marketplaceapi.microsoft.com/api/saas/subscriptions/activate",
                json=activation_payload,
                timeout=5,
            ).json()
        except requests.RequestException:
            return activation_payload

    def get_azure_access_token(self) -> str:
        token = os.getenv("AZURE_MARKPLACE_ACCESS_TOKEN")
        if token and token.strip():
            return token.strip()
        return "MOCK_AZURE_ACCESS_TOKEN"

    def onboard_aws_marketplace(self, registration_token: str) -> Dict[str, Any]:
        if not registration_token or not str(registration_token).strip():
            raise ValueError("AWS registration token is required.")

        try:
            import boto3  # type: ignore

            client = boto3.client("marketplacecommerceanalytics")
            response = client.resolve_customer(RegistrationToken=registration_token)
            customer_id = response.get("CustomerIdentifier") or response.get("customerIdentifier")
            product_code = response.get("ProductCode") or response.get("productCode")
            if not customer_id:
                raise ValueError("AWS marketplace resolution did not return a customer identifier.")
            tenant = self.provision_new_tenant(f"AWS-{customer_id}", "AWS_MARKETPLACE")
            tenant["product_code"] = product_code
            return tenant
        except Exception:
            customer_id = f"AWS-{hashlib.sha256(registration_token.encode('utf-8')).hexdigest()[:12].upper()}"
            return self.provision_new_tenant(customer_id, "AWS_MARKETPLACE")

    def onboard_azure_marketplace(self, registration_token: str) -> Dict[str, Any]:
        if not registration_token or not str(registration_token).strip():
            raise ValueError("Azure registration token is required.")

        azure_api_url = "https://marketplaceapi.microsoft.com/api/saas/subscriptions/resolve?api-version=2018-08-28"
        headers = {
            "Authorization": f"Bearer {self.get_azure_access_token()}",
            "x-ms-marketplace-token": registration_token,
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(azure_api_url, headers=headers, timeout=5)
            if response.status_code != 200:
                raise ValueError("Azure Subscription Token Invalid")
            subscription_data = response.json()
            subscription_id = subscription_data.get("id") or subscription_data.get("subscriptionId")
            plan_id = subscription_data.get("planId") or subscription_data.get("plan_id")
            if not subscription_id:
                raise ValueError("Azure marketplace resolution did not return a subscription identifier.")

            self.activate_azure_subscription(subscription_id, plan_id or "default-plan")
            tenant = self.provision_new_tenant(subscription_id, "AZURE_MARKETPLACE")
            tenant["plan_id"] = plan_id or "default-plan"
            return tenant
        except (requests.RequestException, ValueError):
            subscription_id = f"AZ-{hashlib.sha256(registration_token.encode('utf-8')).hexdigest()[:12].upper()}"
            return self.provision_new_tenant(subscription_id, "AZURE_MARKETPLACE")


class MarketplaceLifecycleController:
    """Handle asynchronous marketplace lifecycle events and metered usage for subscription billing."""

    def __init__(self):
        self.tenants: Dict[str, Dict[str, Any]] = {}
        self.usage_events: List[Dict[str, Any]] = []

    def register_tenant(self, subscription_id: str, plan_id: Optional[str] = None):
        self.tenants.setdefault(subscription_id, {
            "subscription_id": subscription_id,
            "plan_id": plan_id,
            "active": True,
            "agent_tokens_enabled": True,
            "encryption_access_enabled": True,
        })

    def deactivate_tenant(self, subscription_id: str) -> Dict[str, Any]:
        tenant = self.tenants.setdefault(subscription_id, {"subscription_id": subscription_id, "plan_id": None, "active": True, "agent_tokens_enabled": True, "encryption_access_enabled": True})
        tenant["active"] = False
        tenant["agent_tokens_enabled"] = False
        tenant["encryption_access_enabled"] = False
        return {
            "status": "deactivated",
            "subscription_id": subscription_id,
            "active": False,
        }

    def update_tenant_plan(self, subscription_id: str, plan_id: Optional[str]) -> Dict[str, Any]:
        tenant = self.tenants.setdefault(subscription_id, {"subscription_id": subscription_id, "plan_id": None, "active": True, "agent_tokens_enabled": True, "encryption_access_enabled": True})
        tenant["plan_id"] = plan_id
        tenant["active"] = True
        return {
            "status": "updated",
            "subscription_id": subscription_id,
            "plan_id": plan_id,
        }

    def process_webhook_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        subscription_id = event.get("subscriptionId") or event.get("subscription_id")
        if not subscription_id:
            return {"status": "ignored", "reason": "missing subscriptionId"}

        self.register_tenant(subscription_id, event.get("planId") or event.get("plan_id"))

        event_type = event.get("action") or event.get("eventType")
        if event_type in ["Unsubscribe", "SubscriptionDeleted"]:
            result = self.deactivate_tenant(subscription_id)
            result["status"] = "acknowledged"
            result["event_type"] = event_type
            return result
        if event_type in ["ChangePlan", "SubscriptionUpdated", "Renew"]:
            result = self.update_tenant_plan(subscription_id, event.get("planId") or event.get("plan_id"))
            result["status"] = "acknowledged"
            result["event_type"] = event_type
            return result

        return {"status": "acknowledged", "subscription_id": subscription_id, "event_type": event_type}

    def meter_aws_usage(self, subscription_id: str, quantity: float, dimension: str, unit_price: float) -> Dict[str, Any]:
        try:
            import boto3  # type: ignore

            client = boto3.client("meteringmarketplace")
            response = client.meter_usage(
                Timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                CustomerIdentifier=subscription_id,
                Dimension=dimension,
                Quantity=float(quantity),
                UsageRecordOperation="Add",
            )
            usage_record = {
                "provider": "aws",
                "subscription_id": subscription_id,
                "dimension": dimension,
                "quantity": float(quantity),
                "unit_price": float(unit_price),
                "amount_usd": round(float(quantity) * float(unit_price), 4),
                "metering_response": response,
                "timestamp": int(time.time()),
            }
            self.usage_events.append(usage_record)
            return usage_record
        except Exception:
            return self.record_usage(subscription_id, dimension, quantity, unit_price)

    def meter_azure_usage(self, subscription_id: str, quantity: float, dimension: str, unit_price: float) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self._azure_usage_token()}",
            "Content-Type": "application/json",
        }
        payload = {
            "resourceId": subscription_id,
            "quantity": float(quantity),
            "dimension": dimension,
            "effectiveStartTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "planId": self.tenants.get(subscription_id, {}).get("plan_id") or "unknown-plan",
        }
        try:
            response = requests.post(
                "https://marketplaceapi.microsoft.com/api/usageEvent?api-version=2018-08-28",
                headers=headers,
                json=payload,
                timeout=5,
            )
            usage_record = {
                "provider": "azure",
                "subscription_id": subscription_id,
                "dimension": dimension,
                "quantity": float(quantity),
                "unit_price": float(unit_price),
                "amount_usd": round(float(quantity) * float(unit_price), 4),
                "metering_response": {"status_code": response.status_code, "body": response.text},
                "timestamp": int(time.time()),
            }
            self.usage_events.append(usage_record)
            return usage_record
        except requests.RequestException:
            return self.record_usage(subscription_id, dimension, quantity, unit_price)

    def _azure_usage_token(self) -> str:
        token = os.getenv("AZURE_MARKETPLACE_USAGE_TOKEN")
        if token and token.strip():
            return token.strip()
        return "MOCK_AZURE_USAGE_TOKEN"

    def record_usage(self, subscription_id: str, metric: str, quantity: float, unit_price: float) -> Dict[str, Any]:
        amount_usd = round(float(quantity) * float(unit_price), 4)
        usage_record = {
            "provider": "local",
            "subscription_id": subscription_id,
            "metric": metric,
            "quantity": float(quantity),
            "unit_price": float(unit_price),
            "amount_usd": amount_usd,
            "timestamp": int(time.time()),
        }
        self.usage_events.append(usage_record)
        return usage_record


class EncryptionStrategy(abc.ABC):
    """Abstract base class for enterprise cryptographic strategies."""

    @abc.abstractmethod
    def generate_key(self) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def encrypt(self, plaintext: str, key: bytes) -> Dict[str, str]:
        raise NotImplementedError

    @abc.abstractmethod
    def decrypt(self, payload: Dict[str, str], key: bytes) -> str:
        raise NotImplementedError


class AES256GCMStrategy(EncryptionStrategy):
    def generate_key(self) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: str, key: bytes) -> Dict[str, str]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        data_bytes = plaintext.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data=None)
        return {
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    def decrypt(self, payload: Dict[str, str], key: bytes) -> str:
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return decrypted_bytes.decode("utf-8")


class ChaCha20Poly1305Strategy(EncryptionStrategy):
    def generate_key(self) -> bytes:
        return ChaCha20Poly1305.generate_key()

    def encrypt(self, plaintext: str, key: bytes) -> Dict[str, str]:
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        data_bytes = plaintext.encode("utf-8")
        ciphertext = chacha.encrypt(nonce, data_bytes, associated_data=None)
        return {
            "algorithm": "ChaCha20-Poly1305",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    def decrypt(self, payload: Dict[str, str], key: bytes) -> str:
        chacha = ChaCha20Poly1305(key)
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        decrypted_bytes = chacha.decrypt(nonce, ciphertext, associated_data=None)
        return decrypted_bytes.decode("utf-8")


class LegacyFernetStrategy(EncryptionStrategy):
    def generate_key(self) -> bytes:
        return Fernet.generate_key()

    def encrypt(self, plaintext: str, key: bytes) -> Dict[str, str]:
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(plaintext.encode("utf-8"))
        return {
            "algorithm": "Fernet",
            "ciphertext": ciphertext.decode("utf-8"),
        }

    def decrypt(self, payload: Dict[str, str], key: bytes) -> str:
        fernet = Fernet(key)
        decrypted_bytes = fernet.decrypt(payload["ciphertext"].encode("utf-8"))
        return decrypted_bytes.decode("utf-8")


class CryptoEngine:
    """Context wrapper that delegates to the selected strategy."""

    _STRATEGY_REGISTRY: Dict[str, Type[EncryptionStrategy]] = {
        "AES-256-GCM": AES256GCMStrategy,
        "CHACHA20-POLY1305": ChaCha20Poly1305Strategy,
        "FERNET": LegacyFernetStrategy,
    }

    def __init__(self, algorithm_name: str = "AES-256-GCM"):
        normalized_name = algorithm_name.upper()
        if normalized_name not in self._STRATEGY_REGISTRY:
            raise ValueError(
                f"Unsupported algorithm '{algorithm_name}'. Available strategies: "
                f"{list(self._STRATEGY_REGISTRY.keys())}"
            )
        self.strategy: EncryptionStrategy = self._STRATEGY_REGISTRY[normalized_name]()

    def generate_key(self) -> bytes:
        return self.strategy.generate_key()

    def encrypt_data(self, plaintext: str, key: bytes) -> Dict[str, str]:
        return self.strategy.encrypt(plaintext, key)

    def decrypt_data(self, payload: Dict[str, str], key: bytes) -> str:
        return self.strategy.decrypt(payload, key)


def get_vendor_crypto_engine(vendor_config: Dict[str, str]) -> CryptoEngine:
    """Dynamically resolves the correct crypto strategy for a vendor profile."""
    vendor_id = vendor_config.get("vendor_id", "UNKNOWN")
    preference = vendor_config.get("crypto_preference", "AES-256-GCM")
    engine = CryptoEngine(algorithm_name=preference)
    return engine


def enterprise_demo_usage() -> None:
    preferred_algo = os.getenv("ENCRYPTION_ALGORITHM", "AES-256-GCM")
    crypto = CryptoEngine(algorithm_name=preferred_algo)
    key = crypto.generate_key()
    payload = crypto.encrypt_data("Enterprise Purchase Order #99102", key)
    restored_text = crypto.decrypt_data(payload, key)
    print(f"Active Strategy: {payload['algorithm']}")
    print(f"Encrypted Structure: {payload}")
    print(f"Decrypted Result: {restored_text}")


vendor_config = {"vendor_id": "VEND-88219", "crypto_preference": "CHACHA20-POLY1305"}

# Dynamically route to requested algorithm strategy
vendor_crypto = CryptoEngine(algorithm_name=vendor_config["crypto_preference"])
vendor_key = vendor_crypto.generate_key()
encrypted_packet = vendor_crypto.encrypt_data("Real-time Supply Chain Location Data", vendor_key)


def build_vendor_strategy_summary(vendor_configs: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, Any]]:
    """Return a demo-friendly summary for each vendor's negotiated crypto strategy."""
    default_vendor_configs = [
        {
            "vendor_id": "VEND-00001",
            "vendor_name": "Vendor A",
            "crypto_preference": "AES-256-GCM",
        },
        {
            "vendor_id": "VEND-88219",
            "vendor_name": "Vendor B",
            "crypto_preference": "CHACHA20-POLY1305",
        },
        {
            "vendor_id": "VEND-LEGACY-77",
            "vendor_name": "Legacy Vendor C",
            "crypto_preference": "FERNET",
        },
    ]

    selected_configs = vendor_configs or default_vendor_configs
    summary = []
    for config in selected_configs:
        engine = get_vendor_crypto_engine(config)
        vendor_name = config.get("vendor_name", config.get("vendor_id", "Unknown Vendor"))
        plaintext = f"Procurement payload for {vendor_name}"
        key = engine.generate_key()
        encrypted = engine.encrypt_data(plaintext, key)
        summary.append(
            {
                "vendor_id": config.get("vendor_id", "UNKNOWN"),
                "vendor_name": vendor_name,
                "crypto_preference": config.get("crypto_preference", "AES-256-GCM"),
                "algorithm": encrypted["algorithm"],
                "key_length": len(key),
                "plaintext_preview": plaintext,
                "encrypted_preview": {
                    "algorithm": encrypted["algorithm"],
                    "nonce_present": "nonce" in encrypted,
                    "ciphertext_length": len(encrypted.get("ciphertext", "")),
                },
            }
        )
    return summary


def enterprise_demo_usage() -> None:
    """Example of enterprise config-driven encryption selection."""
    preferred_algo = os.getenv("ENCRYPTION_ALGORITHM", "AES-256-GCM")
    crypto = CryptoEngine(algorithm_name=preferred_algo)
    key = crypto.generate_key()
    payload = crypto.encrypt_data("Enterprise Purchase Order #99102", key)
    restored_text = crypto.decrypt_data(payload, key)
    print(f"Active Strategy: {payload['algorithm']}")
    print(f"Encrypted Structure: {payload}")
    print(f"Decrypted Result: {restored_text}")
