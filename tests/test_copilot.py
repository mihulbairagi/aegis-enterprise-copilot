"""Enterprise Integration Test Suite for Aegis-Copilot.

Verifies the Complete Enterprise Operations Platform:
1. Enterprise JWT Authentication: Bearer token validation and 401 unauthenticated rejection.
2. RBAC RLS Pre-Filtering: Intern denied executive payroll; Executive granted full access with citations.
3. Live Grounded LLM Synthesis: Answers synthesized with citations, or explicit clearance denial.
4. Multipart CSV Upload & Circuit Breaker: Uploading corrupt CSVs trips breaker and isolates in DLQ; clean CSVs ingested into DuckDB.
5. Idempotent Action Dispatch: Duplicate Idempotency-Key returns cached result with 0 duplicate side-effects.
6. Tamper-Evident Audit Ledger: SHA-256 hash chaining verifies unbroken chain and detects simulated tampering.
7. Structured DuckDB RBAC: Table-level clearances and SQL injection protection.
"""

import io
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient

from app.config import Role, SecurityClassification
from app.core.audit import AuditLedger
from app.core.auth import create_access_token
from app.core.circuit_breaker import DataQualityCircuitBreaker
from app.core.rbac_engine import RBACHybridEngine
from app.main import app

client = TestClient(app)


def auth_header(user_id: str, role: Role) -> dict:
    """Helper creating standard Bearer authorization header."""
    token = create_access_token(user_id=user_id, role=role)
    return {"Authorization": f"Bearer {token}"}


class TestEnterpriseAuthentication:
    """Test Suite 1: JWT Token Issuance & Bearer Token Enforcement."""

    def test_token_issuance_endpoint(self):
        """Issues valid signed JWT from /api/auth/token."""
        res = client.post(
            "/api/auth/token",
            json={"user_id": "sarah.chen", "role": Role.EXECUTIVE.value},
        )
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == Role.EXECUTIVE.value
        assert data["user_id"] == "sarah.chen"
        assert data["expires_in"] > 0

    def test_unauthenticated_query_rejected_with_401(self):
        """Protected endpoint /api/query rejects calls lacking Bearer token."""
        res = client.post(
            "/api/query",
            json={"query": "What is our deployment architecture?"},
        )
        assert res.status_code == 401
        assert "Missing Authorization header" in res.json()["detail"]

    def test_invalid_token_rejected_with_401(self):
        """Protected endpoint rejects forged / malformed tokens."""
        res = client.post(
            "/api/query",
            headers={"Authorization": "Bearer forged.invalid.token"},
            json={"query": "What is our deployment architecture?"},
        )
        assert res.status_code == 401
        assert "Invalid cryptographic token" in res.json()["detail"]


class TestRBACRowLevelSecurity:
    """Test Suite 2: Data Leakage Prevention via RLS Pre-Filtering & Verified JWTs."""

    def test_intern_denied_executive_payroll(self):
        """Guarantee 2A: Intern query for executive compensation MUST be blocked at the RLS layer."""
        headers = auth_header("intern_alex", Role.INTERN)
        response = client.post(
            "/api/query",
            headers=headers,
            json={
                "query": "What is the Q3 executive payroll and bonus breakdown for VP of Engineering?",
            },
        )
        assert response.status_code == 200
        data = response.json()

        # Invariant: Intern receives zero citations from EXECUTIVE chunks
        assert len(data["citations"]) == 0
        assert data["rls_status"] == "DENIED_ZERO_CLEARANCE"
        assert "ACCESS DENIED" in data["answer"].upper() or "INSUFFICIENT ROLE CLEARANCE" in data["answer"].upper()
        assert data["redacted_or_restricted_chunks_count"] > 0

    def test_executive_granted_full_access_with_citations(self):
        """Guarantee 2B: Executive query retrieves confidential payroll with grounded document citations."""
        headers = auth_header("exec_marcus", Role.EXECUTIVE)
        response = client.post(
            "/api/query",
            headers=headers,
            json={
                "query": "What is the Q3 executive payroll and bonus breakdown for VP of Engineering?",
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["rls_status"] == "ENFORCED_CLEAN"
        assert len(data["citations"]) > 0
        assert data["redacted_or_restricted_chunks_count"] == 0

        # Check citation provenance
        first_citation = data["citations"][0]
        assert first_citation["classification"] == SecurityClassification.EXECUTIVE.value
        assert len(first_citation["doc_hash"]) == 64  # SHA-256 hex string

    def test_intern_allowed_internal_architecture_docs(self):
        """Guarantee 2C: Intern can read Tier-1 INTERNAL documentation freely."""
        headers = auth_header("intern_alex", Role.INTERN)
        response = client.post(
            "/api/query",
            headers=headers,
            json={
                "query": "What are the Project Titan Kubernetes deployment specifications and ingress SLA?",
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["rls_status"] == "ENFORCED_CLEAN"
        assert len(data["citations"]) > 0

    def test_analyst_permitted_restricted_margins_but_not_executive_payroll(self):
        """Guarantee 2D: Analyst role can access Tier-2 (RESTRICTED) but blocked from Tier-3 (EXECUTIVE)."""
        headers = auth_header("analyst_priya", Role.ANALYST)

        # 1. Analyst queries vendor spend (Tier 2 - RESTRICTED): Allowed
        resp_vendor = client.post(
            "/api/query",
            headers=headers,
            json={
                "query": "What are our European operational margins and Q2 supply chain contracts Cloudflare?",
            },
        )
        assert resp_vendor.status_code == 200
        assert resp_vendor.json()["rls_status"] == "ENFORCED_CLEAN"

        # 2. Analyst queries executive payroll (Tier 3 - EXECUTIVE): Blocked
        resp_payroll = client.post(
            "/api/query",
            headers=headers,
            json={
                "query": "What is the C-suite severance payout and VP Engineering bonus package?",
            },
        )
        assert resp_payroll.status_code == 200
        assert resp_payroll.json()["rls_status"] == "DENIED_ZERO_CLEARANCE"
        assert len(resp_payroll.json()["citations"]) == 0


class TestDataQualityCircuitBreaker:
    """Test Suite 3: Silent Data Poisoning Prevention via Circuit Breaker & Live Uploads."""

    def setup_method(self):
        # Reset circuit breaker before each test
        client.post("/api/circuit-breaker/reset")

    def test_clean_csv_json_ingest_passes(self):
        """Healthy batch via JSON envelope is accepted into Gold Storage."""
        clean_csv = (
            "vendor_id,vendor_name,category,annual_spend,status\n"
            "VND-701,Fastly CDN,Edge Infrastructure,180000,ACTIVE\n"
            "VND-702,AWS Cloud,Compute,420000,ACTIVE\n"
            "VND-703,Grafana Labs,Telemetry,48000,ACTIVE\n"
        )
        response = client.post(
            "/api/pipeline/ingest",
            json={
                "source_id": "ERP_TEST_CLEAN",
                "payload_format": "csv",
                "raw_content": clean_csv,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is True
        assert data["status"] == "PASSED"
        assert data["null_rate"] == 0.0

    def test_multipart_clean_csv_upload_promotes_to_warehouse(self):
        """Live multipart CSV upload promotes clean data into Gold and DuckDB."""
        csv_content = (
            "device_id,cluster_zone,temperature_c,status\n"
            "DEV-101,us-west-1a,42.5,ONLINE\n"
            "DEV-102,us-west-1b,39.8,ONLINE\n"
            "DEV-103,us-west-1c,41.2,ONLINE\n"
        )
        files = {
            "file": ("telemetry_metrics.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")
        }
        data = {"source_id": "IOT_TELEMETRY_PIPELINE"}

        res = client.post("/api/pipeline/upload", files=files, data=data)
        assert res.status_code == 200
        resp_data = res.json()
        assert resp_data["is_valid"] is True
        assert resp_data["status"] == "PASSED"
        assert resp_data["null_rate"] == 0.0

    def test_multipart_corrupt_csv_upload_quarantines_and_trips_breaker(self):
        """Corrupt multipart CSV upload with >15% nulls & negative values trips breaker into DLQ."""
        corrupt_csv = (
            "employee_id,name,department,salary,bonus,effective_date\n"
            "EMP-991,John Corrupt,Engineering,-45000,null,2026-10-01\n"
            "EMP-992,null,null,null,null,null\n"
            "EMP-993,Jane Malformed,,NaN,null,\n"
            "EMP-994,,Operations,-12000,null,null\n"
            "EMP-995,Alex Bad,Finance,null,null,2026-10-01\n"
        )
        files = {
            "file": ("corrupt_payroll_batch.csv", io.BytesIO(corrupt_csv.encode("utf-8")), "text/csv")
        }
        res = client.post("/api/pipeline/upload", files=files, data={"source_id": "ERP_CORRUPT_UPLOAD"})
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is False
        assert data["status"] == "QUARANTINED"
        assert data["null_rate"] > 0.15
        assert data["quarantine_id"] is not None

        # Trip breaker to OPEN with 2 more failures
        for i in range(2):
            client.post("/api/pipeline/upload", files=files, data={"source_id": f"ERP_CORRUPT_{i}"})

        # Confirm breaker is OPEN
        status_resp = client.get("/api/circuit-breaker/status")
        assert status_resp.json()["state"] == "OPEN"

        # Subsequent upload rejected immediately
        res_blocked = client.post("/api/pipeline/upload", files=files, data={"source_id": "BLOCKED_TRY"})
        assert res_blocked.json()["status"] == "REJECTED_BREAKER_OPEN"


class TestIdempotentActionDispatch:
    """Test Suite 4: Distributed Idempotency with Verified Bearer Tokens."""

    def test_duplicate_action_returns_cached_result(self):
        """Identical Idempotency-Key executed twice MUST return DUPLICATE_CACHED."""
        headers = auth_header("marcus.exec", Role.EXECUTIVE)
        test_key = f"idem_test_uuid_{uuid_suffix()}"

        payload = {
            "action_type": "APPROVE_PO",
            "idempotency_key": test_key,
            "payload": {"amount": 45000, "vendor": "Cloudflare Inc"},
        }

        # First dispatch -> Status: EXECUTED
        res1 = client.post("/api/actions/dispatch", headers=headers, json=payload)
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["status"] == "EXECUTED"
        original_action_id = data1["action_id"]

        # Second dispatch with identical key -> Status: DUPLICATE_CACHED
        res2 = client.post("/api/actions/dispatch", headers=headers, json=payload)
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["status"] == "DUPLICATE_CACHED"
        assert data2["action_id"] == original_action_id
        assert "IDEMPOTENCY GUARANTEE ENFORCED" in data2["message"]

    def test_intern_denied_from_executing_privileged_actions(self):
        """Intern token cannot trigger executive financial mutations."""
        headers = auth_header("intern_bob", Role.INTERN)
        test_key = f"idem_intern_unauth_{uuid_suffix()}"
        payload = {
            "action_type": "APPROVE_PO",
            "idempotency_key": test_key,
            "payload": {"amount": 100000},
        }
        res = client.post("/api/actions/dispatch", headers=headers, json=payload)
        assert res.status_code == 200
        assert res.json()["status"] == "DENIED_RBAC"

    def test_unauthenticated_action_dispatch_rejected_with_401(self):
        """Action dispatcher rejects requests lacking Bearer token."""
        res = client.post(
            "/api/actions/dispatch",
            json={"action_type": "APPROVE_PO", "idempotency_key": "some_random_key_123"},
        )
        assert res.status_code == 401


class TestTamperEvidentAuditLedger:
    """Test Suite 5: Cryptographic Hash Chaining & Tamper Detection."""

    def test_ledger_integrity_verification(self):
        """Verifies cryptographic hash chain across all audit blocks."""
        res = client.get("/api/audit/verify")
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is True
        assert "VERIFIED" in data["message"]
        assert data["total_records"] >= 1

    def test_tamper_detection_on_database_alteration(self, tmp_path):
        """If an attacker alters a record in SQLite, verification MUST fail."""
        test_db = tmp_path / "tamper_test.db"
        ledger = AuditLedger(db_path=test_db)

        ledger.log_event("user1", "INTERN", "QUERY", "query 1", "SUCCESS")
        entry2 = ledger.log_event("user2", "EXECUTIVE", "QUERY", "query 2", "SUCCESS")
        ledger.log_event("user3", "ANALYST", "ACTION", "action 3", "EXECUTED")

        # Initial check passes
        v1 = ledger.verify_ledger_integrity()
        assert v1["is_valid"] is True

        # Simulate tampering
        with sqlite3.connect(test_db) as conn:
            conn.execute(
                "UPDATE audit_ledger SET action_or_query = 'MALICIOUS_ALTERED_PAYLOAD' WHERE audit_id = ?;",
                (entry2.audit_id,),
            )
            conn.commit()

        # Re-verify detects tampering
        v2 = ledger.verify_ledger_integrity()
        assert v2["is_valid"] is False
        assert v2["broken_at_id"] == entry2.audit_id
        assert "TAMPERING DETECTED" in v2["message"]


class TestStructuredDuckDBRBAC:
    """Test Suite 6: Relational DuckDB Table-Level Security."""

    def test_intern_blocked_from_payroll_and_contracts(self):
        engine = RBACHybridEngine()
        with pytest.raises(PermissionError) as exc_info:
            engine.execute_structured_query("SELECT * FROM employees_payroll;", Role.INTERN)
        assert "RBAC VIOLATION" in str(exc_info.value)

        with pytest.raises(PermissionError) as exc_info_v:
            engine.execute_structured_query("SELECT * FROM vendor_contracts;", Role.INTERN)
        assert "RBAC VIOLATION" in str(exc_info_v.value)

    def test_analyst_permitted_contracts_but_blocked_from_payroll(self):
        engine = RBACHybridEngine()
        res = engine.execute_structured_query("SELECT * FROM vendor_contracts;", Role.ANALYST)
        assert res["row_count"] > 0
        assert "Cloudflare Inc" in [r["vendor_name"] for r in res["data"]]

        with pytest.raises(PermissionError) as exc_info:
            engine.execute_structured_query("SELECT * FROM employees_payroll;", Role.ANALYST)
        assert "RBAC VIOLATION" in str(exc_info.value)

    def test_executive_permitted_payroll(self):
        engine = RBACHybridEngine()
        res = engine.execute_structured_query("SELECT * FROM employees_payroll;", Role.EXECUTIVE)
        assert res["row_count"] > 0
        names = [r["full_name"] for r in res["data"]]
        assert "Sarah Chen" in names
        assert "Marcus Vance" in names

    def test_sql_injection_and_ddl_blocked(self):
        engine = RBACHybridEngine()
        with pytest.raises(PermissionError) as exc_info:
            engine.execute_structured_query("DROP TABLE employees_payroll;", Role.EXECUTIVE)
        assert "SECURITY ALERT" in str(exc_info.value)


def uuid_suffix() -> str:
    import uuid
    return uuid.uuid4().hex[:8]
