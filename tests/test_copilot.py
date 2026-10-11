"""Enterprise Integration Test Suite for Aegis-Copilot.

Verifies the Complete Enterprise Operations Platform:
1. Enterprise JWT Authentication: Salted credentials validation, token issuance, and 401 unauthenticated rejection.
2. Administrative Endpoint Protection: RBAC enforcement on audit and circuit breaker reset (401/403).
3. RBAC RLS Pre-Filtering & Zero Metadata Leakage: Intern denied executive payroll with zero oracle side-channels.
4. Live Grounded LLM Synthesis: Full chunk context passed to LLM; citations preserved.
5. Multipart CSV Upload & Circuit Breaker: Quarantines corrupt CSVs to DLQ; clean CSVs ingested into DuckDB.
6. Idempotent Action Dispatch: User-scoped keys, duplicate caching, and 422 payload mismatch rejection.
7. Tamper-Evident Audit Ledger: SQLite triggers strictly prevent UPDATE/DELETE; SHA-256 hash chaining detects alterations.
8. Structured DuckDB RBAC: Table-level clearances and SQL injection protection.
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
    """Test Suite 1: Salted Enterprise Authentication & JWT Issuance."""

    def test_token_issuance_valid_credentials(self):
        """Issues valid signed JWT when presenting verified enterprise credentials."""
        # 1. Executive
        res_exec = client.post(
            "/api/auth/token",
            json={"username": "exec_user", "password": "exec_pass_2026"},
        )
        assert res_exec.status_code == 200
        data_exec = res_exec.json()
        assert "access_token" in data_exec
        assert data_exec["token_type"] == "bearer"
        assert data_exec["role"] == Role.EXECUTIVE.value
        assert data_exec["user_id"] == "exec_marcus"
        assert data_exec["expires_in"] > 0

        # 2. Analyst
        res_analyst = client.post(
            "/api/auth/token",
            json={"username": "analyst_user", "password": "analyst_pass_2026"},
        )
        assert res_analyst.status_code == 200
        assert res_analyst.json()["role"] == Role.ANALYST.value

        # 3. Intern
        res_intern = client.post(
            "/api/auth/token",
            json={"username": "intern_user", "password": "intern_pass_2026"},
        )
        assert res_intern.status_code == 200
        assert res_intern.json()["role"] == Role.INTERN.value

    def test_invalid_credentials_rejected_with_401(self):
        """Rejects incorrect password or unmapped username with 401."""
        res_bad_pw = client.post(
            "/api/auth/token",
            json={"username": "exec_user", "password": "WRONG_PASSWORD_123"},
        )
        assert res_bad_pw.status_code == 401
        assert "Invalid enterprise username or password" in res_bad_pw.json()["detail"]

        res_bad_user = client.post(
            "/api/auth/token",
            json={"username": "non_existent_user", "password": "any_password"},
        )
        assert res_bad_user.status_code == 401

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


class TestAdminEndpointsProtection:
    """Test Suite 2: Administrative Endpoint RBAC Guards."""

    def test_admin_endpoints_require_executive_role(self):
        """Non-executive users are blocked with 403 Forbidden on administrative endpoints."""
        endpoints = [
            ("POST", "/api/circuit-breaker/reset", {}),
            ("GET", "/api/audit/logs", None),
            ("GET", "/api/audit/verify", None),
            ("GET", "/api/storage/quarantine", None),
        ]

        intern_hdr = auth_header("intern_alex", Role.INTERN)
        analyst_hdr = auth_header("analyst_priya", Role.ANALYST)
        exec_hdr = auth_header("exec_marcus", Role.EXECUTIVE)

        for method, path, body in endpoints:
            # 1. Unauthenticated -> 401
            if method == "POST":
                res_unauth = client.post(path, json=body or {})
            else:
                res_unauth = client.get(path)
            assert res_unauth.status_code == 401, f"{path} did not reject unauthenticated call"

            # 2. Intern -> 403
            if method == "POST":
                res_intern = client.post(path, headers=intern_hdr, json=body or {})
            else:
                res_intern = client.get(path, headers=intern_hdr)
            assert res_intern.status_code == 403, f"{path} did not block INTERN with 403"

            # 3. Analyst -> 403
            if method == "POST":
                res_analyst = client.post(path, headers=analyst_hdr, json=body or {})
            else:
                res_analyst = client.get(path, headers=analyst_hdr)
            assert res_analyst.status_code == 403, f"{path} did not block ANALYST with 403"

            # 4. Executive -> 200
            if method == "POST":
                res_exec = client.post(path, headers=exec_hdr, json=body or {})
            else:
                res_exec = client.get(path, headers=exec_hdr)
            assert res_exec.status_code == 200, f"{path} failed for EXECUTIVE"


class TestRBACRowLevelSecurity:
    """Test Suite 3: Data Leakage Prevention & Zero Metadata Leakage."""

    def test_intern_denied_executive_payroll(self):
        """Guarantee 3A: Intern query for executive compensation MUST receive zero citations and 0 redacted count."""
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
        assert data["rls_status"] == "NO_RECORDS_FOUND"
        assert data["answer"] == "No accessible records found matching your query."
        # Crucial zero metadata leak: client response reports 0 redacted chunks
        assert data["redacted_or_restricted_chunks_count"] == 0

    def test_zero_metadata_leakage_oracle_resistance(self):
        """Guarantee 3B: Attacker cannot probe existence of restricted data through response differences."""
        headers = auth_header("intern_alex", Role.INTERN)

        # 1. Query targeting confidential project
        resp_classified = client.post(
            "/api/query",
            headers=headers,
            json={"query": "What is the confidential C-suite severance protocol and single-trigger RSUs?"},
        )
        data_classified = resp_classified.json()

        # 2. Query targeting completely non-existent nonsense
        resp_nonsense = client.post(
            "/api/query",
            headers=headers,
            json={"query": "zyxwvutsrqponmlkjihgfedcba non_existent_gibberish_98765"},
        )
        data_nonsense = resp_nonsense.json()

        # Both MUST yield identical responses to the client
        assert data_classified["answer"] == data_nonsense["answer"] == "No accessible records found matching your query."
        assert data_classified["redacted_or_restricted_chunks_count"] == data_nonsense["redacted_or_restricted_chunks_count"] == 0
        assert data_classified["citations"] == data_nonsense["citations"] == []

    def test_executive_granted_full_access_with_citations(self):
        """Guarantee 3C: Executive query retrieves confidential payroll with grounded document citations."""
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
        """Guarantee 3D: Intern can read Tier-1 INTERNAL documentation freely."""
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
        """Guarantee 3E: Analyst role can access Tier-2 (RESTRICTED) but blocked from Tier-3 (EXECUTIVE)."""
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

        # 2. Analyst queries executive payroll (Tier 3 - EXECUTIVE): Blocked with zero oracle feedback
        resp_payroll = client.post(
            "/api/query",
            headers=headers,
            json={
                "query": "What is the C-suite severance payout and VP Engineering bonus package?",
            },
        )
        assert resp_payroll.status_code == 200
        assert resp_payroll.json()["answer"] == "No accessible records found matching your query."
        assert len(resp_payroll.json()["citations"]) == 0
        assert resp_payroll.json()["redacted_or_restricted_chunks_count"] == 0


class TestDataQualityCircuitBreaker:
    """Test Suite 4: Silent Data Poisoning Prevention via Circuit Breaker & Live Uploads."""

    def setup_method(self):
        # Reset circuit breaker before each test with executive authorization
        client.post("/api/circuit-breaker/reset", headers=auth_header("exec_marcus", Role.EXECUTIVE))

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
    """Test Suite 5: User-Scoped Idempotency with Payload Mismatch Checks."""

    def test_duplicate_action_returns_cached_result(self):
        """Identical Idempotency-Key executed twice MUST return DUPLICATE_CACHED."""
        headers = auth_header("exec_marcus", Role.EXECUTIVE)
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

        # Second dispatch with identical key and identical payload -> Status: DUPLICATE_CACHED
        res2 = client.post("/api/actions/dispatch", headers=headers, json=payload)
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["status"] == "DUPLICATE_CACHED"
        assert data2["action_id"] == original_action_id
        assert "IDEMPOTENCY GUARANTEE ENFORCED" in data2["message"]

    def test_idempotency_payload_mismatch_rejected_with_422(self):
        """Same idempotency key submitted with different payload parameters MUST be rejected with 422."""
        headers = auth_header("exec_marcus", Role.EXECUTIVE)
        test_key = f"idem_mismatch_key_{uuid_suffix()}"

        # 1. Initial valid dispatch
        payload_orig = {
            "action_type": "APPROVE_PO",
            "idempotency_key": test_key,
            "payload": {"amount": 25000, "vendor": "Cloudflare Inc"},
        }
        res1 = client.post("/api/actions/dispatch", headers=headers, json=payload_orig)
        assert res1.status_code == 200

        # 2. Resubmission of same key with altered payload
        payload_altered = {
            "action_type": "APPROVE_PO",
            "idempotency_key": test_key,
            "payload": {"amount": 999999, "vendor": "Cloudflare Inc"},
        }
        res_mismatch = client.post("/api/actions/dispatch", headers=headers, json=payload_altered)
        assert res_mismatch.status_code == 422
        assert "Idempotency Payload Mismatch" in res_mismatch.json()["detail"]

    def test_user_scoped_idempotency_isolation(self):
        """Idempotency keys are scoped per-user. User B using same key as User A does not collide."""
        key = f"shared_idem_key_{uuid_suffix()}"
        headers_a = auth_header("exec_marcus", Role.EXECUTIVE)
        headers_b = auth_header("exec_sarah", Role.EXECUTIVE)

        payload = {
            "action_type": "APPROVE_PO",
            "idempotency_key": key,
            "payload": {"amount": 10000},
        }

        # User A executes
        res_a = client.post("/api/actions/dispatch", headers=headers_a, json=payload)
        assert res_a.status_code == 200
        assert res_a.json()["status"] == "EXECUTED"

        # User B executes with same key -> Executes independently without collision
        res_b = client.post("/api/actions/dispatch", headers=headers_b, json=payload)
        assert res_b.status_code == 200
        assert res_b.json()["status"] == "EXECUTED"
        assert res_a.json()["action_id"] != res_b.json()["action_id"]

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
    """Test Suite 6: Cryptographic Hash Chaining & SQLite Append-Only Triggers."""

    def test_ledger_integrity_verification(self):
        """Verifies cryptographic hash chain across all audit blocks with executive clearance."""
        headers = auth_header("exec_marcus", Role.EXECUTIVE)
        res = client.get("/api/audit/verify", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is True
        assert "VERIFIED" in data["message"]

    def test_sqlite_triggers_strictly_block_update_and_delete(self, tmp_path):
        """SQLite database triggers MUST raise an exception on direct UPDATE or DELETE attempts."""
        test_db = tmp_path / "trigger_test.db"
        ledger = AuditLedger(db_path=test_db)
        entry = ledger.log_event("user1", "INTERN", "QUERY", "query 1", "SUCCESS")

        # 1. Direct UPDATE is blocked by trigger
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_update:
            with sqlite3.connect(test_db) as conn:
                conn.execute(
                    "UPDATE audit_ledger SET detail = 'TAMPERED' WHERE audit_id = ?;",
                    (entry.audit_id,),
                )
                conn.commit()
        assert "strictly append-only: UPDATE prohibited" in str(exc_update.value)

        # 2. Direct DELETE is blocked by trigger
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_delete:
            with sqlite3.connect(test_db) as conn:
                conn.execute(
                    "DELETE FROM audit_ledger WHERE audit_id = ?;",
                    (entry.audit_id,),
                )
                conn.commit()
        assert "strictly append-only: DELETE prohibited" in str(exc_delete.value)

    def test_tamper_detection_across_all_fields(self, tmp_path):
        """Altering any field (detail, ip_address, payload) MUST break cryptographic hash verification."""
        test_db = tmp_path / "tamper_test.db"
        ledger = AuditLedger(db_path=test_db)

        ledger.log_event("user1", "INTERN", "QUERY", "query 1", "SUCCESS", ip_address="192.168.1.1", detail="clean 1")
        entry2 = ledger.log_event("user2", "EXECUTIVE", "QUERY", "query 2", "SUCCESS", ip_address="10.0.0.1", detail="clean 2")
        ledger.log_event("user3", "ANALYST", "ACTION", "action 3", "EXECUTED", ip_address="172.16.0.1", detail="clean 3")

        # Initial check passes
        v1 = ledger.verify_ledger_integrity()
        assert v1["is_valid"] is True

        # Simulate tampering by dropping trigger temporarily (external SQLite tool tampering)
        with sqlite3.connect(test_db) as conn:
            conn.execute("DROP TRIGGER prevent_audit_update;")
            conn.execute(
                "UPDATE audit_ledger SET detail = 'MALICIOUS_ALTERED_DETAIL' WHERE audit_id = ?;",
                (entry2.audit_id,),
            )
            conn.commit()

        # Re-verify detects tampering on detail field
        v2 = ledger.verify_ledger_integrity()
        assert v2["is_valid"] is False
        assert v2["broken_at_id"] == entry2.audit_id
        assert "TAMPERING DETECTED" in v2["message"]


class TestStructuredDuckDBRBAC:
    """Test Suite 7: Relational DuckDB Table-Level Security."""

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
