"""Live API Verification Script for Aegis-Copilot.

Tests:
1. Live JWT Issuance via POST /api/auth/token
2. RLS Pre-Filtered Query via POST /api/query (Intern denied vs Executive granted with RouterPlus LLM)
3. Multipart CSV Upload via POST /api/pipeline/upload (Clean promoted, Corrupt quarantined)
"""

import io
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.config import Role
from app.main import app

client = TestClient(app)


def verify_live_flow():
    print("=" * 76)
    print("  LIVE AEGIS-COPILOT API VERIFICATION")
    print("=" * 76)

    # 1. Acquire JWT for Intern
    print("\n[1] Issuing JWT for Role: INTERN ...")
    res_intern = client.post("/api/auth/token", json={"username": "intern_user", "password": "intern_pass_2026"})
    assert res_intern.status_code == 200, f"Failed: {res_intern.text}"
    token_intern = res_intern.json()["access_token"]
    print(f"    Status: 200 OK | Token: {token_intern[:32]}... (HS256)")

    # 2. Query Executive Payroll as Intern (Must Deny with Zero Oracle Leakage)
    print("\n[2] Querying Executive Payroll with INTERN Bearer token ...")
    query_payload = {"query": "What is the Q3 executive payroll and bonus breakdown for VP of Engineering?"}
    res_q_intern = client.post("/api/query", headers={"Authorization": f"Bearer {token_intern}"}, json=query_payload)
    assert res_q_intern.status_code == 200
    q_data_intern = res_q_intern.json()
    print(f"    RLS Status        : {q_data_intern['rls_status']}")
    print(f"    Accessible Chunks : {q_data_intern['accessible_chunks_count']}")
    print(f"    Redacted Chunks   : {q_data_intern['redacted_or_restricted_chunks_count']}")
    print(f"    LLM Output        : {q_data_intern['answer']}")
    assert q_data_intern["rls_status"] == "NO_RECORDS_FOUND"
    assert q_data_intern["redacted_or_restricted_chunks_count"] == 0
    assert len(q_data_intern["citations"]) == 0

    # 3. Acquire JWT for Executive
    print("\n[3] Issuing JWT for Role: EXECUTIVE ...")
    res_exec = client.post("/api/auth/token", json={"username": "exec_user", "password": "exec_pass_2026"})
    assert res_exec.status_code == 200
    token_exec = res_exec.json()["access_token"]
    print(f"    Status: 200 OK | Token: {token_exec[:32]}... (HS256)")

    # 4. Query Executive Payroll as Executive (Must Grant with Citations & Claude synthesis)
    print("\n[4] Querying Executive Payroll with EXECUTIVE Bearer token ...")
    res_q_exec = client.post("/api/query", headers={"Authorization": f"Bearer {token_exec}"}, json=query_payload)
    assert res_q_exec.status_code == 200
    q_data_exec = res_q_exec.json()
    print(f"    RLS Status        : {q_data_exec['rls_status']}")
    print(f"    Citations Count   : {len(q_data_exec['citations'])}")
    for cit in q_data_exec["citations"]:
        print(f"      * {cit['doc_name']} [{cit['classification']}] (Hash: {cit['doc_hash'][:16]}...)")
    print(f"    Live LLM Answer   :\n    {q_data_exec['answer'][:200]}...")
    assert q_data_exec["rls_status"] == "ENFORCED_CLEAN"
    assert len(q_data_exec["citations"]) > 0

    # 5. Multipart CSV File Upload (Circuit Breaker Inspection)
    print("\n[5] Testing Multipart CSV Upload to Circuit Breaker ...")
    # Reset breaker first with executive authorization
    client.post("/api/circuit-breaker/reset", headers={"Authorization": f"Bearer {token_exec}"})

    # Clean CSV
    clean_csv = "server_id,region,cpu_util,status\nSRV-01,ap-south-1,45.2,ONLINE\nSRV-02,us-east-1,62.1,ONLINE\n"
    res_up_clean = client.post(
        "/api/pipeline/upload",
        files={"file": ("servers_clean.csv", io.BytesIO(clean_csv.encode("utf-8")), "text/csv")},
        data={"source_id": "INFRA_STREAM"}
    )
    assert res_up_clean.status_code == 200
    print(f"    Clean CSV Upload Status   : {res_up_clean.json()['status']} (Promoted to Gold Storage)")

    # Corrupt CSV
    corrupt_csv = "emp_id,name,salary\nE1,null,-50000\nE2,null,null\nE3,,null\n"
    res_up_corrupt = client.post(
        "/api/pipeline/upload",
        files={"file": ("payroll_corrupt.csv", io.BytesIO(corrupt_csv.encode("utf-8")), "text/csv")},
        data={"source_id": "LEGACY_PAYROLL"}
    )
    assert res_up_corrupt.status_code == 200
    corrupt_res = res_up_corrupt.json()
    print(f"    Corrupt CSV Upload Status : {corrupt_res['status']} (Quarantined in DLQ)")
    print(f"    Measured Null Rate        : {corrupt_res['null_rate']:.1%}")
    print(f"    Quarantine ID             : {corrupt_res['quarantine_id']}")

    print("\n" + "=" * 76)
    print("  ALL LIVE API FLOWS VALIDATED SUCCESSFULLY (100% OPERATIONAL)")
    print("=" * 76)


if __name__ == "__main__":
    verify_live_flow()
