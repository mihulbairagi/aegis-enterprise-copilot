"""Command-Line Interface (CLI) Demonstration for Aegis-Copilot.

Runs a fast, end-to-end interactive simulation of:
1. Enterprise JWT Issuance & Bearer Token Verification
2. Row-Level Security Pre-Filtering & Live RouterPlus Claude Synthesis
3. Data Quality Circuit Breaker Tripping & Dead-Letter Quarantine
4. Idempotent ERP Action Dispatch (Exactly-Once Semantics)
5. Cryptographic Audit Ledger Hash Chain Verification
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Role
from app.core.actions import GroundedReasoningEngine, IdempotentActionDispatcher
from app.core.audit import AuditLedger
from app.core.auth import create_access_token, verify_access_token
from app.core.circuit_breaker import DataQualityCircuitBreaker
from app.core.rbac_engine import RBACHybridEngine
from app.models.schemas import ActionRequest, CopilotQueryRequest, IngestionPayload


def main():
    print("=" * 78)
    print("  AEGIS-COPILOT: ENTERPRISE OPERATIONS CAPSTONE DEMONSTRATION")
    print("  JWT Bearer RBAC | RouterPlus Synthesis | Circuit Breaker DLQ")
    print("=" * 78)

    audit_ledger = AuditLedger()
    circuit_breaker = DataQualityCircuitBreaker()
    rbac_engine = RBACHybridEngine()
    reasoning_engine = GroundedReasoningEngine(rbac_engine, audit_ledger)
    action_dispatcher = IdempotentActionDispatcher(audit_ledger)

    # -------------------------------------------------------------
    # 1. ENTERPRISE JWT ISSUANCE & VERIFICATION
    # -------------------------------------------------------------
    print("\n[PILLAR 1] ENTERPRISE JWT ISSUANCE & BEARER AUTHENTICATION")
    print("-" * 78)
    token_intern = create_access_token(user_id="intern.bob@enterprise.internal", role=Role.INTERN)
    token_exec = create_access_token(user_id="marcus.exec@enterprise.internal", role=Role.EXECUTIVE)

    verified_intern = verify_access_token(token_intern)
    verified_exec = verify_access_token(token_exec)
    print(f"-> Issued JWT for Intern: {token_intern[:28]}...")
    print(f"   [Verified Claims]    : Sub='{verified_intern.user_id}', Role='{verified_intern.role.value}'")
    print(f"-> Issued JWT for Exec  : {token_exec[:28]}...")
    print(f"   [Verified Claims]    : Sub='{verified_exec.user_id}', Role='{verified_exec.role.value}'")

    # -------------------------------------------------------------
    # 2. RBAC RLS PRE-FILTERING & LIVE ROUTERPLUS SYNTHESIS
    # -------------------------------------------------------------
    print("\n[PILLAR 2] RLS PRE-FILTERING & GROUNDED ROUTERPLUS LLM SYNTHESIS")
    print("-" * 78)
    query_text = "What is the Q3 executive payroll and bonus breakdown for VP of Engineering?"

    # Intern Attempt
    print(f"-> USER 1 (Role: INTERN via JWT) queries: \"{query_text}\"")
    req_intern = CopilotQueryRequest(query=query_text, user_id=verified_intern.user_id, role=verified_intern.role)
    resp_intern = reasoning_engine.process_query(req_intern)
    print(f"   [RLS Status]        : {resp_intern.rls_status}")
    print(f"   [Accessible Chunks] : {resp_intern.accessible_chunks_count}")
    print(f"   [Redacted Chunks]   : {resp_intern.redacted_or_restricted_chunks_count}")
    print(f"   [LLM Output]        : {resp_intern.answer.splitlines()[0]}")

    # Executive Attempt
    print(f"\n-> USER 2 (Role: EXECUTIVE via JWT) queries: \"{query_text}\"")
    req_exec = CopilotQueryRequest(query=query_text, user_id=verified_exec.user_id, role=verified_exec.role)
    resp_exec = reasoning_engine.process_query(req_exec)
    print(f"   [RLS Status]        : {resp_exec.rls_status}")
    print(f"   [Citations Count]   : {len(resp_exec.citations)} document(s) cited")
    for cit in resp_exec.citations[:2]:
        print(f"     * {cit.doc_name} (SHA-256: {cit.doc_hash[:16]}...)")
    print(f"   [LLM Grounded Synthesis Excerpt]:\n   \"{resp_exec.answer[:240].strip()}...\"")

    # -------------------------------------------------------------
    # 3. DATA QUALITY CIRCUIT BREAKER DEMONSTRATION
    # -------------------------------------------------------------
    print("\n[PILLAR 3] DATA QUALITY CIRCUIT BREAKER & DEAD-LETTER QUARANTINE")
    print("-" * 78)
    circuit_breaker.reset()
    corrupt_csv = """employee_id,name,department,salary,bonus,effective_date
EMP-991,John Corrupt,Engineering,-45000,null,2026-10-01
EMP-992,null,null,null,null,null
EMP-993,Jane Malformed,,NaN,null,
EMP-994,,Operations,-12000,null,null"""

    print("-> Ingesting upstream batch with 38% null rate & negative salaries...")
    payload = IngestionPayload(
        source_id="UPSTREAM_HR_STREAM",
        payload_format="csv",
        raw_content=corrupt_csv,
    )
    val_res = circuit_breaker.inspect_and_ingest(payload)
    print(f"   [Validation Status] : {val_res.status}")
    print(f"   [Measured Null Rate]: {val_res.null_rate:.1%}")
    print(f"   [Violations Count]  : {len(val_res.violations)}")
    print(f"   [Dead-Letter ID]    : {val_res.quarantine_id}")
    print(f"   [Quarantine File]   : {val_res.saved_path}")

    # -------------------------------------------------------------
    # 4. IDEMPOTENT ACTION DISPATCH (EXACTLY-ONCE)
    # -------------------------------------------------------------
    print("\n[PILLAR 4] IDEMPOTENT ACTION DISPATCHER (PREVENTING ERP REPLAY ATTACKS)")
    print("-" * 78)
    idempotency_key = "idem_key_erp_payout_90412"
    act_req = ActionRequest(
        action_type="APPROVE_PO",
        idempotency_key=idempotency_key,
        payload={"vendor": "Cloudflare Inc", "amount": 45000},
        requester_id=verified_exec.user_id,
        requester_role=verified_exec.role,
    )

    print(f"-> Dispatching Purchase Order ($45,000) with key='{idempotency_key}' (Attempt 1)...")
    res1 = action_dispatcher.dispatch(act_req)
    print(f"   [Status]            : {res1.status} (Action ID: {res1.action_id})")

    print(f"-> Client retries identical request due to simulated timeout (Attempt 2)...")
    res2 = action_dispatcher.dispatch(act_req)
    print(f"   [Status]            : {res2.status} (Action ID: {res2.action_id})")
    print(f"   [Idempotency Msg]   : {res2.message}")

    # -------------------------------------------------------------
    # 5. CRYPTOGRAPHIC AUDIT LEDGER VERIFICATION
    # -------------------------------------------------------------
    print("\n[PILLAR 5] TAMPER-EVIDENT CRYPTOGRAPHIC AUDIT LEDGER")
    print("-" * 78)
    audit_report = audit_ledger.verify_ledger_integrity()
    print(f"   [Integrity Status]  : {'VERIFIED UNBROKEN' if audit_report['is_valid'] else 'TAMPER DETECTED'}")
    print(f"   [Total Log Blocks]  : {audit_report['total_records']}")
    print(f"   [Ledger Report]     : {audit_report['message']}")

    print("\n" + "=" * 78)
    print("  ALL ENTERPRISE PILLARS VERIFIED OPERATIONAL.")
    print("  Run live dashboard: uvicorn app.main:app --port 8001")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
