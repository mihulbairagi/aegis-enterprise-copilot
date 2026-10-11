"""FastAPI REST API Routes for Aegis-Copilot.

Provides endpoints for:
- Enterprise JWT Issuance (/api/auth/token)
- RLS Pre-Filtered Query Processing with Bearer Authentication (/api/query)
- Multipart CSV File Upload & Circuit Breaker Inspection (/api/pipeline/upload)
- Pipeline Ingestion via Circuit Breaker & Quarantine (/api/pipeline/ingest)
- Circuit Breaker Telemetry & Admin Reset (/api/circuit-breaker/*)
- Idempotent Action Dispatcher with Verified RBAC (/api/actions/dispatch)
- Tamper-Evident Audit Ledger Inspection & Verification (/api/audit/*)
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import duckdb
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status

from app.config import AuthConfig, DUCKDB_PATH, QUARANTINE_DIR, Role
from app.core.actions import GroundedReasoningEngine, IdempotentActionDispatcher
from app.core.audit import AuditLedger
from app.core.auth import authenticate_user, create_access_token, get_current_user, require_executive
from app.core.circuit_breaker import DataQualityCircuitBreaker
from app.core.rbac_engine import RBACHybridEngine
from app.models.schemas import (
    ActionRequest,
    ActionResponse,
    AuditLogRecord,
    AuthenticatedUser,
    CircuitBreakerStatus,
    CopilotQueryRequest,
    CopilotQueryResponse,
    IngestionPayload,
    TokenRequest,
    TokenResponse,
    ValidationResult,
)

logger = logging.getLogger("aegis.routes")
router = APIRouter(prefix="/api", tags=["Aegis Core Operations"])

# Singletons initialized for runtime
audit_ledger = AuditLedger()
circuit_breaker = DataQualityCircuitBreaker()
rbac_engine = RBACHybridEngine()
reasoning_engine = GroundedReasoningEngine(rbac_engine, audit_ledger)
action_dispatcher = IdempotentActionDispatcher(audit_ledger)


# ============================================================================
# 1. ENTERPRISE JWT AUTHENTICATION
# ============================================================================

@router.post("/auth/token", response_model=TokenResponse, summary="Issue Enterprise JWT Token")
def issue_token(req: TokenRequest) -> TokenResponse:
    """Authenticates enterprise credentials and issues a signed JWT with verified RBAC role."""
    authenticated = authenticate_user(req.username, req.password)
    if not authenticated:
        audit_ledger.log_event(
            user_id=req.username,
            role="UNKNOWN",
            event_type="AUTH_FAILURE",
            action_or_query=f"LOGIN_ATTEMPT user={req.username}",
            status="DENIED_CREDENTIALS",
            detail="Authentication failed: Invalid enterprise credentials.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enterprise username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user_id=authenticated.user_id, role=authenticated.role)
    expires_in_sec = AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    audit_ledger.log_event(
        user_id=authenticated.user_id,
        role=authenticated.role.value,
        event_type="AUTH_TOKEN_ISSUED",
        action_or_query=f"JWT_GRANT role={authenticated.role.value}",
        status="SUCCESS",
        detail=f"Issued JWT with {AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES}m expiration.",
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in_sec,
        user_id=authenticated.user_id,
        role=authenticated.role,
    )


# ============================================================================
# 2. GROUNDED REASONING & RLS QUERY (BEARER TOKEN PROTECTED)
# ============================================================================

@router.post("/query", response_model=CopilotQueryResponse, summary="Grounded Query with RLS Pre-Filtering")
def execute_query(
    req: CopilotQueryRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> CopilotQueryResponse:
    """Executes natural language copilot query with strict Row-Level Security pre-filtering.

    Security Guarantee: User identity and RBAC role are extracted from the verified JWT,
    preventing client-side role spoofing.
    """
    # Enforce verified JWT credentials over body fields to prevent role spoofing
    req.user_id = current_user.user_id
    req.role = current_user.role

    return reasoning_engine.process_query(req)


# ============================================================================
# 3. LIVE CSV FILE UPLOAD & CIRCUIT BREAKER INSPECTION
# ============================================================================

@router.post("/pipeline/upload", response_model=ValidationResult, summary="Upload CSV directly to Circuit Breaker")
async def upload_pipeline_csv(
    file: UploadFile = File(..., description="Raw CSV file to inspect and ingest"),
    source_id: str = Form(default="MANUAL_CSV_UPLOAD", description="Origin data system identifier"),
) -> ValidationResult:
    """Accepts a multipart CSV file upload and subjects it to statistical circuit breaker inspection.

    If anomalies breach thresholds (>15% nulls, negative financial numbers, malformed headers):
    - Trips breaker state to OPEN
    - Quarantines bad payload to data/quarantined/ with SHA-256 sidecar
    - Logs alert to audit ledger

    If clean:
    - Promotes payload to data/gold/
    - Ingests batch directly into DuckDB warehouse
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{file.filename}'. Only .csv files are supported for pipeline upload.",
        )

    try:
        content_bytes = await file.read()
        raw_text = content_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read and decode uploaded CSV: {str(exc)}",
        )

    payload = IngestionPayload(
        source_id=source_id,
        payload_format="csv",
        raw_content=raw_text,
        metadata={"filename": file.filename, "upload_size_bytes": len(content_bytes)},
    )

    result = circuit_breaker.inspect_and_ingest(payload)

    if result.is_valid:
        # Ingest clean verified batch into DuckDB analytical warehouse
        try:
            con = duckdb.connect(str(DUCKDB_PATH))
            stem = Path(file.filename).stem
            clean_table = "".join(c if c.isalnum() else "_" for c in stem).strip("_") or "uploaded_data"
            con.execute(f"CREATE TABLE IF NOT EXISTS {clean_table} AS SELECT * FROM read_csv_auto('{result.saved_path}');")
            con.close()
            logger.info(f"Clean CSV batch '{file.filename}' registered in DuckDB table '{clean_table}'.")
        except Exception as db_exc:
            logger.warning(f"DuckDB automatic table registration warning: {db_exc}")

        audit_ledger.log_event(
            user_id=source_id,
            role="PIPELINE_AGENT",
            event_type="INGESTION_UPLOAD",
            action_or_query=f"UPLOAD {file.filename}",
            status="PASSED",
            cited_doc_hashes=[result.payload_hash],
            detail=f"Rows: {result.row_count}, Null rate: {result.null_rate:.1%}. Ingested into warehouse.",
        )
    else:
        audit_ledger.log_event(
            user_id=source_id,
            role="PIPELINE_AGENT",
            event_type="INGESTION_UPLOAD",
            action_or_query=f"UPLOAD {file.filename}",
            status=result.status,
            cited_doc_hashes=[result.payload_hash],
            detail=f"Quarantined in DLQ ({result.quarantine_id}). Violations: {'; '.join(result.violations[:2])}",
        )

    return result


@router.post("/pipeline/ingest", response_model=ValidationResult, summary="Pipeline Ingestion via Circuit Breaker (JSON Envelope)")
def ingest_pipeline_batch(payload: IngestionPayload) -> ValidationResult:
    """Submits tabular/JSON string batch to Data Quality Circuit Breaker."""
    result = circuit_breaker.inspect_and_ingest(payload)

    audit_ledger.log_event(
        user_id=payload.source_id,
        role="PIPELINE_AGENT",
        event_type="INGESTION",
        action_or_query=f"Ingestion {payload.source_id} ({payload.payload_format})",
        status=result.status,
        cited_doc_hashes=[result.payload_hash],
        detail=f"Rows: {result.row_count}, Null rate: {result.null_rate:.1%}, Status: {result.status}",
    )
    return result


# ============================================================================
# 4. CIRCUIT BREAKER TELEMETRY & ADMIN RESET
# ============================================================================

@router.get("/circuit-breaker/status", response_model=CircuitBreakerStatus, summary="Get Circuit Breaker Telemetry")
def get_circuit_breaker_status() -> CircuitBreakerStatus:
    """Returns real-time status of the data quality circuit breaker."""
    return circuit_breaker.get_status()


@router.post("/circuit-breaker/reset", response_model=CircuitBreakerStatus, summary="Admin Reset Circuit Breaker")
def reset_circuit_breaker(
    current_user: AuthenticatedUser = Depends(require_executive),
) -> CircuitBreakerStatus:
    """Admin override resetting circuit breaker back to CLOSED state (Requires EXECUTIVE clearance)."""
    status_obj = circuit_breaker.reset()
    audit_ledger.log_event(
        user_id=current_user.user_id,
        role=current_user.role.value,
        event_type="CIRCUIT_BREAKER_RESET",
        action_or_query="ADMIN_RESET",
        status="SUCCESS",
        detail="Circuit breaker reset to CLOSED state via console.",
    )
    return status_obj


# ============================================================================
# 5. IDEMPOTENT ERP ACTION DISPATCHER (BEARER TOKEN PROTECTED)
# ============================================================================

@router.post("/actions/dispatch", response_model=ActionResponse, summary="Idempotent ERP Action Dispatch")
def dispatch_action(
    req: ActionRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> ActionResponse:
    """Dispatches operational ERP action requiring an Idempotency-Key and verified JWT role."""
    req.requester_id = current_user.user_id
    req.requester_role = current_user.role

    return action_dispatcher.dispatch(req)


# ============================================================================
# 6. IMMUTABLE AUDIT LEDGER & QUARANTINE INSPECTION (EXECUTIVE PROTECTED)
# ============================================================================

@router.get("/audit/logs", response_model=List[AuditLogRecord], summary="Get Immutable Audit Logs")
def get_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: AuthenticatedUser = Depends(require_executive),
) -> List[AuditLogRecord]:
    """Retrieves recent records from the append-only SQLite ledger (Requires EXECUTIVE clearance)."""
    return audit_ledger.get_recent_entries(limit=limit)


@router.get("/audit/verify", summary="Verify Tamper-Evident Hash Chain Integrity")
def verify_audit_ledger(
    current_user: AuthenticatedUser = Depends(require_executive),
) -> Dict[str, Any]:
    """Cryptographically audits the entire SQLite chain from Genesis to head (Requires EXECUTIVE clearance)."""
    return audit_ledger.verify_ledger_integrity()


@router.get("/storage/quarantine", summary="List Quarantined Dead-Letter Queue Files")
def list_quarantine_files(
    current_user: AuthenticatedUser = Depends(require_executive),
) -> List[Dict[str, Any]]:
    """Returns metadata for all files isolated by the circuit breaker (Requires EXECUTIVE clearance)."""
    files: List[Dict[str, Any]] = []
    if not QUARANTINE_DIR.exists():
        return files

    for meta_file in sorted(QUARANTINE_DIR.glob("*.meta.json"), reverse=True):
        try:
            import json
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                files.append(data)
        except Exception:
            continue
    return files
