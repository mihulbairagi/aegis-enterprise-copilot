"""Enterprise Pydantic Schemas for Aegis-Copilot.

Defines schemas for Document Chunks, Ingestion Payloads, Data Quality Validation,
Audit Logs, Circuit Breaker states, and Idempotent Action Dispatches.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.config import Role, SecurityClassification


class CircuitBreakerState(str, Enum):
    """3-State Circuit Breaker lifecycle states."""
    CLOSED = "CLOSED"        # Normal: Ingestion allowed, health metrics healthy
    OPEN = "OPEN"            # Tripped: Ingestion blocked, data directed to DLQ
    HALF_OPEN = "HALF_OPEN"  # Probe: Testing next batches for recovery


class CircuitBreakerStatus(BaseModel):
    """Real-time operational status of the Data Quality Circuit Breaker."""
    state: CircuitBreakerState
    failure_count: int
    success_count: int
    failure_threshold: int
    max_null_rate_threshold: float
    last_tripped_at: Optional[str] = None
    last_error_reason: Optional[str] = None
    total_quarantined_batches: int = 0
    total_accepted_batches: int = 0


class DocumentChunk(BaseModel):
    """Granular text chunk with cryptographic provenance and classification tag."""
    chunk_id: str
    doc_id: str
    doc_name: str
    doc_hash: str = Field(description="SHA-256 hash of the parent source document")
    content: str
    classification: SecurityClassification
    department: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Citation(BaseModel):
    """Cryptographically verifiable source attribution for grounded responses."""
    chunk_id: str
    doc_name: str
    doc_hash: str
    snippet: str
    classification: SecurityClassification


class TokenRequest(BaseModel):
    """Request payload for issuing a signed enterprise JWT."""
    user_id: str = Field(..., min_length=1, description="Enterprise user identifier / email")
    role: Role = Field(..., description="Assigned RBAC clearance tier")


class TokenResponse(BaseModel):
    """Signed JWT bearer token envelope."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    role: Role


class AuthenticatedUser(BaseModel):
    """Verified user identity extracted from cryptographically validated JWT."""
    user_id: str
    role: Role


class CopilotQueryRequest(BaseModel):
    """Inbound query from user subject to RBAC RLS filtering."""
    query: str = Field(..., min_length=1, description="Natural language enterprise operations query")
    user_id: Optional[str] = Field(default=None, description="Optional user ID, overridden by authenticated JWT")
    role: Optional[Role] = Field(default=None, description="Optional role, overridden by authenticated JWT")


class CopilotQueryResponse(BaseModel):
    """Synthesized response with grounded citations and RLS audit telemetry."""
    query: str
    user_id: str
    role: Role
    answer: str
    citations: List[Citation] = Field(default_factory=list)
    accessible_chunks_count: int
    redacted_or_restricted_chunks_count: int
    rls_status: str
    latency_ms: float
    audit_id: str


class IngestionPayload(BaseModel):
    """Raw ingestion envelope submitted to the data pipeline."""
    source_id: str
    payload_format: str = Field(default="csv", description="'csv' or 'json'")
    raw_content: str = Field(..., description="Raw tabular or JSON string data")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    """Report produced by the Data Quality Circuit Breaker inspection."""
    is_valid: bool
    status: str  # "PASSED", "QUARANTINED", "REJECTED_BREAKER_OPEN"
    null_rate: float
    row_count: int
    violations: List[str] = Field(default_factory=list)
    quarantine_id: Optional[str] = None
    saved_path: Optional[str] = None
    payload_hash: str
    message: str


class ActionRequest(BaseModel):
    """Enterprise ERP/Webhook action dispatch requiring an Idempotency-Key."""
    action_type: str = Field(..., description="Enterprise action name (e.g. APPROVE_PO, ADJUST_BUDGET)")
    idempotency_key: str = Field(..., min_length=8, description="Unique client-supplied idempotency key")
    payload: Dict[str, Any] = Field(default_factory=dict)
    requester_id: Optional[str] = Field(default=None, description="Optional requester ID, overridden by authenticated JWT")
    requester_role: Optional[Role] = Field(default=None, description="Optional requester role, overridden by authenticated JWT")


class ActionResponse(BaseModel):
    """Result of an action dispatch with duplicate idempotency confirmation."""
    action_id: str
    idempotency_key: str
    action_type: str
    status: str = Field(description="'EXECUTED', 'DUPLICATE_CACHED', or 'DENIED_RBAC'")
    executed_at: str
    result_data: Dict[str, Any] = Field(default_factory=dict)
    audit_id: str
    message: str


class AuditLogRecord(BaseModel):
    """Immutable, tamper-evident audit ledger record."""
    audit_id: str
    timestamp: str
    user_id: str
    role: str
    event_type: str
    action_or_query: str
    status: str
    cited_doc_hashes: List[str] = Field(default_factory=list)
    ip_address: str = "127.0.0.1"
    signature_hash: str
    detail: Optional[str] = None
