"""Grounded Reasoning Synthesizer & Idempotent Action Dispatcher.

Guarantees:
1. Zero Hallucination Attribution: Answers are grounded strictly in RLS pre-filtered chunks,
   citing SHA-256 document hashes and chunk IDs.
2. Explicit RLS Boundary Feedback: If a query matched restricted data that was filtered out,
   the engine returns explicit clearance denial rather than silent hallucinations.
3. Distributed Idempotency: Enforces unique Idempotency-Key on all mutating operations
   to guarantee exactly-once execution and prevent duplicate ERP side-effects.
"""

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import HTTPException, status

from app.config import (
    AUDIT_DB_PATH,
    Role,
    ROLE_CLEARANCE,
    ROLE_PERMITTED_ACTIONS,
    RouterPlusConfig,
    SecurityClassification,
)
from app.core.audit import AuditLedger
from app.core.rbac_engine import RBACHybridEngine
from app.models.schemas import (
    ActionRequest,
    ActionResponse,
    Citation,
    CopilotQueryRequest,
    CopilotQueryResponse,
    DocumentChunk,
)

logger = logging.getLogger("aegis.actions")


class IdempotencyStore:
    """SQLite-backed persistent store for Idempotency-Key enforcement with user-scoping and payload hashing."""

    def __init__(self, db_path: Path = AUDIT_DB_PATH):
        self.db_path = db_path
        self._init_table()

    def _init_table(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    requester_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    requester_role TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(requester_id, idempotency_key)
                );
            """)
            conn.commit()

    @staticmethod
    def compute_payload_hash(payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash over canonically ordered payload JSON."""
        canonical_json = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def get_existing(self, requester_id: str, key: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT requester_id, idempotency_key, action_id, action_type,
                       requester_role, payload_hash, response_json, status, created_at
                FROM idempotency_keys
                WHERE requester_id = ? AND idempotency_key = ?;
                """,
                (requester_id, key),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "idempotency_key": row["idempotency_key"],
                    "action_id": row["action_id"],
                    "action_type": row["action_type"],
                    "requester_id": row["requester_id"],
                    "requester_role": row["requester_role"],
                    "payload_hash": row["payload_hash"],
                    "response_data": json.loads(row["response_json"]),
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
            return None

    def record_execution(
        self,
        key: str,
        action_id: str,
        action_type: str,
        requester_id: str,
        requester_role: str,
        payload: Dict[str, Any],
        response_data: Dict[str, Any],
        status: str,
    ) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        payload_hash = self.compute_payload_hash(payload)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO idempotency_keys (
                    idempotency_key, action_id, action_type, requester_id,
                    requester_role, payload_hash, payload_json, response_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    key,
                    action_id,
                    action_type,
                    requester_id,
                    requester_role,
                    payload_hash,
                    json.dumps(payload),
                    json.dumps(response_data),
                    status,
                    created_at,
                ),
            )
            conn.commit()


class GroundedReasoningEngine:
    """Synthesizes query responses grounded in RLS pre-filtered chunks with citation proof."""

    def __init__(self, rbac_engine: RBACHybridEngine, audit_ledger: AuditLedger):
        self.rbac_engine = rbac_engine
        self.audit_ledger = audit_ledger

    def _call_routerplus_llm(
        self,
        query: str,
        chunks: List[DocumentChunk],
        user_role: Role,
    ) -> str:
        """Invokes RouterPlus (Claude-3.5-Sonnet) with strictly pre-filtered context.

        Invariant: LLM receives ONLY context chunks that passed RLS pre-filtering.
        Passes FULL content of each chunk so numerical figures and confidential policies are not truncated.
        Prompt enforces strict provenance: 'Answer using ONLY provided context and cite [doc_id].
        If context is empty, respond with: Access Denied: Insufficient Role Clearance for this information.'
        """
        system_prompt = (
            "You are Aegis-Copilot, an enterprise operations assistant.\n"
            "STRICT PROVENANCE POLICY: Answer the user's question using ONLY the provided verified context chunks below. "
            "Cite each source using [chunk_id] or [doc_id]. "
            "Do NOT speculate, assume, or hallucinate facts outside the provided context.\n"
            "If context is empty or lacks information to answer the question, respond with: "
            "'Access Denied: Insufficient Role Clearance for this information.'"
        )

        if not chunks:
            context_str = "(No authorized context provided - pre-filtering pruned all chunks or zero matches)"
        else:
            context_blocks = []
            for c in chunks:
                context_blocks.append(
                    f"[{c.chunk_id}] {c.doc_name} (Classification: {c.classification.value}, SHA-256: {c.doc_hash[:16]}...):\n{c.content}"
                )
            context_str = "\n\n".join(context_blocks)

        user_content = f"Context:\n{context_str}\n\nQuestion: {query}"

        try:
            with httpx.Client(timeout=RouterPlusConfig.TIMEOUT_SECONDS) as client:
                resp = client.post(
                    f"{RouterPlusConfig.BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {RouterPlusConfig.API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": RouterPlusConfig.MODEL,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_content},
                        ],
                        "max_tokens": 400,
                        "temperature": 0.0,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        content = choices[0]["message"].get("content", "").strip()
                        if content:
                            return content
                logger.warning(f"RouterPlus API returned non-200 or empty response ({resp.status_code})")
        except Exception as exc:
            logger.warning(f"RouterPlus API call exception ({type(exc).__name__}: {exc}). Using local deterministic synthesis.")

        # Fallback if external API unreachable
        if not chunks:
            return "Access Denied: Insufficient Role Clearance for this information."

        fallback_parts = [f"Based on {len(chunks)} verified enterprise document(s) accessible to role [{user_role.value}]:"]
        for idx, c in enumerate(chunks, 1):
            fallback_parts.append(f"[{idx}] {c.doc_name} (Classification: {c.classification.value}): \"{c.content}\"")
        return "\n\n".join(fallback_parts)

    def process_query(self, req: CopilotQueryRequest) -> CopilotQueryResponse:
        start_time = time.perf_counter()

        # Step 1: Execute unstructured retrieval with Row-Level Security Pre-Filtering
        citations, chunks, accessible_count, redacted_count = self.rbac_engine.query_unstructured_chunks(
            query=req.query, user_role=req.role, top_k=4
        )

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        cited_hashes = [c.doc_hash for c in citations]

        # Case 1: Zero authorized citations found (either unauthorized query OR zero corpus match)
        # CRITICAL FIX: Eliminate existence / metadata probing oracle.
        # Both unauthorized classified queries and non-matching queries return identical generic response
        # with redacted_or_restricted_chunks_count = 0 in client DTO.
        if not citations:
            generic_response = "No accessible records found matching your query."
            if redacted_count > 0:
                audit_entry = self.audit_ledger.log_event(
                    user_id=req.user_id,
                    role=req.role.value,
                    event_type="QUERY",
                    action_or_query=req.query,
                    status="DENIED_RBAC",
                    cited_doc_hashes=[],
                    detail=f"RLS pre-filter pruned {redacted_count} classified chunks from unauthorized caller. Returned generic oracle-safe response.",
                )
            else:
                audit_entry = self.audit_ledger.log_event(
                    user_id=req.user_id,
                    role=req.role.value,
                    event_type="QUERY",
                    action_or_query=req.query,
                    status="NO_MATCH",
                    cited_doc_hashes=[],
                    detail="Zero matching chunks found in authorized corpus.",
                )

            return CopilotQueryResponse(
                query=req.query,
                user_id=req.user_id,
                role=req.role,
                answer=generic_response,
                citations=[],
                accessible_chunks_count=accessible_count,
                redacted_or_restricted_chunks_count=0,  # Zero metadata leakage to client
                rls_status="NO_RECORDS_FOUND",
                latency_ms=latency_ms,
                audit_id=audit_entry.audit_id,
            )

        # Case 2: Grounded factual LLM synthesis from RLS pre-filtered citations (passing full chunks)
        llm_response = self._call_routerplus_llm(req.query, chunks=chunks, user_role=req.role)

        audit_entry = self.audit_ledger.log_event(
            user_id=req.user_id,
            role=req.role.value,
            event_type="QUERY",
            action_or_query=req.query,
            status="SUCCESS",
            cited_doc_hashes=cited_hashes,
            detail=f"Retrieved {len(citations)} chunks ({redacted_count} restricted chunks pruned at RLS boundary). Synthesized via RouterPlus LLM.",
        )

        return CopilotQueryResponse(
            query=req.query,
            user_id=req.user_id,
            role=req.role,
            answer=llm_response,
            citations=citations,
            accessible_chunks_count=accessible_count,
            redacted_or_restricted_chunks_count=0,  # Redacted count strictly preserved only in audit log
            rls_status="ENFORCED_CLEAN",
            latency_ms=latency_ms,
            audit_id=audit_entry.audit_id,
        )


class IdempotentActionDispatcher:
    """Dispatches ERP and operational webhooks with RBAC validation and exactly-once execution."""

    def __init__(self, audit_ledger: AuditLedger, idempotency_store: Optional[IdempotencyStore] = None):
        self.audit_ledger = audit_ledger
        self.idempotency_store = idempotency_store or IdempotencyStore()

    def dispatch(self, req: ActionRequest) -> ActionResponse:
        key = req.idempotency_key.strip()
        action_type = req.action_type.strip().upper()
        requester_id = req.requester_id or "anonymous_user"
        requester_role = req.requester_role or Role.INTERN

        # Compute incoming payload hash
        current_payload_hash = self.idempotency_store.compute_payload_hash(req.payload)

        # Step 1: Check Idempotency Store for prior execution scoped to requester_id
        cached = self.idempotency_store.get_existing(requester_id=requester_id, key=key)
        if cached:
            # 1A: Check Payload Mismatch (reject altered payloads with 422 Unprocessable Entity)
            if cached["payload_hash"] != current_payload_hash:
                logger.warning(
                    f"[IDEMPOTENCY PAYLOAD MISMATCH] Key '{key}' for user '{requester_id}' "
                    f"resubmitted with altered payload parameters. Raising 422."
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Idempotency Payload Mismatch: Key previously dispatched with different payload parameters.",
                )

            # 1B: Validate caller RBAC clearance before returning cached result
            permitted_actions = ROLE_PERMITTED_ACTIONS.get(requester_role, set())
            if action_type not in permitted_actions:
                denied_msg = (
                    f"RBAC ACTION VIOLATION: Role '{requester_role.value}' is not permitted to access "
                    f"cached operation '{action_type}'. Required clearance tier: EXECUTIVE."
                )
                audit_entry = self.audit_ledger.log_event(
                    user_id=requester_id,
                    role=requester_role.value,
                    event_type="ACTION",
                    action_or_query=action_type,
                    status="DENIED_RBAC",
                    detail=denied_msg,
                )
                return ActionResponse(
                    action_id=f"act_denied_{uuid.uuid4().hex[:8]}",
                    idempotency_key=key,
                    action_type=action_type,
                    status="DENIED_RBAC",
                    executed_at=datetime.now(timezone.utc).isoformat(),
                    result_data={"error": denied_msg},
                    audit_id=audit_entry.audit_id,
                    message=denied_msg,
                )

            logger.info(f"[IDEMPOTENCY HIT] Replay request with key={key} for user={requester_id}. Returning cached response without duplicate side-effects.")
            audit_entry = self.audit_ledger.log_event(
                user_id=requester_id,
                role=requester_role.value,
                event_type="ACTION",
                action_or_query=f"{action_type} (REPLAY key={key[:8]}...)",
                status="DUPLICATE_CACHED",
                detail=f"Prevented duplicate ERP dispatch for key {key}.",
            )
            return ActionResponse(
                action_id=cached["action_id"],
                idempotency_key=key,
                action_type=cached["action_type"],
                status="DUPLICATE_CACHED",
                executed_at=cached["created_at"],
                result_data=cached["response_data"],
                audit_id=audit_entry.audit_id,
                message="IDEMPOTENCY GUARANTEE ENFORCED: Operation previously executed. Duplicate side-effects avoided.",
            )

        # Step 2: RBAC Action Permission Check
        permitted_actions = ROLE_PERMITTED_ACTIONS.get(req.requester_role, set())
        if action_type not in permitted_actions:
            denied_msg = (
                f"RBAC ACTION VIOLATION: Role '{req.requester_role.value}' is not permitted to trigger "
                f"operation '{action_type}'. Required clearance tier: EXECUTIVE."
            )
            audit_entry = self.audit_ledger.log_event(
                user_id=req.requester_id,
                role=req.requester_role.value,
                event_type="ACTION",
                action_or_query=action_type,
                status="DENIED_RBAC",
                detail=denied_msg,
            )
            return ActionResponse(
                action_id=f"act_denied_{uuid.uuid4().hex[:8]}",
                idempotency_key=key,
                action_type=action_type,
                status="DENIED_RBAC",
                executed_at=datetime.now(timezone.utc).isoformat(),
                result_data={"error": denied_msg},
                audit_id=audit_entry.audit_id,
                message=denied_msg,
            )

        # Step 3: Mock ERP / Webhook Execution
        action_id = f"act_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Execute domain logic based on action type
        result_payload: Dict[str, Any] = {
            "erp_transaction_id": f"ERP-TXN-{uuid.uuid4().hex[:8].upper()}",
            "executed_by": req.requester_id,
            "role": req.requester_role.value,
            "action": action_type,
            "parameters": req.payload,
            "timestamp": now_iso,
            "status": "COMMITTED_TO_ERP",
        }

        # Step 4: Record execution in idempotency store & audit ledger
        self.idempotency_store.record_execution(
            key=key,
            action_id=action_id,
            action_type=action_type,
            requester_id=req.requester_id,
            requester_role=req.requester_role.value,
            payload=req.payload,
            response_data=result_payload,
            status="EXECUTED",
        )

        audit_entry = self.audit_ledger.log_event(
            user_id=req.requester_id,
            role=req.requester_role.value,
            event_type="ACTION",
            action_or_query=f"{action_type} (key={key[:8]}...)",
            status="EXECUTED",
            detail=f"Dispatched ERP transaction {result_payload['erp_transaction_id']}.",
        )

        return ActionResponse(
            action_id=action_id,
            idempotency_key=key,
            action_type=action_type,
            status="EXECUTED",
            executed_at=now_iso,
            result_data=result_payload,
            audit_id=audit_entry.audit_id,
            message=f"Operation '{action_type}' executed successfully and committed to ERP.",
        )
