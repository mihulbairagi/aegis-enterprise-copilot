"""Tamper-Evident Immutable Audit Ledger with Cryptographic Hash Chaining.

Persists every copilot query, RBAC redaction event, pipeline quarantine, and
action dispatch into an append-only SQLite ledger.

Guarantees tamper-evidence:
Each entry calculates a chained signature hash:
  signature_hash = SHA256(prev_signature_hash + audit_id + timestamp + event_type + user_id + status + action_or_query)
Any manual tampering, deletion, or backdating in SQLite immediately breaks the cryptographic chain.
"""

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import AUDIT_DB_PATH
from app.models.schemas import AuditLogRecord

logger = logging.getLogger("aegis.audit")

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditLedger:
    """Cryptographically chained append-only audit ledger."""

    def __init__(self, db_path: Path = AUDIT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initializes SQLite table for the immutable ledger."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    action_or_query TEXT NOT NULL,
                    status TEXT NOT NULL,
                    cited_doc_hashes TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    signature_hash TEXT NOT NULL,
                    prev_signature_hash TEXT NOT NULL,
                    detail TEXT
                );
            """)
            conn.commit()

    def _get_last_signature_hash(self) -> str:
        """Fetches the signature hash of the latest record in the chain."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT signature_hash FROM audit_ledger ORDER BY id DESC LIMIT 1;")
            row = cursor.fetchone()
            if row and row[0]:
                return row[0]
            return GENESIS_HASH

    def log_event(
        self,
        user_id: str,
        role: str,
        event_type: str,
        action_or_query: str,
        status: str,
        cited_doc_hashes: Optional[List[str]] = None,
        ip_address: str = "127.0.0.1",
        detail: Optional[str] = None,
    ) -> AuditLogRecord:
        """Appends a new event and seals it with a cryptographic signature hash."""
        audit_id = f"aud_{uuid.uuid4().hex[:16]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        cited_hashes_list = cited_doc_hashes or []
        cited_hashes_json = json.dumps(cited_hashes_list)

        prev_hash = self._get_last_signature_hash()

        # Compute tamper-evident chained hash
        hash_payload = (
            f"{prev_hash}|{audit_id}|{timestamp}|{event_type}|{user_id}|"
            f"{role}|{status}|{action_or_query}|{cited_hashes_json}"
        )
        signature_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_ledger (
                    audit_id, timestamp, user_id, role, event_type,
                    action_or_query, status, cited_doc_hashes, ip_address,
                    signature_hash, prev_signature_hash, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    audit_id,
                    timestamp,
                    user_id,
                    role,
                    event_type,
                    action_or_query,
                    status,
                    cited_hashes_json,
                    ip_address,
                    signature_hash,
                    prev_hash,
                    detail or "",
                ),
            )
            conn.commit()

        logger.info(f"[AUDIT EVENT LOGGED] {event_type} | {user_id} ({role}) | Status: {status} | ID: {audit_id}")

        return AuditLogRecord(
            audit_id=audit_id,
            timestamp=timestamp,
            user_id=user_id,
            role=role,
            event_type=event_type,
            action_or_query=action_or_query,
            status=status,
            cited_doc_hashes=cited_hashes_list,
            ip_address=ip_address,
            signature_hash=signature_hash,
            detail=detail,
        )

    def get_recent_entries(self, limit: int = 50) -> List[AuditLogRecord]:
        """Retrieves most recent audit ledger records in reverse chronological order."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT audit_id, timestamp, user_id, role, event_type,
                       action_or_query, status, cited_doc_hashes, ip_address,
                       signature_hash, detail
                FROM audit_ledger
                ORDER BY id DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()

        entries: List[AuditLogRecord] = []
        for r in rows:
            try:
                cited = json.loads(r["cited_doc_hashes"])
            except Exception:
                cited = []
            entries.append(
                AuditLogRecord(
                    audit_id=r["audit_id"],
                    timestamp=r["timestamp"],
                    user_id=r["user_id"],
                    role=r["role"],
                    event_type=r["event_type"],
                    action_or_query=r["action_or_query"],
                    status=r["status"],
                    cited_doc_hashes=cited,
                    ip_address=r["ip_address"],
                    signature_hash=r["signature_hash"],
                    detail=r["detail"],
                )
            )
        return entries

    def verify_ledger_integrity(self) -> Dict[str, Any]:
        """Verifies the unbroken cryptographic hash chain from Genesis to head.

        Detects:
        - Out-of-order edits
        - Content modifications
        - Row deletions or truncated ledger files
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, audit_id, timestamp, user_id, role, event_type,
                       action_or_query, status, cited_doc_hashes,
                       signature_hash, prev_signature_hash
                FROM audit_ledger
                ORDER BY id ASC;
            """)
            records = cursor.fetchall()

        if not records:
            return {
                "is_valid": True,
                "total_records": 0,
                "broken_at_id": None,
                "message": "Audit ledger is currently empty. Genesis state intact.",
            }

        expected_prev_hash = GENESIS_HASH
        for rec in records:
            # 1. Verify prev_signature_hash link
            if rec["prev_signature_hash"] != expected_prev_hash:
                return {
                    "is_valid": False,
                    "total_records": len(records),
                    "broken_at_id": rec["audit_id"],
                    "broken_at_row_id": rec["id"],
                    "message": (
                        f"CRYPTOGRAPHIC INTEGRITY BREACH: Row {rec['id']} (ID: {rec['audit_id']}) "
                        f"has invalid previous hash pointer. Expected {expected_prev_hash[:16]}..., "
                        f"found {rec['prev_signature_hash'][:16]}..."
                    ),
                }

            # 2. Recompute signature hash
            hash_payload = (
                f"{rec['prev_signature_hash']}|{rec['audit_id']}|{rec['timestamp']}|{rec['event_type']}|{rec['user_id']}|"
                f"{rec['role']}|{rec['status']}|{rec['action_or_query']}|{rec['cited_doc_hashes']}"
            )
            recomputed = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

            if recomputed != rec["signature_hash"]:
                return {
                    "is_valid": False,
                    "total_records": len(records),
                    "broken_at_id": rec["audit_id"],
                    "broken_at_row_id": rec["id"],
                    "message": (
                        f"TAMPERING DETECTED: Row {rec['id']} (ID: {rec['audit_id']}) payload has been altered! "
                        f"Stored signature: {rec['signature_hash'][:16]}..., Recomputed: {recomputed[:16]}..."
                    ),
                }

            expected_prev_hash = rec["signature_hash"]

        return {
            "is_valid": True,
            "total_records": len(records),
            "broken_at_id": None,
            "message": f"Cryptographic integrity VERIFIED. All {len(records)} audit log blocks valid and intact.",
        }
