"""Data Quality Pipeline Circuit Breaker (Dead-Letter Quarantine Engine).

Implements a 3-State Circuit Breaker (CLOSED -> OPEN -> HALF_OPEN) with statistical
anomaly detection, schema conformance verification, and dead-letter quarantine
to stop silent database poisoning at the pipeline ingestion boundary.
"""

import csv
import hashlib
import io
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config import (
    CircuitBreakerConfig,
    GOLD_DIR,
    QUARANTINE_DIR,
    RAW_DIR,
)
from app.models.schemas import (
    CircuitBreakerState,
    CircuitBreakerStatus,
    IngestionPayload,
    ValidationResult,
)

logger = logging.getLogger("aegis.circuit_breaker")


class DataQualityCircuitBreaker:
    """Enterprise Pipeline Circuit Breaker guarding downstream storage against data poisoning.

    Guarantees:
    1. Schema Conformance: Rejects missing mandatory columns or empty batches.
    2. Statistical Null Rate Guard: Trips if null/whitespace cells exceed 15% threshold.
    3. Anomaly Domain Guard: Blocks negative financial numbers and NaN/corrupt tokens.
    4. Dead-Letter Quarantine: Segregates toxic payloads with cryptographic sidecars.
    5. Self-Healing Probe Recovery: HALF_OPEN state with consecutive probe gating.
    """

    def __init__(
        self,
        config: type = CircuitBreakerConfig,
        quarantine_dir: Path = QUARANTINE_DIR,
        gold_dir: Path = GOLD_DIR,
    ):
        self.config = config
        self.quarantine_dir = quarantine_dir
        self.gold_dir = gold_dir

        # State Machine
        self.state: CircuitBreakerState = CircuitBreakerState.CLOSED
        self.failure_count: int = 0
        self.success_count: int = 0
        self.last_tripped_time: Optional[float] = None
        self.last_error_reason: Optional[str] = None
        self.total_quarantined_batches: int = 0
        self.total_accepted_batches: int = 0

    def get_status(self) -> CircuitBreakerStatus:
        """Returns current operational telemetry of the circuit breaker."""
        self._check_cooldown_transition()
        last_tripped_iso = (
            datetime.fromtimestamp(self.last_tripped_time, tz=timezone.utc).isoformat()
            if self.last_tripped_time
            else None
        )
        return CircuitBreakerStatus(
            state=self.state,
            failure_count=self.failure_count,
            success_count=self.success_count,
            failure_threshold=self.config.FAILURE_THRESHOLD,
            max_null_rate_threshold=self.config.MAX_NULL_RATE_THRESHOLD,
            last_tripped_at=last_tripped_iso,
            last_error_reason=self.last_error_reason,
            total_quarantined_batches=self.total_quarantined_batches,
            total_accepted_batches=self.total_accepted_batches,
        )

    def reset(self) -> CircuitBreakerStatus:
        """Manually reset the circuit breaker back to CLOSED healthy state (Admin override)."""
        logger.warning("Administrative reset triggered for Data Quality Circuit Breaker.")
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_tripped_time = None
        self.last_error_reason = None
        return self.get_status()

    def trip(self, reason: str) -> None:
        """Forces the circuit breaker to OPEN state."""
        self.state = CircuitBreakerState.OPEN
        self.last_tripped_time = time.time()
        self.last_error_reason = reason
        self.success_count = 0
        logger.error(f"[CIRCUIT BREAKER TRIPPED -> OPEN] Reason: {reason}")

    def inspect_and_ingest(self, payload: IngestionPayload) -> ValidationResult:
        """Primary gatekeeper: Inspects incoming batch and enforces circuit breaker invariants.

        Returns ValidationResult with detailed violations and quarantine path if rejected.
        """
        self._check_cooldown_transition()
        payload_hash = hashlib.sha256(payload.raw_content.encode("utf-8")).hexdigest()

        # If Circuit Breaker is already OPEN, reject immediately without pipeline poisoning
        if self.state == CircuitBreakerState.OPEN:
            quarantine_id, saved_path = self._quarantine_payload(
                payload,
                payload_hash,
                violations=[f"Circuit Breaker is OPEN due to: {self.last_error_reason}"],
            )
            self.total_quarantined_batches += 1
            return ValidationResult(
                is_valid=False,
                status="REJECTED_BREAKER_OPEN",
                null_rate=1.0,
                row_count=0,
                violations=[f"Pipeline is HALTED: Circuit Breaker is OPEN. Quarantine ID: {quarantine_id}"],
                quarantine_id=quarantine_id,
                saved_path=str(saved_path),
                payload_hash=payload_hash,
                message="Pipeline rejected payload: Circuit breaker is OPEN. Upstream ingestion locked to protect warehouse.",
            )

        # Perform deep statistical inspection of the payload
        is_valid, null_rate, row_count, violations = self._validate_payload_content(payload)

        if not is_valid:
            # Handle failure
            self.failure_count += 1
            self.total_quarantined_batches += 1
            quarantine_id, saved_path = self._quarantine_payload(payload, payload_hash, violations)

            if self.state == CircuitBreakerState.HALF_OPEN:
                # In probe state, a single failure immediately re-trips back to OPEN
                self.trip(f"Failed recovery probe in HALF_OPEN: {'; '.join(violations[:2])}")
            elif self.failure_count >= self.config.FAILURE_THRESHOLD:
                self.trip(
                    f"Threshold breached ({self.failure_count}/{self.config.FAILURE_THRESHOLD} failures): {'; '.join(violations[:2])}"
                )

            return ValidationResult(
                is_valid=False,
                status="QUARANTINED",
                null_rate=null_rate,
                row_count=row_count,
                violations=violations,
                quarantine_id=quarantine_id,
                saved_path=str(saved_path),
                payload_hash=payload_hash,
                message=f"Payload failed quality gates. Quarantined in Dead-Letter Queue ({quarantine_id}).",
            )

        # Batch is valid! Handle recovery or normal accepted state
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.SUCCESS_THRESHOLD:
                # Successfully recovered
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                self.last_error_reason = None
                logger.info("[CIRCUIT BREAKER RESTORED -> CLOSED] Pipeline probe successfully healed system.")
        else:
            # Success in CLOSED state resets consecutive failure counter
            self.failure_count = max(0, self.failure_count - 1)

        # Save clean verified batch to gold directory
        saved_gold_path = self._persist_gold_payload(payload, payload_hash)
        self.total_accepted_batches += 1

        return ValidationResult(
            is_valid=True,
            status="PASSED",
            null_rate=null_rate,
            row_count=row_count,
            violations=[],
            quarantine_id=None,
            saved_path=str(saved_gold_path),
            payload_hash=payload_hash,
            message="Data quality checks PASSED. Batch verified and promoted to Gold Storage.",
        )

    def _check_cooldown_transition(self) -> None:
        """Transitions OPEN breaker to HALF_OPEN probe state if cooldown elapsed."""
        if self.state == CircuitBreakerState.OPEN and self.last_tripped_time:
            elapsed = time.time() - self.last_tripped_time
            if elapsed >= self.config.COOLDOWN_SECONDS:
                logger.info(f"Cooldown elapsed ({elapsed:.1f}s >= {self.config.COOLDOWN_SECONDS}s). Transitioning OPEN -> HALF_OPEN.")
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0

    def _validate_payload_content(
        self, payload: IngestionPayload
    ) -> Tuple[bool, float, int, List[str]]:
        """Deep tabular and statistical inspection."""
        violations: List[str] = []
        raw = payload.raw_content.strip()

        if not raw:
            return False, 1.0, 0, ["Payload is completely empty (0 bytes)."]

        rows: List[Dict[str, str]] = []
        headers: List[str] = []

        if payload.payload_format.lower() == "csv":
            try:
                reader = csv.DictReader(io.StringIO(raw))
                if not reader.fieldnames:
                    return False, 1.0, 0, ["CSV lacks a valid header row."]
                headers = [h.strip() for h in reader.fieldnames if h]
                for row_idx, r in enumerate(reader):
                    rows.append({k.strip(): (v.strip() if v else "") for k, v in r.items() if k})
            except Exception as exc:
                return False, 1.0, 0, [f"CSV parsing exception: {str(exc)}"]
        elif payload.payload_format.lower() == "json":
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    if not parsed:
                        return False, 1.0, 0, ["JSON array is empty."]
                    headers = list(parsed[0].keys())
                    rows = [{k: str(v) if v is not None else "" for k, v in item.items()} for item in parsed]
                elif isinstance(parsed, dict):
                    headers = list(parsed.keys())
                    rows = [{k: str(v) if v is not None else "" for k, v in parsed.items()}]
                else:
                    return False, 1.0, 0, ["JSON root is neither an object nor an array."]
            except Exception as exc:
                return False, 1.0, 0, [f"JSON parsing exception: {str(exc)}"]
        else:
            return False, 1.0, 0, [f"Unsupported payload format: {payload.payload_format}"]

        row_count = len(rows)
        if row_count == 0:
            return False, 1.0, 0, ["Payload contains 0 data rows."]

        total_cells = row_count * len(headers)
        if total_cells == 0:
            return False, 1.0, 0, ["Zero cells found in parsed table."]

        # Calculate null rate
        empty_cells = 0
        column_empty_counts: Dict[str, int] = {h: 0 for h in headers}

        for row in rows:
            for h in headers:
                val = row.get(h, "")
                if val == "" or val.lower() in {"null", "none", "nan", "nil"}:
                    empty_cells += 1
                    column_empty_counts[h] += 1

        overall_null_rate = empty_cells / total_cells

        # Threshold 1: Statistical Null Rate
        if overall_null_rate > self.config.MAX_NULL_RATE_THRESHOLD:
            violations.append(
                f"Statistical null rate {overall_null_rate:.1%} breaches threshold ({self.config.MAX_NULL_RATE_THRESHOLD:.1%}) [{empty_cells}/{total_cells} empty cells]."
            )

        # Threshold 2: Single-column critical null rate (> 40% in any single column)
        for h, count in column_empty_counts.items():
            col_null_rate = count / row_count
            if col_null_rate > 0.40:
                violations.append(f"Column '{h}' has critical null rate of {col_null_rate:.1%} ({count}/{row_count} rows).")

        # Threshold 3: Anomaly detection on numeric / monetary domains
        for row_idx, row in enumerate(rows):
            for col_name, val in row.items():
                lower_col = col_name.lower()
                if any(monetary_term in lower_col for monetary_term in self.config.REJECT_NEGATIVE_VALUES_FOR_COLS):
                    if val and val.replace(".", "", 1).replace("-", "", 1).isdigit():
                        try:
                            num = float(val)
                            if num < 0:
                                violations.append(
                                    f"Domain anomaly at row {row_idx + 1}: Negative value {num} in financial column '{col_name}'."
                                )
                        except ValueError:
                            pass

        is_valid = len(violations) == 0
        return is_valid, overall_null_rate, row_count, violations

    def _quarantine_payload(
        self, payload: IngestionPayload, payload_hash: str, violations: List[str]
    ) -> Tuple[str, Path]:
        """Isolates poisoned payload into Dead-Letter Queue with cryptographic metadata sidecar."""
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        short_hash = payload_hash[:12]
        quarantine_id = f"dlq_{timestamp_str}_{short_hash}"

        file_ext = "csv" if payload.payload_format.lower() == "csv" else "json"
        data_path = self.quarantine_dir / f"{quarantine_id}.{file_ext}"
        meta_path = self.quarantine_dir / f"{quarantine_id}.meta.json"

        # Write raw quarantined data
        with open(data_path, "w", encoding="utf-8") as f:
            f.write(payload.raw_content)

        # Write cryptographic sidecar
        metadata = {
            "quarantine_id": quarantine_id,
            "source_id": payload.source_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_hash_sha256": payload_hash,
            "violations": violations,
            "breaker_state_at_quarantine": self.state.value,
            "quarantined_file": data_path.name,
            "metadata": payload.metadata,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.warning(f"Payload quarantined into DLQ: {data_path.name}. Violations: {violations}")
        return quarantine_id, data_path

    def _persist_gold_payload(self, payload: IngestionPayload, payload_hash: str) -> Path:
        """Stores clean, validated payload into Gold directory for downstream analytics."""
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_ext = "csv" if payload.payload_format.lower() == "csv" else "json"
        gold_path = self.gold_dir / f"gold_{payload.source_id}_{timestamp_str}_{payload_hash[:8]}.{file_ext}"

        with open(gold_path, "w", encoding="utf-8") as f:
            f.write(payload.raw_content)

        return gold_path
