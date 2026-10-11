"""Enterprise System Configuration & Security Governance Settings.

Defines role hierarchies, Row-Level Security (RLS) clearance tiers,
data quality circuit breaker thresholds, and storage persistence paths.
"""

import os
from enum import Enum
from pathlib import Path
import logging
import secrets
from typing import Dict, List, Set

_logger = logging.getLogger("aegis.config")

class AuthConfig:
    """Enterprise JWT authentication parameters."""
    _env_secret = os.getenv("JWT_SECRET_KEY")
    if _env_secret:
        SECRET_KEY: str = _env_secret
    else:
        SECRET_KEY: str = secrets.token_hex(32)
        _logger.warning(
            "CRITICAL SECURITY NOTICE: 'JWT_SECRET_KEY' environment variable not set. "
            "Generated an ephemeral 256-bit cryptographically secure secret for runtime."
        )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60


class RouterPlusConfig:
    """Live LLM synthesis via RouterPlus API."""
    BASE_URL: str = os.getenv("ROUTERPLUS_BASE_URL", "https://api.routerplus.com/v1")
    API_KEY: str = os.getenv("ROUTERPLUS_API_KEY", "")
    MODEL: str = os.getenv("ROUTERPLUS_MODEL", "claude-sonnet-5-5")
    TIMEOUT_SECONDS: float = 15.0


class Role(str, Enum):
    """Enterprise Role-Based Access Control (RBAC) tiers."""
    INTERN = "INTERN"
    ANALYST = "ANALYST"
    EXECUTIVE = "EXECUTIVE"


class SecurityClassification(str, Enum):
    """Information security sensitivity tags applied to document chunks and tables."""
    PUBLIC = "PUBLIC"              # Tier 0: General public / unclassified
    INTERNAL = "INTERNAL"          # Tier 1: General internal company operations
    RESTRICTED = "RESTRICTED"      # Tier 2: Operational finances, vendor negotiations, department metrics
    EXECUTIVE = "EXECUTIVE"        # Tier 3: Confidential payroll, executive compensation, M&A strategy


# Strict Row-Level Security (RLS) Clearance Mapping
# Queries from a given role are mathematically constrained to these classification tags BEFORE retrieval.
ROLE_CLEARANCE: Dict[Role, Set[SecurityClassification]] = {
    Role.INTERN: {
        SecurityClassification.PUBLIC,
        SecurityClassification.INTERNAL,
    },
    Role.ANALYST: {
        SecurityClassification.PUBLIC,
        SecurityClassification.INTERNAL,
        SecurityClassification.RESTRICTED,
    },
    Role.EXECUTIVE: {
        SecurityClassification.PUBLIC,
        SecurityClassification.INTERNAL,
        SecurityClassification.RESTRICTED,
        SecurityClassification.EXECUTIVE,
    },
}

# Role hierarchy levels for quick privilege checks (Higher = More Clearance)
ROLE_HIERARCHY_LEVEL: Dict[Role, int] = {
    Role.INTERN: 1,
    Role.ANALYST: 2,
    Role.EXECUTIVE: 3,
}

# Allowed action executions by role
ROLE_PERMITTED_ACTIONS: Dict[Role, Set[str]] = {
    Role.INTERN: {"READ_STATUS", "EXPORT_PUBLIC_REPORT"},
    Role.ANALYST: {"READ_STATUS", "EXPORT_PUBLIC_REPORT", "GENERATE_OPERATIONAL_SUMMARY", "FLAG_VENDOR_INVOICE"},
    Role.EXECUTIVE: {
        "READ_STATUS",
        "EXPORT_PUBLIC_REPORT",
        "GENERATE_OPERATIONAL_SUMMARY",
        "FLAG_VENDOR_INVOICE",
        "ADJUST_BUDGET",
        "APPROVE_PO",
        "FREEZE_VENDOR",
        "PAYROLL_OVERRIDE",
    },
}


class CircuitBreakerConfig:
    """Statistical thresholds and state-machine tuning for Data Quality Circuit Breaker."""
    # Breaker trips if the overall null/empty rate across critical fields exceeds this ratio (15%)
    MAX_NULL_RATE_THRESHOLD: float = 0.15

    # Number of consecutive malformed/poisoned batches required to trip the breaker to OPEN
    FAILURE_THRESHOLD: int = 3

    # Consecutive healthy batches required in HALF_OPEN state to restore to CLOSED
    SUCCESS_THRESHOLD: int = 2

    # Timeout in seconds before an OPEN circuit breaker transitions to HALF_OPEN probe state
    COOLDOWN_SECONDS: float = 60.0

    # Max allowed anomaly deviation (e.g. negative values in non-negative numeric columns)
    REJECT_NEGATIVE_VALUES_FOR_COLS: Set[str] = {"salary", "bonus", "amount", "unit_price", "total_cost"}


# Filesystem persistence paths
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"
RAW_DIR: Path = DATA_DIR / "raw"
QUARANTINE_DIR: Path = DATA_DIR / "quarantined"  # Dead-Letter Queue (DLQ)
GOLD_DIR: Path = DATA_DIR / "gold"                # Verified clean data
AUDIT_DB_PATH: Path = DATA_DIR / "audit.db"
DUCKDB_PATH: Path = DATA_DIR / "warehouse.duckdb"

# Ensure runtime directories exist
for directory in (DATA_DIR, RAW_DIR, QUARANTINE_DIR, GOLD_DIR):
    directory.mkdir(parents=True, exist_ok=True)
