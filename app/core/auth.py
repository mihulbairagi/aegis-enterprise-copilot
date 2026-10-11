import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import AuthConfig, Role
from app.models.schemas import AuthenticatedUser

# Standard HTTPBearer scheme
security = HTTPBearer(auto_error=False)


def hash_password(password: str, salt: str) -> str:
    """Computes PBKDF2-HMAC-SHA256 password hash."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
    ).hex()


SALT_INTERN = "aegis_salt_intern_2026_x89"
SALT_ANALYST = "aegis_salt_analyst_2026_q41"
SALT_EXEC = "aegis_salt_exec_2026_w73"

ENTERPRISE_USERS: Dict[str, Dict[str, Any]] = {
    "intern_user": {
        "user_id": "intern_alex",
        "role": Role.INTERN,
        "salt": SALT_INTERN,
        "password_hash": hash_password("intern_pass_2026", SALT_INTERN),
    },
    "user.intern@enterprise.internal": {
        "user_id": "intern_alex",
        "role": Role.INTERN,
        "salt": SALT_INTERN,
        "password_hash": hash_password("intern_pass_2026", SALT_INTERN),
    },
    "analyst_user": {
        "user_id": "analyst_priya",
        "role": Role.ANALYST,
        "salt": SALT_ANALYST,
        "password_hash": hash_password("analyst_pass_2026", SALT_ANALYST),
    },
    "sarah.analyst@enterprise.internal": {
        "user_id": "analyst_priya",
        "role": Role.ANALYST,
        "salt": SALT_ANALYST,
        "password_hash": hash_password("analyst_pass_2026", SALT_ANALYST),
    },
    "exec_user": {
        "user_id": "exec_marcus",
        "role": Role.EXECUTIVE,
        "salt": SALT_EXEC,
        "password_hash": hash_password("exec_pass_2026", SALT_EXEC),
    },
    "marcus.exec@enterprise.internal": {
        "user_id": "exec_marcus",
        "role": Role.EXECUTIVE,
        "salt": SALT_EXEC,
        "password_hash": hash_password("exec_pass_2026", SALT_EXEC),
    },
}


def authenticate_user(username: str, password: str) -> Optional[AuthenticatedUser]:
    """Timing-safe enterprise credential authentication."""
    user_record = ENTERPRISE_USERS.get(username.strip().lower())
    if not user_record:
        return None
    computed = hash_password(password, user_record["salt"])
    if not hmac.compare_digest(computed, user_record["password_hash"]):
        return None
    return AuthenticatedUser(
        user_id=user_record["user_id"],
        role=user_record["role"],
    )


def create_access_token(
    user_id: str,
    role: Role,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Issues a cryptographically signed JWT with user identity and RBAC role."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,
        "role": role.value if isinstance(role, Role) else str(role),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    encoded_jwt = jwt.encode(payload, AuthConfig.SECRET_KEY, algorithm=AuthConfig.ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str) -> AuthenticatedUser:
    """Decodes and cryptographically validates JWT signature and expiration."""
    try:
        payload = jwt.decode(
            token,
            AuthConfig.SECRET_KEY,
            algorithms=[AuthConfig.ALGORITHM],
        )
        user_id = payload.get("sub")
        role_str = payload.get("role")
        if not user_id or not role_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing required claims ('sub', 'role').",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            role = Role(role_str)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token contains invalid enterprise role '{role_str}'.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return AuthenticatedUser(user_id=user_id, role=role)

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Re-authenticate via /api/auth/token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid cryptographic token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthenticatedUser:
    """FastAPI Dependency: Enforces valid Bearer token on protected endpoints."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Expected: 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_access_token(credentials.credentials)


def require_role(min_role: Role):
    """Enforces role clearance level on administrative and privileged endpoints."""
    def dependency(current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        from app.config import ROLE_HIERARCHY_LEVEL
        caller_level = ROLE_HIERARCHY_LEVEL.get(current_user.role, 0)
        required_level = ROLE_HIERARCHY_LEVEL.get(min_role, 3)
        if caller_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Action requires '{min_role.value}' clearance. Current caller role: '{current_user.role.value}'.",
            )
        return current_user
    return dependency


require_executive = require_role(Role.EXECUTIVE)

