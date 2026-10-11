"""Enterprise JWT Authentication & Cryptographic RBAC Verification.

Provides token issuance and strict Bearer token validation using PyJWT.
Extracts verified roles and prevents client-side role spoofing.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import AuthConfig, Role
from app.models.schemas import AuthenticatedUser

# Standard HTTPBearer scheme
security = HTTPBearer(auto_error=False)


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
