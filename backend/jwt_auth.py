"""Authentication utilities for API request identity resolution.

This module validates Supabase JWT bearer tokens and provides a development
bypass path for local testing.

Key invariants:
    - Production requests require a valid bearer token.
    - Local bypass is opt-in via environment variable.
    - Returned user object always contains `user_id` and `email`.
"""

import os
from dataclasses import dataclass

from fastapi import Header, HTTPException
from jose import JWTError, jwt


@dataclass
class AuthUser:
    """Authenticated user context attached to API handlers.

    Attributes:
        user_id: Stable identity subject used for project scoping.
        email: User email for ownership and billing metadata.
    """

    user_id: str
    email: str


def _decode_supabase_jwt(token: str) -> dict:
    """Decode and validate a Supabase JWT payload.

    Args:
        token: Raw JWT string from Authorization header.

    Returns:
        dict: Decoded claims payload.

    Raises:
        HTTPException: 500 when JWT secret is not configured.
        HTTPException: 401 when token cannot be decoded/validated.
    """
    secret = os.getenv("SUPABASE_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="SUPABASE_JWT_SECRET is not configured.",
        )
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], options={"verify_aud": False})
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid JWT: {exc}") from exc


def get_current_user(authorization: str | None = Header(default=None)) -> AuthUser:
    """Resolve authenticated user from bearer token or local bypass.

    Side effects:
        Reads process environment variables.

    Idempotency:
        Idempotent for identical input header and environment variables.

    Audit Notes:
        - What can go wrong: bypass variables accidentally enabled in shared env.
        - Detection: inspect startup/configuration and request auth behavior.
        - Recovery: unset `AUTH_BYPASS_USER_ID` and require bearer tokens.

    Args:
        authorization: Raw Authorization header value.

    Returns:
        AuthUser: Normalized authenticated user context.

    Raises:
        HTTPException: 401 on missing/invalid bearer token or subject claim.
        HTTPException: 500 when JWT secret is not configured.
    """
    # Optional local bypass for rapid development.
    if os.getenv("AUTH_BYPASS_USER_ID"):
        return AuthUser(
            user_id=os.environ["AUTH_BYPASS_USER_ID"],
            email=os.getenv("AUTH_BYPASS_EMAIL", "dev@example.com"),
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")

    token = authorization.split(" ", 1)[1].strip()
    payload = _decode_supabase_jwt(token)
    user_id = payload.get("sub")
    email = payload.get("email") or payload.get("user_email") or "unknown@example.com"
    if not user_id:
        raise HTTPException(status_code=401, detail="JWT missing subject (sub).")
    return AuthUser(user_id=user_id, email=email)
