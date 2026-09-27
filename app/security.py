import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, Request
from .config import settings

def authenticate(request: Request):
    if not settings.require_auth:
        return {"sub": "development"}
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    if not settings.jwt_jwks_url:
        raise HTTPException(503, "JWT JWKS is not configured")
    token = auth[7:]
    try:
        key = PyJWKClient(settings.jwt_jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key,
            algorithms=["RS256", "ES256"],
            issuer=settings.jwt_issuer or None,
            audience=settings.jwt_audience or None,
            options={"verify_iss": bool(settings.jwt_issuer),
                     "verify_aud": bool(settings.jwt_audience)}
        )
        return claims
    except Exception as exc:
        raise HTTPException(401, f"Invalid token: {type(exc).__name__}")
