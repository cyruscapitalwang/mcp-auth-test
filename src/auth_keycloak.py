# auth_keycloak.py
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jwt
from jwt import PyJWKClient

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


DEFAULT_SCOPES: List[str] = ["openid", "profile", "email"]


@dataclass(frozen=True)
class KeycloakConfig:
    base_url: str = os.getenv(
        "KC_BASE_URL",
        "https://keycloak.grayisland-59e8a8bb.eastus.azurecontainerapps.io",
    )
    realm: str = os.getenv("KC_REALM", "GAINSystems")

    client_id: str = os.getenv("KC_CLIENT_ID", "claude_mcp").strip()
    expected_azp: str = os.getenv("KC_EXPECTED_AZP", "claude_mcp").strip()
    expected_aud: str = os.getenv("KC_EXPECTED_AUD", "").strip()

    @property
    def issuer(self) -> str:
        return f"{self.base_url}/realms/{self.realm}"

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/auth"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    @property
    def userinfo_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/userinfo"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"


CFG = KeycloakConfig()
_JWK_CLIENT = PyJWKClient(CFG.jwks_uri)


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization")
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    return token or None


def verify_jwt(access_token: str) -> Dict[str, Any]:
    signing_key = _JWK_CLIENT.get_signing_key_from_jwt(access_token).key
    claims = jwt.decode(
        access_token,
        signing_key,
        algorithms=["RS256"],
        issuer=CFG.issuer,
        options={"verify_aud": False},
    )

    if CFG.expected_azp:
        azp = claims.get("azp")
        if not azp:
            raise jwt.InvalidTokenError("missing azp claim")
        if azp != CFG.expected_azp:
            raise jwt.InvalidTokenError(f"azp mismatch: expected {CFG.expected_azp}, got {azp}")

    if CFG.expected_aud:
        aud = claims.get("aud")
        if isinstance(aud, str):
            aud_list = [aud]
        elif isinstance(aud, list):
            aud_list = aud
        else:
            aud_list = []
        if CFG.expected_aud not in aud_list:
            raise jwt.InvalidTokenError(f"aud mismatch: expected {CFG.expected_aud}, got {aud}")

    return claims


def external_base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


# ----- Claude discovery endpoints handlers -----

async def oidc_config(_request: Request):
    return JSONResponse(
        {
            "issuer": CFG.issuer,
            "authorization_endpoint": CFG.authorization_endpoint,
            "token_endpoint": CFG.token_endpoint,
            "userinfo_endpoint": CFG.userinfo_endpoint,
            "jwks_uri": CFG.jwks_uri,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": DEFAULT_SCOPES,
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }
    )


async def oauth_authorization_server(request: Request):
    base = external_base_url(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": CFG.authorization_endpoint,
            "token_endpoint": CFG.token_endpoint,
            "jwks_uri": CFG.jwks_uri,
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": DEFAULT_SCOPES,
            "token_endpoint_auth_methods_supported": ["none"],
        }
    )


async def oauth_protected_resource(request: Request):
    base = external_base_url(request)
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": DEFAULT_SCOPES,
            "bearer_methods_supported": ["header"],
        }
    )


async def register_client(request: Request):
    base = external_base_url(request)
    return JSONResponse(
        {
            "client_id": CFG.client_id,
            "client_id_issued_at": 0,
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["claude://claude.ai/*", "https://claude.ai/*"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": " ".join(DEFAULT_SCOPES),
            "authorization_endpoint": CFG.authorization_endpoint,
            "token_endpoint": CFG.token_endpoint,
            "issuer_for_tokens": CFG.issuer,
            "mcp_resource": f"{base}/mcp",
        }
    )


# ----- Middleware & redirect fix -----

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if request.method == "OPTIONS":
            return await call_next(request)

        if (
            path == "/"
            or path == "/healthz"
            or path == "/whoami"
            or path == "/register"
            or "/.well-known/" in path
        ):
            return await call_next(request)

        if path.startswith("/mcp"):
            token = extract_bearer_token(request)
            if not token:
                return JSONResponse({"error": "missing_bearer_token"}, status_code=401)

            try:
                request.state.jwt_claims = verify_jwt(token)
            except Exception as e:
                return JSONResponse({"error": "invalid_token", "details": str(e)}, status_code=401)

        return await call_next(request)


class NoRedirectSlashFix:
    """
    Claude POSTs /mcp (no trailing slash). Some sub-apps redirect to /mcp/.
    Claude often drops Authorization on redirect -> 401.
    Rewrite internally with NO redirect.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/mcp":
            scope = dict(scope)
            scope["path"] = "/mcp/"
        await self.app(scope, receive, send)
