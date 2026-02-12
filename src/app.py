import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, List

import jwt
from jwt import PyJWKClient
from fastmcp import FastMCP

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route


# ============================================================
# Keycloak / OIDC Configuration (Resource Server)
# ============================================================

@dataclass(frozen=True)
class KeycloakConfig:
    base_url: str = os.environ.get(
        "KC_BASE_URL",
        "https://keycloak.grayisland-59e8a8bb.eastus.azurecontainerapps.io",
    )
    realm: str = os.environ.get("KC_REALM", "gains")

    # Keycloak client that Claude will use when doing auth code + PKCE
    client_id: str = os.environ.get("KC_CLIENT_ID", "claude-mcp").strip()

    # Optional: enforce token was issued to this Keycloak client (azp claim).
    # Set KC_EXPECTED_AZP="" to disable.
    expected_azp: str = os.environ.get("KC_EXPECTED_AZP", "claude-mcp").strip()

    # Optional: enforce audience (ONLY if your Keycloak tokens include your API as aud).
    # Set KC_EXPECTED_AUD="" to disable.
    expected_aud: str = os.environ.get("KC_EXPECTED_AUD", "").strip()

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

DEFAULT_SCOPES: List[str] = ["openid", "profile", "email"]


# ============================================================
# Helpers
# ============================================================

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
        options={"verify_aud": False},  # enforce aud manually if configured
    )

    print("==== JWT CLAIMS ====")
    print(claims)
    print("====================")

    if CFG.expected_azp:
        azp = claims.get("azp")
        if not azp:
            raise jwt.InvalidTokenError("missing azp claim")
        if azp != CFG.expected_azp:
            raise jwt.InvalidTokenError(
                f"azp mismatch: expected {CFG.expected_azp}, got {azp}"
            )

    if CFG.expected_aud:
        aud = claims.get("aud")
        if isinstance(aud, str):
            aud_list = [aud]
        elif isinstance(aud, list):
            aud_list = aud
        else:
            aud_list = []
        if CFG.expected_aud not in aud_list:
            raise jwt.InvalidTokenError(
                f"aud mismatch: expected {CFG.expected_aud}, got {aud}"
            )

    return claims


def _external_base_url(request: Request) -> str:
    """
    Build absolute base URL as seen externally (important behind Azure App Service proxy).
    """
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


# ============================================================
# Discovery Endpoints
# ============================================================

async def oidc_config(_request: Request):
    # OIDC discovery for Keycloak
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
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        }
    )


async def oauth_authorization_server(request: Request):
    """
    RFC 8414: OAuth Authorization Server Metadata.
    IMPORTANT: issuer = THIS server base URL (so /register lives here),
    but auth/token endpoints remain Keycloak.
    """
    base = _external_base_url(request)
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


async def oauth_protected_resource_root(request: Request):
    """
    RFC 9728: OAuth Protected Resource Metadata.
    authorization_servers MUST point to THIS server base.
    """
    base = _external_base_url(request)
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": DEFAULT_SCOPES,
            "bearer_methods_supported": ["header"],
        }
    )


async def oauth_protected_resource_mcp(request: Request):
    return await oauth_protected_resource_root(request)


async def register_client(request: Request):
    """
    Claude Desktop POSTs /register. We return your EXISTING Keycloak client_id.
    """
    base = _external_base_url(request)

    # Not required, but safe if Claude sends JSON body.
    try:
        await request.json()
    except Exception:
        pass

    return JSONResponse(
        {
            "client_id": CFG.client_id,
            "client_id_issued_at": 0,
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["claude://claude.ai/*", "https://claude.ai/*"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": " ".join(DEFAULT_SCOPES),

            # Debug hints (harmless extra fields)
            "authorization_endpoint": CFG.authorization_endpoint,
            "token_endpoint": CFG.token_endpoint,
            "issuer_for_tokens": CFG.issuer,
            "mcp_resource": f"{base}/mcp",
        }
    )


# ============================================================
# Auth Middleware
# ============================================================

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if request.method == "OPTIONS":
            return await call_next(request)

        # Allow discovery + register + health without auth
        if (
            path == "/"
            or path == "/healthz"
            or path == "/register"
            or path.startswith("/.well-known/")
            or path.startswith("/mcp/.well-known/")
        ):
            return await call_next(request)

        # Protect MCP endpoint
        if path.startswith("/mcp"):
            token = extract_bearer_token(request)
            if not token:
                return JSONResponse({"error": "missing_bearer_token"}, status_code=401)
            try:
                request.state.jwt_claims = verify_jwt(token)
            except Exception as e:
                return JSONResponse({"error": "invalid_token", "details": str(e)}, status_code=401)

        return await call_next(request)


# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP("keycloak-mcp")

FAKE_DATABASE = {
    ("rexel", "prod"): 12450,
    ("rexel", "dev"): 530,
    ("bse", "prod"): 9800,
    ("bse", "sit"): 2100,
}


@mcp.tool()
def get_sku_count(customer: str, environment: str) -> Dict[str, Any]:
    key = (customer.lower(), environment.lower())
    return {"customer": customer, "environment": environment, "sku_count": FAKE_DATABASE.get(key, 0)}


@mcp.tool()
def get_customer_and_its_environment() -> Dict[str, Any]:
    result: Dict[str, list] = {}
    for (cust, env) in FAKE_DATABASE.keys():
        result.setdefault(cust, [])
        if env not in result[cust]:
            result[cust].append(env)
    for cust in result:
        result[cust].sort()
    return result


mcp_app = mcp.http_app(path="/")


# ============================================================
# Extra HTTP Endpoints
# ============================================================

async def root(_request: Request):
    return PlainTextResponse("ok")


async def healthz(_request: Request):
    return PlainTextResponse("ok")


async def whoami(request: Request):
    token = extract_bearer_token(request)
    if not token:
        return JSONResponse({"ok": False, "error": "missing_bearer_token"}, status_code=401)
    try:
        claims = verify_jwt(token)
        return JSONResponse({"ok": True, "claims": claims})
    except Exception as e:
        return JSONResponse({"ok": False, "error": "invalid_token", "details": str(e)}, status_code=401)


# ============================================================
# Starlette App
# ============================================================

app = Starlette(
    debug=False,
    routes=[
        Route("/", root, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/whoami", whoami, methods=["GET"]),

        # Root discovery (what Claude probes)
        Route("/.well-known/openid-configuration", oidc_config, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource_root, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", oauth_protected_resource_mcp, methods=["GET"]),

        # Also under /mcp (some clients probe relative to MCP base URL)
        Route("/mcp/.well-known/openid-configuration", oidc_config, methods=["GET"]),
        Route("/mcp/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
        Route("/mcp/.well-known/oauth-protected-resource", oauth_protected_resource_root, methods=["GET"]),
        Route("/mcp/.well-known/oauth-protected-resource/mcp", oauth_protected_resource_mcp, methods=["GET"]),

        # Claude registration
        Route("/register", register_client, methods=["POST"]),

        # MCP (mounted twice to avoid any redirect edge cases)
        Mount("/mcp", app=mcp_app),
        Mount("/mcp/", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

app.add_middleware(AuthMiddleware)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
