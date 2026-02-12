# app.py
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

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

    # Optional: enforce token was issued to this client (Keycloak "azp" claim).
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

# Cache JWKS client globally (fast enough, no need to rebuild each request)
_JWK_CLIENT = PyJWKClient(CFG.jwks_uri)


def verify_jwt(access_token: str) -> Dict[str, Any]:
    """
    Verify:
      - signature via JWKS
      - issuer == Keycloak realm issuer
      - optionally enforce azp (client id)
      - optionally enforce aud (if configured)
    """
    signing_key = _JWK_CLIENT.get_signing_key_from_jwt(access_token).key

    # Many Keycloak setups don't use aud the way typical APIs expect, so we do it manually.
    claims = jwt.decode(
        access_token,
        signing_key,
        algorithms=["RS256"],
        issuer=CFG.issuer,
        options={"verify_aud": False},
    )

    # Optional azp enforcement
    if CFG.expected_azp:
        azp = claims.get("azp")
        if not azp:
            raise jwt.InvalidTokenError("missing azp claim")
        if azp != CFG.expected_azp:
            raise jwt.InvalidTokenError(f"azp mismatch: expected {CFG.expected_azp}, got {azp}")

    # Optional aud enforcement
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


def extract_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization")
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    return token or None


# ============================================================
# Auth Middleware (protect /mcp)
# ============================================================

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Let CORS preflight through
        if request.method == "OPTIONS":
            return await call_next(request)

        # Only protect MCP endpoints
        if request.url.path.startswith("/mcp"):
            token = extract_bearer_token(request)
            if not token:
                return JSONResponse({"error": "missing_bearer_token"}, status_code=401)

            try:
                claims = verify_jwt(token)
                request.state.jwt_claims = claims
            except Exception as e:
                return JSONResponse({"error": "invalid_token", "details": str(e)}, status_code=401)

        return await call_next(request)


# ============================================================
# OIDC / OAuth Metadata Endpoints (for MCP Inspector / clients)
# ============================================================

async def oidc_config(_request: Request):
    # Important: some clients validate schema strictly
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
            "scopes_supported": ["openid", "profile", "email"],
            # Include these to satisfy some strict clients:
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        }
    )


async def oauth_server(_request: Request):
    # Some clients use this RFC 8414 endpoint instead of OIDC config
    return JSONResponse(
        {
            "issuer": CFG.issuer,
            "authorization_endpoint": CFG.authorization_endpoint,
            "token_endpoint": CFG.token_endpoint,
            "jwks_uri": CFG.jwks_uri,
        }
    )


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
    return {
        "customer": customer,
        "environment": environment,
        "sku_count": FAKE_DATABASE.get(key, 0),
    }


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


# MCP ASGI app (we mount at /mcp, so path="/")
mcp_app = mcp.http_app(path="/")


# ============================================================
# Extra HTTP Endpoints
# ============================================================

async def healthz(_request: Request):
    return PlainTextResponse("ok")


async def whoami(request: Request):
    """
    Debug endpoint: verify Authorization header and return JWT claims.
    Helpful to test locally with curl.
    """
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
    routes=[
        Route("/healthz", healthz, methods=["GET"]),

        # Support BOTH dotted and non-dotted paths (different clients do different things)
        Route("/.well-known/openid-configuration", oidc_config, methods=["GET"]),
        Route("/well-known/openid-configuration", oidc_config, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth_server, methods=["GET"]),
        Route("/well-known/oauth-authorization-server", oauth_server, methods=["GET"]),

        Route("/whoami", whoami, methods=["GET"]),
        Mount("/mcp", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,
)

# CORS helps browser-based tools (MCP Inspector)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

# Auth after CORS so OPTIONS preflight can pass
app.add_middleware(AuthMiddleware)


# ============================================================
# Main (local run)
# ============================================================

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
