# app.py
import os
from typing import Any, List

from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route

from auth_keycloak import (
    AuthMiddleware,
    NoRedirectSlashFix,
    extract_bearer_token,
    verify_jwt,
    oidc_config,
    oauth_authorization_server,
    oauth_protected_resource,
    register_client,
)
from mcp_tools import mcp_app


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


def add_well_known(routes: List[Any], prefix: str = "") -> None:
    routes.extend(
        [
            Route(f"{prefix}/.well-known/openid-configuration", oidc_config, methods=["GET"]),
            Route(f"{prefix}/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
            Route(f"{prefix}/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
            Route(f"{prefix}/.well-known/oauth-protected-resource/mcp", oauth_protected_resource, methods=["GET"]),
        ]
    )


routes: List[Any] = [
    Route("/", root, methods=["GET"]),
    Route("/healthz", healthz, methods=["GET"]),
    Route("/whoami", whoami, methods=["GET"]),
    Route("/register", register_client, methods=["POST"]),
    Mount("/mcp", app=mcp_app),
]

# Claude probes both sets
add_well_known(routes, prefix="")
add_well_known(routes, prefix="/mcp")

_starlette_app = Starlette(debug=False, routes=routes, lifespan=mcp_app.lifespan)

# If your Starlette supports it, prevent redirect_slashes
try:
    _starlette_app.router.redirect_slashes = False
except Exception:
    pass

_starlette_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)
_starlette_app.add_middleware(AuthMiddleware)

# internal rewrite to avoid 307
app = NoRedirectSlashFix(_starlette_app)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
