import base64
import hashlib
import json
import os
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import httpx
import jwt
from jwt import PyJWKClient

from mcp.server.fastmcp import FastMCP


@dataclass(frozen=True)
class KeycloakConfig:
    base_url: str = os.environ.get(
        "KC_BASE_URL",
        "https://keycloak.grayisland-59e8a8bb.eastus.azurecontainerapps.io",
    )
    realm: str = os.environ.get("KC_REALM", "gains")
    client_id: str = os.environ.get("KC_CLIENT_ID", "claude-mcp")

    redirect_host: str = os.environ.get("KC_REDIRECT_HOST", "127.0.0.1")
    redirect_port: int = int(os.environ.get("KC_REDIRECT_PORT", "8765"))
    redirect_path: str = os.environ.get("KC_REDIRECT_PATH", "/callback")

    scope: str = os.environ.get("KC_SCOPE", "openid profile email")

    token_path: str = os.environ.get(
        "KC_TOKEN_PATH",
        os.path.expanduser("~/.cache/claude-mcp/keycloak_tokens.json"),
    )

    timeout_seconds: float = float(os.environ.get("KC_TIMEOUT", "20"))

    @property
    def redirect_uri(self) -> str:
        return f"http://{self.redirect_host}:{self.redirect_port}{self.redirect_path}"

    @property
    def auth_url(self) -> str:
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/auth"

    @property
    def token_url(self) -> str:
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"

    @property
    def userinfo_url(self) -> str:
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/userinfo"

    @property
    def jwks_url(self) -> str:
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/certs"


CFG = KeycloakConfig()


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _pkce_verifier() -> str:
    return _b64url_no_pad(secrets.token_bytes(32))


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return _b64url_no_pad(digest)


def _ensure_token_dir():
    os.makedirs(os.path.dirname(CFG.token_path), exist_ok=True)


def _save_tokens(tokens: Dict[str, Any]) -> None:
    _ensure_token_dir()
    with open(CFG.token_path, "w") as f:
        json.dump(tokens, f, indent=2)


def _load_tokens() -> Optional[Dict[str, Any]]:
    try:
        with open(CFG.token_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def _delete_tokens() -> None:
    try:
        os.remove(CFG.token_path)
    except FileNotFoundError:
        pass


def _now() -> int:
    return int(time.time())


def _is_access_token_expired(tokens: Dict[str, Any]) -> bool:
    expires_at = tokens.get("expires_at")
    if isinstance(expires_at, int):
        return _now() >= expires_at - 10

    at = tokens.get("access_token")
    if not at:
        return True
    try:
        payload = jwt.decode(at, options={"verify_signature": False})
        exp = int(payload.get("exp", 0))
        return _now() >= exp - 10
    except Exception:
        return True


def _token_exchange(code: str, code_verifier: str) -> Dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "client_id": CFG.client_id,
        "code": code,
        "redirect_uri": CFG.redirect_uri,
        "code_verifier": code_verifier,
    }
    with httpx.Client(timeout=CFG.timeout_seconds) as client:
        r = client.post(CFG.token_url, data=data)
        r.raise_for_status()
        tokens = r.json()

    if "expires_in" in tokens:
        tokens["expires_at"] = _now() + int(tokens["expires_in"])
    return tokens


def _refresh(tokens: Dict[str, Any]) -> Dict[str, Any]:
    rt = tokens.get("refresh_token")
    if not rt:
        raise RuntimeError("No refresh_token found. Please login again.")

    data = {
        "grant_type": "refresh_token",
        "client_id": CFG.client_id,
        "refresh_token": rt,
    }
    with httpx.Client(timeout=CFG.timeout_seconds) as client:
        r = client.post(CFG.token_url, data=data)
        r.raise_for_status()
        new_tokens = r.json()

    if "expires_in" in new_tokens:
        new_tokens["expires_at"] = _now() + int(new_tokens["expires_in"])

    if "refresh_token" not in new_tokens:
        new_tokens["refresh_token"] = rt
    return new_tokens


def _get_valid_access_token() -> str:
    tokens = _load_tokens()
    if not tokens:
        raise RuntimeError("Not logged in. Call login() first.")
    if _is_access_token_expired(tokens):
        tokens = _refresh(tokens)
        _save_tokens(tokens)
    at = tokens.get("access_token")
    if not at:
        raise RuntimeError("Missing access_token. Call login() again.")
    return at


def _verify_jwt_signature(access_token: str) -> Dict[str, Any]:
    jwk_client = PyJWKClient(CFG.jwks_url)
    signing_key = jwk_client.get_signing_key_from_jwt(access_token).key
    issuer = f"{CFG.base_url}/realms/{CFG.realm}"

    payload = jwt.decode(
        access_token,
        signing_key,
        algorithms=["RS256"],
        issuer=issuer,
        options={"verify_aud": False},
    )
    return payload


class _CallbackState:
    def __init__(self):
        self.code: Optional[str] = None
        self.state: Optional[str] = None
        self.error: Optional[str] = None


def _run_callback_server(expected_state: str, out: _CallbackState) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != CFG.redirect_path:
                self.send_response(404)
                self.end_headers()
                return

            qs = parse_qs(parsed.query)
            err = qs.get("error", [None])[0]
            if err:
                out.error = err
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Login failed. You can close this tab.")
                return

            code = qs.get("code", [None])[0]
            state = qs.get("state", [None])[0]
            if not code or not state:
                out.error = "missing_code_or_state"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Missing code/state. You can close this tab.")
                return

            if state != expected_state:
                out.error = "state_mismatch"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"State mismatch. You can close this tab.")
                return

            out.code = code
            out.state = state
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login complete. You can close this tab.")

        def log_message(self, format, *args):
            return

    return HTTPServer((CFG.redirect_host, CFG.redirect_port), Handler)


mcp = FastMCP("keycloak-mcp")


@mcp.tool()
def login() -> Dict[str, Any]:
    verifier = _pkce_verifier()
    challenge = _pkce_challenge(verifier)
    state = secrets.token_urlsafe(24)

    params = {
        "client_id": CFG.client_id,
        "redirect_uri": CFG.redirect_uri,
        "response_type": "code",
        "scope": CFG.scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    url = f"{CFG.auth_url}?{urlencode(params)}"

    out = _CallbackState()
    server = _run_callback_server(state, out)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    webbrowser.open(url)

    deadline = time.time() + 180
    while time.time() < deadline:
        if out.error:
            server.shutdown()
            return {"ok": False, "error": out.error}
        if out.code:
            break
        time.sleep(0.2)

    server.shutdown()

    if not out.code:
        return {"ok": False, "error": "timeout_waiting_for_callback"}

    tokens = _token_exchange(out.code, verifier)
    _save_tokens(tokens)

    info = whoami()
    return {
        "ok": True,
        "redirect_uri": CFG.redirect_uri,
        "token_saved_to": CFG.token_path,
        "userinfo": info,
    }


@mcp.tool()
def whoami() -> Dict[str, Any]:
    at = _get_valid_access_token()
    headers = {"Authorization": f"Bearer {at}"}
    with httpx.Client(timeout=CFG.timeout_seconds) as client:
        r = client.get(CFG.userinfo_url, headers=headers)
        if r.status_code != 200:
            return {"ok": False, "status": r.status_code, "body": r.text}
        return {"ok": True, "userinfo": r.json()}


@mcp.tool()
def verify_token_signature() -> Dict[str, Any]:
    at = _get_valid_access_token()
    payload = _verify_jwt_signature(at)
    return {"ok": True, "claims": payload}

@mcp.tool()
def validate_bearer(token: str, fetch_userinfo: bool = True) -> Dict[str, Any]:
    """
    Validate a Bearer/JWT token against Keycloak:
      - verifies signature using Keycloak JWKS
      - verifies issuer
      - (does NOT verify aud by default; easy to enable if you want)
      - optionally calls /userinfo using that token
    """
    if not token or not token.strip():
        return {"ok": False, "error": "missing_token"}

    raw = token.strip()
    if raw.lower().startswith("bearer "):
        raw = raw.split(" ", 1)[1].strip()

    try:
        claims = _verify_jwt_signature(raw)  # verifies signature + issuer
    except Exception as e:
        return {"ok": False, "error": "invalid_token", "details": str(e)}

    result: Dict[str, Any] = {
        "ok": True,
        "valid": True,
        "issuer": claims.get("iss"),
        "subject": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "email": claims.get("email"),
        "claims": claims,
    }

    if fetch_userinfo:
        try:
            headers = {"Authorization": f"Bearer {raw}"}
            with httpx.Client(timeout=CFG.timeout_seconds) as client:
                r = client.get(CFG.userinfo_url, headers=headers)
                if r.status_code == 200:
                    result["userinfo"] = r.json()
                else:
                    result["userinfo_error"] = {"status": r.status_code, "body": r.text}
        except Exception as e:
            result["userinfo_error"] = {"error": str(e)}

    return result

# @mcp.tool()
# def validate_authorization_header(
#     authorization: str,
#     fetch_userinfo: bool = True,
# ) -> Dict[str, Any]:
#     """
#     Validate a full HTTP Authorization header against Keycloak.

#     Expected formats:
#       - "Bearer <JWT>"
#       - "bearer <JWT>"

#     Performs:
#       - Header parsing & validation
#       - JWT signature verification via Keycloak JWKS
#       - Issuer verification
#       - Optional /userinfo call
#     """
#     if not authorization or not authorization.strip():
#         return {"ok": False, "error": "missing_authorization_header"}

#     value = authorization.strip()

#     if not value.lower().startswith("bearer "):
#         return {
#             "ok": False,
#             "error": "invalid_authorization_scheme",
#             "expected": "Bearer <token>",
#             "received": value.split(" ", 1)[0],
#         }

#     token = value.split(" ", 1)[1].strip()
#     if not token:
#         return {"ok": False, "error": "missing_bearer_token"}

#     try:
#         claims = _verify_jwt_signature(token)
#     except Exception as e:
#         return {"ok": False, "error": "invalid_token", "details": str(e)}

#     result: Dict[str, Any] = {
#         "ok": True,
#         "valid": True,
#         "issuer": claims.get("iss"),
#         "subject": claims.get("sub"),
#         "preferred_username": claims.get("preferred_username"),
#         "email": claims.get("email"),
#         "azp": claims.get("azp"),            # authorized party (client)
#         "aud": claims.get("aud"),            # audience
#         "claims": claims,
#     }

#     if fetch_userinfo:
#         try:
#             headers = {"Authorization": f"Bearer {token}"}
#             with httpx.Client(timeout=CFG.timeout_seconds) as client:
#                 r = client.get(CFG.userinfo_url, headers=headers)
#                 if r.status_code == 200:
#                     result["userinfo"] = r.json()
#                 else:
#                     result["userinfo_error"] = {
#                         "status": r.status_code,
#                         "body": r.text,
#                     }
#         except Exception as e:
#             result["userinfo_error"] = {"error": str(e)}

#     return result

@mcp.tool()
def logout() -> Dict[str, Any]:
    _delete_tokens()
    return {"ok": True, "cleared": True, "token_path": CFG.token_path}

# -------------------------------
# Fake database
# -------------------------------
FAKE_DATABASE = {
    ("rexel", "prod"): 12450,
    ("rexel", "dev"): 530,
    ("bse", "prod"): 9800,
    ("bse", "sit"): 2100,
}

@mcp.tool()
def get_sku_count(customer: str, environment: str) -> dict:
    """
    Returns number of SKUs for a given customer and environment.
    """

    key = (customer, environment)

    count = FAKE_DATABASE.get(key, 0)

    return {
        "customer": customer,
        "environment": environment,
        "sku_count": count
    }


# -------------------------------
# Tool Implementation
# -------------------------------
@mcp.tool()
def get_customer_and_its_environment() -> dict:
    """
    Returns all customers and their available environments.
    """

    result = {}

    for (customer, environment) in FAKE_DATABASE.keys():

        customer = customer.lower()
        environment = environment.lower()

        if customer not in result:
            result[customer] = []

        if environment not in result[customer]:
            result[customer].append(environment)

    # Optional: sort environments for consistent output
    for customer in result:
        result[customer].sort()

    return result


if __name__ == "__main__":
    mcp.run()

