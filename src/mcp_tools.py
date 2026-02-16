# mcp_tools.py
from typing import Any, Dict, List, Tuple

from fastmcp import FastMCP, Context

mcp = FastMCP("keycloak-mcp")

FAKE_DATABASE: Dict[Tuple[str, str], int] = {
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
    result: Dict[str, List[str]] = {}
    for cust, env in FAKE_DATABASE.keys():
        result.setdefault(cust, [])
        if env not in result[cust]:
            result[cust].append(env)
    for cust in result:
        result[cust].sort()
    return result


@mcp.tool()
def whoami(ctx: Context) -> Dict[str, Any]:
    """
    Return JWT claims of the currently authenticated user.
    Requires valid Bearer token.
    """
    request = ctx.request_context.request

    claims = getattr(request.state, "jwt_claims", None)
    if not claims:
        return {
            "ok": False,
            "error": "no_authenticated_user",
        }

    return {
        "ok": True,
        "sub": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "email": claims.get("email"),
        "azp": claims.get("azp"),
        "aud": claims.get("aud"),
        "claims": claims,  # full raw claims (remove if too verbose)
    }


# Starlette sub-app for MCP
mcp_app = mcp.http_app(path="/")
