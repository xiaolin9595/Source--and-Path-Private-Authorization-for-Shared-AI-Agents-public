#!/usr/bin/env python3
"""Legacy MCP stdio adapter for the existing Plan A HTTP read endpoint.

This synthetic experiment profile intentionally fixes MCP 2025-11-25 because
the gate requires the legacy initialize handshake. It is not a production
OAuth or MCP 2026-07-28 integration.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from mcp.server.fastmcp import FastMCP

MCP_PROTOCOL_VERSION = "2025-11-25"
SDK_VERSION = "mcp==1.29.1"
HTTP_URL = os.environ.get("PLAN_A_HTTP_READ_URL", "http://127.0.0.1:8787/resource/read")

mcp = FastMCP("plan-a-synthetic-read-adapter", json_response=True)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def failure(error: str, *, status: int = 0, source: str = "adapter") -> dict[str, Any]:
    return {"ok": False, "status": status, "error": error, "source": source}


def parse_authorization(value: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, item in items:
            if key in out:
                raise ValueError("duplicate-authorization-key")
            out[key] = item
        return out

    parsed = json.loads(value, object_pairs_hook=pairs)
    if not isinstance(parsed, dict):
        raise ValueError("authorization-must-be-object")
    return parsed


def post_http(authorization: dict[str, Any], body: bytes) -> dict[str, Any]:
    request = urllib.request.Request(
        HTTP_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-PlanA-Authorization": canonical(authorization).decode("utf-8"),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            status = response.status
            raw = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read()
    except urllib.error.URLError as error:
        return failure(f"http-unavailable:{error.reason}", status=502, source="transport")
    try:
        payload = json.loads(raw)
    except Exception:
        return failure("non-json-http-response", status=status, source="http-service")
    if not isinstance(payload, dict):
        return failure("non-object-http-response", status=status, source="http-service")
    return {
        "ok": status == 200 and payload.get("ok") is True,
        "status": status,
        "source": "http-service",
        "body": payload,
    }


@mcp.tool()
def read_resource(
    resource: str,
    action_onehot: int,
    nonce: str,
    terminal_agent_pk: str,
    body_utf8: str,
    authorization_json: str,
) -> dict[str, Any]:
    """Invoke the existing private-authorization HTTP read endpoint.

    Public MCP arguments are checked against the signed/proven envelope before
    the exact UTF-8 body and canonical authorization bytes are forwarded. The
    HTTP service independently binds the body hash, request, terminal, header,
    proof and nonce, then consumes the nonce in its commit transaction.
    """
    try:
        authorization = parse_authorization(authorization_json)
    except Exception as error:
        return failure(f"bad-authorization-json:{error}")
    for field, supplied in (
        ("resource", resource),
        ("action_onehot", action_onehot),
        ("nonce", nonce),
        ("terminal_agent_pk", terminal_agent_pk),
    ):
        if authorization.get(field) != supplied:
            return failure(f"tool-argument-mismatch:{field}", status=400)
    if not isinstance(body_utf8, str):
        return failure("body-must-be-utf8-string", status=400)
    return post_http(authorization, body_utf8.encode("utf-8"))


if __name__ == "__main__":
    mcp.run(transport="stdio")
