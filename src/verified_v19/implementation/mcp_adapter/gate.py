#!/usr/bin/env python3
"""Exercise real MCP initialize/list/call over stdio against three owners."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROTOCOL_VERSION = "2025-11-25"
SDK_VERSION = "mcp==1.29.1"
TOOL_NAME = "read_resource"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def model_json(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)
    if hasattr(value, "dict"):
        return value.dict(by_alias=True)
    return value


def call_payload(result: Any) -> dict[str, Any]:
    if getattr(result, "isError", False) or getattr(result, "is_error", False):
        raise AssertionError(f"MCP tool returned protocol error: {model_json(result)}")
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    for block in getattr(result, "content", []):
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
    raise AssertionError(f"MCP result has no JSON object: {model_json(result)}")


def load_case(spec: str) -> dict[str, Any]:
    if "=" not in spec:
        raise ValueError("case must be LABEL=PATH")
    label, raw_path = spec.split("=", 1)
    path = Path(raw_path)
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"{path}: case must be an object")
    envelope = document.get("envelope")
    owner = document.get("private_owner_commitment")
    witness_digest = document.get("private_witness_source_sha256")
    if not isinstance(envelope, dict):
        raise ValueError(f"{path}: missing envelope")
    if not isinstance(owner, str) or not owner:
        raise ValueError(f"{path}: missing private_owner_commitment")
    if (
        not isinstance(witness_digest, str)
        or len(witness_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in witness_digest)
    ):
        raise ValueError(f"{path}: invalid private_witness_source_sha256")
    body = document.get("body_utf8")
    if not isinstance(body, str):
        raise ValueError(f"{path}: missing body_utf8")
    return {
        "label": label,
        "path": str(path),
        "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "owner": owner,
        "witness_digest": witness_digest,
        "body_utf8": body,
        "envelope": envelope,
    }


def tool_arguments(case: dict[str, Any], **changes: Any) -> dict[str, Any]:
    envelope = case["envelope"]
    values = {
        "resource": envelope["resource"],
        "action_onehot": envelope["action_onehot"],
        "nonce": envelope["nonce"],
        "terminal_agent_pk": envelope["terminal_agent_pk"],
        "body_utf8": case["body_utf8"],
        "authorization_json": canonical(envelope).decode("utf-8"),
    }
    values.update(changes)
    return values


def common_request(case: dict[str, Any]) -> dict[str, Any]:
    envelope = case["envelope"]
    fields = (
        "protocol_version",
        "deployment_id",
        "audience",
        "resource",
        "action_onehot",
        "request_time",
        "expires_at",
        "terminal_agent_pk",
        "circuit_id",
        "vk_id",
        "snapshot_digest",
    )
    return {**{field: envelope[field] for field in fields}, "body_utf8": case["body_utf8"]}


def wire_evidence(prefix: Path) -> dict[str, Any]:
    client_path = Path(f"{prefix}.client-to-server.jsonl")
    server_path = Path(f"{prefix}.server-to-client.jsonl")
    client_lines = client_path.read_bytes().splitlines(keepends=True)
    server_lines = server_path.read_bytes().splitlines(keepends=True)
    requests: list[tuple[dict[str, Any], bytes]] = []
    responses: dict[str, tuple[dict[str, Any], bytes]] = {}
    for line in client_lines:
        value = json.loads(line)
        if isinstance(value, dict) and "id" in value and "method" in value:
            requests.append((value, line))
    for line in server_lines:
        value = json.loads(line)
        if isinstance(value, dict) and "id" in value and (
            "result" in value or "error" in value
        ):
            responses[json.dumps(value["id"], sort_keys=True)] = (value, line)
    paired: list[dict[str, Any]] = []
    for request, request_line in requests:
        key = json.dumps(request["id"], sort_keys=True)
        assert key in responses, (request, list(responses))
        response, response_line = responses[key]
        assert "result" in response and "error" not in response, response
        paired.append(
            {
                "id": request["id"],
                "method": request["method"],
                "request_wire_sha256": hashlib.sha256(request_line).hexdigest(),
                "response_wire_sha256": hashlib.sha256(response_line).hexdigest(),
                "request_bytes": len(request_line),
                "response_bytes": len(response_line),
            }
        )
    methods = [item["method"] for item in paired]
    assert methods[0:2] == ["initialize", "tools/list"], methods
    assert methods.count("tools/call") == 8, methods
    return {
        "client_to_server_path": str(client_path),
        "server_to_client_path": str(server_path),
        "client_to_server_sha256": hashlib.sha256(client_path.read_bytes()).hexdigest(),
        "server_to_client_sha256": hashlib.sha256(server_path.read_bytes()).hexdigest(),
        "paired_requests": paired,
    }


async def run(args: argparse.Namespace) -> dict[str, Any]:
    installed_sdk = importlib.metadata.version("mcp")
    assert installed_sdk == "1.29.1", installed_sdk
    lock_sha256 = hashlib.sha256(args.lock_file.read_bytes()).hexdigest()
    cases = [load_case(spec) for spec in args.case]
    assert len(cases) == 3, "exactly three owner cases are required"
    assert len({case["owner"] for case in cases}) == 3, "owners must be distinct"
    assert len({case["witness_digest"] for case in cases}) == 3, "witness sources must be distinct"
    assert len({case["envelope"]["nonce"] for case in cases}) == 3, "positive nonces must be distinct"
    common = common_request(cases[0])
    assert all(common_request(case) == common for case in cases[1:]), (
        "terminal and common public request fields must match"
    )

    environment = dict(os.environ)
    environment["PLAN_A_HTTP_READ_URL"] = args.http_url
    environment["PLAN_A_MCP_WIRE_LOG_PREFIX"] = str(args.wire_log_prefix)
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            str(Path(__file__).with_name("wire_proxy.py")),
            str(Path(__file__).with_name("server.py")),
        ],
        env=environment,
    )
    sequence: list[dict[str, Any]] = []
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            started = time.perf_counter_ns()
            initialized = await session.initialize()
            sequence.append({"method": "initialize", "elapsed_ns": time.perf_counter_ns() - started})
            initialize_json = model_json(initialized)
            negotiated = initialize_json.get("protocolVersion") or initialize_json.get("protocol_version")
            assert negotiated == PROTOCOL_VERSION, initialize_json

            started = time.perf_counter_ns()
            listed = await session.list_tools()
            sequence.append({"method": "tools/list", "elapsed_ns": time.perf_counter_ns() - started})
            tools_json = model_json(listed)
            tools = getattr(listed, "tools", [])
            names = [tool.name for tool in tools]
            assert names == [TOOL_NAME], names
            schema = model_json(tools[0]).get("inputSchema") or model_json(tools[0]).get("input_schema")
            required = set(schema.get("required", []))
            assert required == {
                "resource",
                "action_onehot",
                "nonce",
                "terminal_agent_pk",
                "body_utf8",
                "authorization_json",
            }, schema

            first = cases[0]
            mutations = {
                "resource": tool_arguments(first, resource=first["envelope"]["resource"] + ":mutated"),
                "terminal": tool_arguments(first, terminal_agent_pk="mutated-terminal"),
                "nonce": tool_arguments(first, nonce=first["envelope"]["nonce"] + "A"),
                "body": tool_arguments(first, body_utf8=first["body_utf8"] + "-mutated"),
            }
            negatives: dict[str, Any] = {}
            for name, tool_args in mutations.items():
                started = time.perf_counter_ns()
                result = await session.call_tool(TOOL_NAME, tool_args)
                sequence.append({"method": "tools/call", "case": f"mutated-{name}", "elapsed_ns": time.perf_counter_ns() - started})
                payload = call_payload(result)
                assert payload.get("ok") is False, (name, payload)
                if name != "body":
                    assert payload.get("status") == 400 and payload.get("source") == "adapter", payload
                else:
                    assert payload.get("status") != 200 and payload.get("source") == "http-service", payload
                negatives[name] = payload

            positives: list[dict[str, Any]] = []
            for case in cases:
                started = time.perf_counter_ns()
                result = await session.call_tool(TOOL_NAME, tool_arguments(case))
                elapsed = time.perf_counter_ns() - started
                sequence.append({"method": "tools/call", "case": case["label"], "elapsed_ns": elapsed})
                payload = call_payload(result)
                assert payload.get("ok") is True and payload.get("status") == 200, payload
                positives.append({"label": case["label"], "elapsed_ns": elapsed, "result": payload})

            started = time.perf_counter_ns()
            replay_result = await session.call_tool(TOOL_NAME, tool_arguments(first))
            sequence.append({"method": "tools/call", "case": "nonce-replay", "elapsed_ns": time.perf_counter_ns() - started})
            replay = call_payload(replay_result)
            assert replay.get("ok") is False and replay.get("status") == 409, replay
            assert replay.get("body", {}).get("error") == "nonce-replay", replay

    wire = wire_evidence(args.wire_log_prefix)

    return {
        "schema": "plan-a-synthetic-mcp-legacy-gate-v1",
        "ok": True,
        "profile": {
            "protocol_version": PROTOCOL_VERSION,
            "sdk_pin": SDK_VERSION,
            "installed_sdk_version": installed_sdk,
            "resolved_lock_path": str(args.lock_file),
            "resolved_lock_sha256": lock_sha256,
            "transport": "stdio",
            "http_target": args.http_url,
            "synthetic_authorization_profile": True,
            "production_oauth_compatible": False,
            "mcp_2026_07_28_compatible": False,
            "owner_identity_sent_to_mcp_or_http": False,
        },
        "initialize": initialize_json,
        "tools_list": tools_json,
        "method_sequence": sequence,
        "wire_evidence": wire,
        "common_public_request": common,
        "private_owner_audit": [
            {
                "label": case["label"],
                "private_owner_commitment": case["owner"],
                "private_witness_source_sha256": case["witness_digest"],
                "case_file_sha256": case["file_sha256"],
                "sent_in_protocol": False,
            }
            for case in cases
        ],
        "positive_owner_paths": positives,
        "negative_argument_and_body_binding": negatives,
        "nonce_replay": replay,
        "gates": {
            "initialize": True,
            "tools_list": True,
            "tools_call": True,
            "three_distinct_private_owners": True,
            "same_terminal_and_common_public_request": True,
            "argument_binding": True,
            "body_binding_to_http_proof": True,
            "nonce_replay_rejected": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--http-url", required=True)
    parser.add_argument("--case", action="append", required=True, metavar="LABEL=PATH")
    parser.add_argument("--lock-file", type=Path, required=True)
    parser.add_argument("--wire-log-prefix", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(run(args))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ok": True, "trace": str(args.out), "gates": result["gates"]}))


if __name__ == "__main__":
    main()
