"""Minimal JSON-RPC 2.0 frame model for the MCP stdin/stdout data plane.

Scoped to what ProvProxy needs: classify `tools/call` requests for
inspection, pass everything else through untouched — that's what the
roadmap's "100% pass-through for lifecycle messages" target depends on.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional, Union


@dataclass
class JsonRpcRequest:
    jsonrpc: str
    method: str
    id: Any = None
    params: Optional[dict] = None

    def tool_call_params(self) -> Optional[dict]:
        if self.params is None:
            return None
        name = self.params.get("name")
        if name is None:
            return None
        return {"name": name, "arguments": self.params.get("arguments", {})}


@dataclass
class JsonRpcError:
    code: int
    message: str
    data: Any = None


@dataclass
class JsonRpcResponse:
    jsonrpc: str
    id: Any = None
    result: Any = None
    error: Optional[JsonRpcError] = None

    def to_json(self) -> str:
        payload: dict = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            payload["error"] = {
                "code": self.error.code,
                "message": self.error.message,
                **({"data": self.error.data} if self.error.data is not None else {}),
            }
        else:
            payload["result"] = self.result
        return json.dumps(payload)


@dataclass
class ToolCallFrame:
    request: JsonRpcRequest


@dataclass
class PassThroughFrame:
    raw_value: Any


Frame = Union[ToolCallFrame, PassThroughFrame]


def classify(raw_line: str) -> Frame:
    """Classify a raw line. Anything that isn't a `tools/call` request
    passes through untouched.

    Raises json.JSONDecodeError if the line isn't valid JSON at all — the
    caller (relay) treats that the same as a pass-through, per the
    non-tool-frame transparency goal.
    """
    value = json.loads(raw_line)
    is_tool_call = isinstance(value, dict) and value.get("method") == "tools/call"

    if is_tool_call:
        req = JsonRpcRequest(
            jsonrpc=value.get("jsonrpc", "2.0"),
            method=value["method"],
            id=value.get("id"),
            params=value.get("params"),
        )
        return ToolCallFrame(request=req)
    return PassThroughFrame(raw_value=value)


def error_response(request_id: Any, code: int, message: str) -> JsonRpcResponse:
    return JsonRpcResponse(
        jsonrpc="2.0",
        id=request_id,
        error=JsonRpcError(code=code, message=message),
    )
