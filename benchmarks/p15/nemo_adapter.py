from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nemoguardrails import Guardrails, RailsConfig
from nemoguardrails.types import ToolCall, ToolCallFunction


CONFIG_DIR = Path("benchmarks/p15/nemo_eval_config")


@dataclass
class NemoDecision:
    is_safe: bool
    blocked: bool
    reason: str | None
    latency_ms: float
    raw_result: Any


class NemoIORailsAdapter:
    def __init__(self) -> None:
        config = RailsConfig.from_path(str(CONFIG_DIR))

        self.guardrails = Guardrails(
            config,
            use_iorails=True,
            require_iorails=True,
        )

        self.manager = self.guardrails.rails_engine.rails_manager

    @staticmethod
    def _tool_call(
        *,
        call_id: str,
        name: str,
        arguments: dict,
    ) -> ToolCall:
        return ToolCall(
            id=call_id,
            function=ToolCallFunction(
                name=name,
                arguments=arguments,
            ),
        )

    async def validate_tool_call_async(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: dict,
        declared_tools: list[dict],
    ) -> NemoDecision:
        tool_call = self._tool_call(
            call_id=call_id,
            name=tool_name,
            arguments=arguments,
        )

        llm_params = {
            "tools": declared_tools,
        }

        t0 = time.perf_counter_ns()

        result = await self.manager.are_tool_calls_safe(
            [tool_call],
            llm_params,
            enabled=True,
            model_type="main",
        )

        latency_ms = (
            time.perf_counter_ns() - t0
        ) / 1_000_000.0

        return NemoDecision(
            is_safe=bool(result.is_safe),
            blocked=not bool(result.is_safe),
            reason=result.reason,
            latency_ms=latency_ms,
            raw_result=result,
        )

    def validate_tool_call(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: dict,
        declared_tools: list[dict],
    ) -> NemoDecision:
        return asyncio.run(
            self.validate_tool_call_async(
                call_id=call_id,
                tool_name=tool_name,
                arguments=arguments,
                declared_tools=declared_tools,
            )
        )

    async def validate_tool_results_async(
        self,
        *,
        messages: list[dict],
    ) -> NemoDecision:
        t0 = time.perf_counter_ns()

        result = await self.manager.are_tool_results_safe(
            messages,
            enabled=True,
            model_type="main",
        )

        latency_ms = (
            time.perf_counter_ns() - t0
        ) / 1_000_000.0

        return NemoDecision(
            is_safe=bool(result.is_safe),
            blocked=not bool(result.is_safe),
            reason=result.reason,
            latency_ms=latency_ms,
            raw_result=result,
        )

    def validate_tool_results(
        self,
        *,
        messages: list[dict],
    ) -> NemoDecision:
        return asyncio.run(
            self.validate_tool_results_async(
                messages=messages,
            )
        )
