"""ProvProxy CLI entry point.

Usage:
    python -m provproxy --policy policies/default_policy.json \\
                           --server-id filesystem-local \\
                           -- npx -y @modelcontextprotocol/server-filesystem /home/user/project
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from pathlib import Path

from .config import PolicyFile
from .relay import Relay, RelayConfig


def main() -> None:
    logging.basicConfig(
        stream=sys.stderr,  # telemetry plane: stderr only, never stdout
        level=logging.INFO,
        format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "msg": "%(message)s"}',
    )

    args, target_command = _parse_args(sys.argv[1:])

    policy = PolicyFile.load(Path(args.policy))

    if policy.persistence.enabled and not args.session_id:
        raise SystemExit(
            "Persistence is enabled, so --session-id is required. "
            "Use a stable deployment/session identifier across restarts."
        )
    session_id = args.session_id or str(uuid.uuid4())

    relay = Relay(
        RelayConfig(
            target_command=target_command,
            server_id=args.server_id,
            session_id=session_id,
            approval_broker_port=args.approval_port,
        ),
        policy,
    )

    asyncio.run(relay.run())


def _parse_args(argv: list[str]):
    if "--" in argv:
        split_at = argv.index("--")
        own_args, target_command = argv[:split_at], argv[split_at + 1 :]
    else:
        own_args, target_command = argv, []

    parser = argparse.ArgumentParser(prog="provproxy")
    parser.add_argument("--policy", required=True, help="Path to policy JSON file")
    parser.add_argument("--server-id", required=True, help="server_id for the V0 baseline binding")
    parser.add_argument(
        "--session-id", default=None,
        help=("Stable logical session/deployment ID. Required when "
              "persistence.enabled=true so state can be recovered after restart."),
    )
    parser.add_argument(
        "--approval-port", type=int, default=8765,
        help="Local port for the approval broker (companion CLI connects here)",
    )
    args = parser.parse_args(own_args)

    if not target_command:
        parser.error("target MCP server command is required after `--`")

    return args, target_command


if __name__ == "__main__":
    main()
