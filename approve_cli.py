#!/usr/bin/env python3
"""Companion CLI for ProvProxy's approval broker.

WHAT THIS IS: a small, SEPARATE program from `python -m provproxy`. Run
this in its own terminal window, alongside the relay. It connects to the
relay's approval socket and shows you pending tool calls that need a
yes/no decision, so you can type "approve <id>" or "deny <id>".

Usage:
    python approve_cli.py [--host 127.0.0.1] [--port 8765]
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading


def _listen(sock: socket.socket) -> None:
    """Runs in a background thread: continuously reads whatever the relay
    sends us (PENDING/RESOLVED lines) and prints them, so incoming
    messages don't block us from also reading what the human types."""
    buf = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return
        if not chunk:
            print("\n[connection to ProvProxy closed]")
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            _print_line(line.decode("utf-8", errors="replace"))


def _print_line(line: str) -> None:
    if line.startswith("PENDING"):
        parts = line.split(" ", 2)
        req_id = parts[1] if len(parts) > 1 else "?"
        desc = parts[2] if len(parts) > 2 else ""
        print(f"\n[#{req_id}] APPROVAL NEEDED: {desc}")
        print(f"  -> type: approve {req_id}   or   deny {req_id}")
    elif line.startswith("RESOLVED"):
        print(f"\n[{line}]")
    else:
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    try:
        sock = socket.create_connection((args.host, args.port), timeout=5)
    except OSError as e:
        print(f"Could not connect to ProvProxy at {args.host}:{args.port} — is the relay running? ({e})")
        sys.exit(1)

    print(f"Connected to ProvProxy approval broker at {args.host}:{args.port}")
    print("Waiting for pending approvals... (Ctrl+C to quit)\n")

    listener = threading.Thread(target=_listen, args=(sock,), daemon=True)
    listener.start()

    try:
        while True:
            line = input()
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) == 2 and parts[0].lower() in ("approve", "deny"):
                sock.sendall(f"{parts[0].upper()} {parts[1]}\n".encode("utf-8"))
            else:
                print("Type: approve <id>   or   deny <id>")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
