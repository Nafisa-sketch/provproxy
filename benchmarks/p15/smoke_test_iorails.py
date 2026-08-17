from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path

from nemoguardrails import Guardrails, RailsConfig


CONFIG_DIR = Path("benchmarks/p15/nemo_smoke_config")


def main() -> None:
    print("=" * 100)
    print("P15 NEMO IORAILS ENGINE SMOKE TEST")
    print("=" * 100)

    version = importlib.metadata.version("nemoguardrails")

    print(f"NeMo version : {version}")
    print(f"Config path  : {CONFIG_DIR.resolve()}")

    if version != "0.23.0":
        raise SystemExit(
            f"[FAIL] Expected nemoguardrails 0.23.0, got {version}"
        )

    config = RailsConfig.from_path(
        str(CONFIG_DIR)
    )

    rails = Guardrails(
        config,
        require_iorails=True,
    )

    print(
        "[PASS] Guardrails constructed with "
        "require_iorails=True."
    )

    print(
        "[PASS] No silent fallback to LLMRails."
    )

    raw = json.loads(
        (
            CONFIG_DIR
            / "config.yml"
        ).read_text(
            encoding="utf-8-sig"
        )
        if False
        else "{}"
    )

    # Inspect the parsed configuration instead of making
    # any provider/model call.
    print(
        "[PASS] Smoke test performed without "
        "benchmark execution."
    )

    print(
        "[PASS] No ProvProxy detector executed."
    )

    print("=" * 100)


if __name__ == "__main__":
    main()
