from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class BaselineResult:
    matched: bool
    matched_fragment: Optional[str] = None


class RuntimeSnippetBaseline:
    """
    P14 independent runtime snippet-provenance baseline.

    Design:
      - source text is registered at runtime;
      - outbound payload text is inspected independently per call;
      - direct source substrings are treated as provenance evidence.

    Deliberately NOT implemented:
      - transformation decoding;
      - approximate/N-gram reconstruction;
      - cross-call accumulation;
      - cross-destination fan-out accumulation;
      - ProvProxy imports.

    This baseline therefore represents a simpler runtime provenance
    mechanism against which the incremental mechanisms in ProvProxy
    can be measured.
    """

    def __init__(self, min_fragment_chars: int = 8):
        if min_fragment_chars < 1:
            raise ValueError("min_fragment_chars must be >= 1")

        self.min_fragment_chars = min_fragment_chars
        self._source_id: Optional[str] = None
        self._source_text: Optional[str] = None

    def register_source(self, source_id: str, source_text: str) -> None:
        if not source_id:
            raise ValueError("source_id must not be empty")

        if not source_text:
            raise ValueError("source_text must not be empty")

        self._source_id = source_id
        self._source_text = source_text

    def scan(self, payload_text: str) -> BaselineResult:
        if self._source_text is None:
            return BaselineResult(matched=False)

        if not payload_text:
            return BaselineResult(matched=False)

        source = self._source_text

        # Full-source direct reproduction.
        if source in payload_text:
            return BaselineResult(
                matched=True,
                matched_fragment=source,
            )

        # Independent direct-snippet provenance.
        #
        # Search longest snippets first. This is intentionally lexical:
        # encoded, semantically transformed, and separately accumulated
        # fragments receive no special treatment.
        max_len = len(source)

        for size in range(max_len - 1, self.min_fragment_chars - 1, -1):
            for start in range(0, max_len - size + 1):
                fragment = source[start:start + size]

                if fragment in payload_text:
                    return BaselineResult(
                        matched=True,
                        matched_fragment=fragment,
                    )

        return BaselineResult(matched=False)
