"""Minimal HuJSON (JWCC) reader.

Headscale stores its policy in the same huJSON format as Tailscale: JSON with
comments and trailing commas (https://github.com/tailscale/hujson). Rather than
add a dependency, this module strips comments and trailing commas outside of
string literals and hands the result to :mod:`json`.
"""

from __future__ import annotations

import json
from typing import Any


class HuJSONError(ValueError):
    """Raised when the document cannot be turned into valid JSON."""


def strip(text: str) -> str:
    """Return ``text`` with comments and trailing commas removed."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            # Copy the string literal verbatim, honouring escapes.
            start = i
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            else:
                raise HuJSONError("unterminated string literal")
            out.append(text[start:i])
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                raise HuJSONError("unterminated block comment")
            # Keep newlines so that json error line numbers stay usable.
            out.append("\n" * text.count("\n", i, end))
            i = end + 2
            continue
        if ch == ",":
            j = i + 1
            while j < n and (text[j].isspace() or _starts_comment(text, j)):
                if _starts_comment(text, j):
                    j = _skip_comment(text, j)
                else:
                    j += 1
            if j < n and text[j] in "]}":
                # Trailing comma: drop it, keep the whitespace for line numbers.
                out.append("\n" * text.count("\n", i, j))
                i = j
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _starts_comment(text: str, i: int) -> bool:
    return text[i] == "/" and i + 1 < len(text) and text[i + 1] in "/*"


def _skip_comment(text: str, i: int) -> int:
    if text[i + 1] == "/":
        end = text.find("\n", i)
        return len(text) if end == -1 else end
    end = text.find("*/", i + 2)
    if end == -1:
        raise HuJSONError("unterminated block comment")
    return end + 2


def loads(text: str) -> Any:
    """Parse a huJSON document."""
    cleaned = strip(text)
    if not cleaned.strip():
        raise HuJSONError("empty document")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:  # pragma: no cover - message passthrough
        raise HuJSONError(f"invalid huJSON: {exc}") from exc
