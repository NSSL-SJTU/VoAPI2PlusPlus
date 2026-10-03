"""Harvest candidate render URLs from API response bodies.

A stored-XSS walker can only confirm a payload if it loads the page where that payload
renders. Rather than hardcode each app's render/preview scheme, treat every URL the app
itself returns as a candidate render page: absolute http(s) URLs appearing anywhere in a
response (covers plain-string URL responses such as Halo's post-preview endpoint, which
returns ``/archives/{slug}?token=...``) and site paths held in URL-shaped fields
(``fullPath``/``permalink``/``link``/``url``). Feeding these into the walker's frontier
lets it reach app-generated pages -- e.g. a token-gated draft preview -- with no
app-specific knowledge.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Absolute URLs, stopping at whitespace, quotes, angle brackets or wrapping brackets so a
# URL embedded in JSON or prose is captured without its delimiters.
_ABS_URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]]+")

# Field-name substrings that mark a value as a site path worth visiting.
_PATH_FIELD_HINTS = ("fullpath", "permalink", "link", "url", "href")


def harvest_urls(body_text: str, base_url: str) -> set[str]:
    """Return candidate render URLs found in one response body."""
    urls: set[str] = set()
    if not body_text:
        return urls

    for match in _ABS_URL_RE.findall(body_text):
        urls.add(match.rstrip(".,;"))

    try:
        data = json.loads(body_text)
    except (ValueError, TypeError):
        data = None
    if data is not None:
        _collect_path_fields(data, base_url.rstrip("/"), urls)
    return urls


def _collect_path_fields(node: Any, base: str, urls: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if (
                isinstance(value, str)
                and value.startswith("/")
                and not value.startswith("//")
                and any(hint in key.lower() for hint in _PATH_FIELD_HINTS)
            ):
                urls.add(base + value)
            _collect_path_fields(value, base, urls)
    elif isinstance(node, list):
        for item in node:
            _collect_path_fields(item, base, urls)
