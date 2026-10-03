#!/usr/bin/env python3
"""
Utilities for mapping Java type strings to internal ParamType and providing
examples/defaults suitable for APIModel generation.
"""

from __future__ import annotations

import re
from typing import Tuple, List

from models.types import ParamType


BASIC_TYPES = {
    "String","Integer","int","Long","long","Double","double",
    "Float","float","Boolean","boolean","Date","LocalDateTime","LocalDate",
    "BigDecimal","BigInteger"
}


def map_java_type(
    java_type: str, name_hint: str = ""
) -> Tuple[ParamType, List[object], List[object]]:
    """
    Map a Java type string (possibly generic) to ParamType and provide
    (examples, defaults) lists. Keep examples non-empty for constrained types.

    name_hint: parameter/field name to refine examples (e.g., sort/order)
    """
    t = _normalize_java_type(java_type)
    n = (name_hint or "").lower()

    # Basic heuristics
    if t in {"byte", "Byte"}:
        # Byte is constrained: 0..255 (signed/unsigned confusion across stacks), use 0 example
        return ParamType.INTEGER, [0, 1, 2, 3], []
    if t in {"short", "Short"}:
        return ParamType.INTEGER, [], []
    if t in {"int", "Integer"}:
        # common id/count conventions
        if "id" in n:
            return ParamType.INTEGER, [1], []
        if any(k in n for k in ["count", "num", "size", "page", "limit", "offset", "index"]):
            return ParamType.INTEGER, [10], []
        return ParamType.INTEGER, [], []
    if t in {"long", "Long"}:
        if "id" in n:
            return ParamType.INTEGER, [1], []
        return ParamType.INTEGER, [], []
    if t == "BigInteger":
        return ParamType.INTEGER, [1] if "id" in n else [], []
    if t == "BigDecimal":
        return ParamType.NUMBER, [9.99] if any(k in n for k in ["price", "amount", "score", "rate"]) else [0.0], []
    if t in {"float", "Float", "double", "Double"}:
        if any(k in n for k in ["price", "amount", "score", "rate"]):
            return ParamType.NUMBER, [9.99], []
        return ParamType.NUMBER, [0.0], []
    if t in {"boolean", "Boolean"}:
        return ParamType.BOOLEAN, [False], []
    if t == "String":
        if "sort" in n:
            return ParamType.STRING, ["id"], []
        if "order" in n:
            return ParamType.STRING, ["ASC", "DESC"], []
        if "email" in n:
            return ParamType.STRING, ["user@example.com"], []
        if "url" in n:
            return ParamType.STRING, ["http://example.com"], []
        return ParamType.STRING, ["VoAPITestString"], []

    # Collections and objects
    if t.endswith("[]"):
        return ParamType.ARRAY, [], []
    if _raw_type(t) in {"List", "Set", "Collection", "Iterable"}:
        return ParamType.ARRAY, [], []
    if _raw_type(t) in {"Map", "HashMap"}:
        return ParamType.OBJECT, [], []

    # Temporal types
    if t in {"LocalDateTime", "DateTime"}:
        return ParamType.DATETIME, ["2024-01-01T00:00:00Z"], []
    if t in {"LocalDate", "Date"}:
        return ParamType.DATE, ["2024-01-01"], []
    
    if t in {"MultipartFile"}:
        return ParamType.FILE, [], []

    # Fallback
    return ParamType.STRING, ["VoAPITestString"], []


def _normalize_java_type(java_type: str) -> str:
    text = (java_type or "").strip()
    if not text:
        return text
    text = re.sub(r"\s+", "", text)
    if "<" not in text:
        return text.split(".")[-1]
    raw, generic = text.split("<", 1)
    return f"{raw.split('.')[-1]}<{generic}"


def _raw_type(java_type: str) -> str:
    return java_type.split("<", 1)[0].split(".")[-1]
