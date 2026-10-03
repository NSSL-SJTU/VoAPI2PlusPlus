#!/usr/bin/env python3
"""
Small Spring MVC annotation parsing helpers shared by API extraction and
endpoint code indexing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")


@dataclass(frozen=True)
class SpringMapping:
    method: str
    path: str


def annotation_name(annotation_text: str) -> str:
    match = re.match(r"\s*@\s*([\w.]+)", annotation_text or "")
    if not match:
        return ""
    return match.group(1).split(".")[-1]


def is_mapping_annotation(annotation_text: str) -> bool:
    return annotation_name(annotation_text) in {
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
        "RequestMapping",
    }


def mapping_values(
    annotation_text: str, default_methods: list[str] | None = None
) -> list[SpringMapping]:
    name = annotation_name(annotation_text)
    if name == "GetMapping":
        methods = ["GET"]
    elif name == "PostMapping":
        methods = ["POST"]
    elif name == "PutMapping":
        methods = ["PUT"]
    elif name == "DeleteMapping":
        methods = ["DELETE"]
    elif name == "PatchMapping":
        methods = ["PATCH"]
    elif name == "RequestMapping":
        methods = request_methods(annotation_text, default_methods)
    else:
        return []

    paths = string_values(annotation_text, ("value", "path"))
    if not paths:
        paths = [""]
    return [SpringMapping(method, path) for method in methods for path in paths]


def request_methods(
    annotation_text: str, default: list[str] | None = None
) -> list[str]:
    expr = value_expression(annotation_text, "method")
    if not expr:
        # Spring accepts every method when unspecified. Probing all of them would
        # multiply endpoints, so callers that can read the handler signature pass
        # the method it actually expects; GET stays the fallback.
        return list(default) if default else ["GET"]
    found: list[str] = []
    for method in HTTP_METHODS:
        if re.search(rf"\b{method}\b", expr):
            found.append(method)
    return found or ["GET"]


def default_methods_for_handler(handler_text: str) -> list[str]:
    """Pick the method a method-less @RequestMapping should be probed with.

    A handler declaring @RequestBody expects a request that carries one, so GET
    would both misroute it and send the payload as query parameters.
    """
    return ["POST"] if "@RequestBody" in handler_text else ["GET"]


def string_values(annotation_text: str, keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        for expr in value_expressions(annotation_text, key):
            values.extend(_string_literals(expr))
    if values:
        return _dedupe(values)

    args = _annotation_args(annotation_text)
    if not args:
        return []
    stripped = args.lstrip()
    if not stripped or re.match(r"[A-Za-z_][\w$]*\s*=", stripped):
        return []
    expr = _scan_expression(stripped, 0)
    return _dedupe(_string_literals(expr))


def bool_value(annotation_text: str, key: str) -> bool | None:
    expr = value_expression(annotation_text, key)
    if not expr:
        return None
    lowered = expr.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def value_expression(annotation_text: str, key: str) -> str:
    expressions = value_expressions(annotation_text, key)
    return expressions[0] if expressions else ""


def value_expressions(annotation_text: str, key: str) -> list[str]:
    args = _annotation_args(annotation_text)
    if not args:
        return []

    out: list[str] = []
    for match in re.finditer(rf"\b{re.escape(key)}\s*=", args):
        start = match.end()
        out.append(_scan_expression(args, start).strip())
    return out


def _annotation_args(annotation_text: str) -> str:
    start = annotation_text.find("(")
    if start == -1:
        return ""
    return annotation_text[start + 1 : _matching_paren(annotation_text, start)]


def _matching_paren(text: str, start: int) -> int:
    quote = ""
    escape = False
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return len(text)


def _scan_expression(text: str, start: int) -> str:
    idx = start
    while idx < len(text) and text[idx].isspace():
        idx += 1
    begin = idx
    quote = ""
    escape = False
    depth = 0
    while idx < len(text):
        ch = text[idx]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            idx += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "{[(":
            depth += 1
        elif ch in "}])":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        idx += 1
    return text[begin:idx]


def _string_literals(expr: str) -> list[str]:
    out: list[str] = []
    for match in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', expr or ""):
        text = match.group(0)
        out.append(_unquote_java_string(text))
    return out


def _unquote_java_string(text: str) -> str:
    if len(text) < 2:
        return text
    body = text[1:-1]
    return (
        body.replace(r"\"", '"')
        .replace(r"\'", "'")
        .replace(r"\\", "\\")
        .replace(r"\/", "/")
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
