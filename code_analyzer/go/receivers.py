#!/usr/bin/env python3
"""Reject registration calls whose receiver is demonstrably not a router.

``Get`` and ``Put`` are HTTP verbs in chi and Gitea, but they are also how Go
code reads a JWT claim (``token.Get("uid", &uid)``) or writes a key-value store
(``ds.Property(ctx).Put(key, value)``). Those calls look exactly like a route
registration, and on Navidrome they invented 19 endpoints.

Two rules keep them out. The receiver must resolve to a plain identifier, and
that identifier must not be *shown* to hold something else -- by its declared
type, or by the constructor it came from. The test stays negative on purpose:
demanding positive proof drops real routes, because a router can arrive as a
package-level variable the function never mentions.

Resolution is scope-aware, which matters more than it sounds: Navidrome writes
``r.Post("/", func(w http.ResponseWriter, r *http.Request){...})``, shadowing a
``chi.Router`` named ``r`` with a request of the same name. Collecting names per
function instead of per scope disqualified 12 real playlist endpoints.
"""

from __future__ import annotations

from tree_sitter import Node

from code_analyzer.go.parser import node_text


# Type names that identify a router value, after dropping package and pointer.
_ROUTER_TYPES = frozenset(
    {"Router", "Route", "RouterGroup", "Mux", "ServeMux", "Engine", "Group"}
)

# Packages whose bare New()/Default() hands back a router.
_ROUTER_PACKAGES = frozenset(
    {"chi", "gin", "httprouter", "mux", "web", "echo", "fiber", "macaron"}
)

_SCOPE_TYPES = ("func_literal", "function_declaration", "method_declaration")


def receiver_could_be_router(call: Node, name: str) -> bool:
    """Whether ``name``, as resolved at ``call``, may hold a router."""
    node = call.parent
    while node is not None:
        if node.type in _SCOPE_TYPES:
            verdict = _parameter_verdict(node, name)
            if verdict is not None:
                return verdict
        if node.type == "block":
            verdict = _block_verdict(node, name, call.start_byte)
            if verdict is not None:
                return verdict
        node = node.parent
    return True


def _parameter_verdict(scope: Node, name: str) -> bool | None:
    for field in ("parameters", "receiver"):
        section = scope.child_by_field_name(field)
        if section is None:
            continue
        for declaration in section.named_children:
            if declaration.type != "parameter_declaration":
                continue
            names = [node_text(n) for n in declaration.children_by_field_name("name")]
            if name not in names:
                continue
            type_node = declaration.child_by_field_name("type")
            if type_node is None:
                return True
            return is_router_type(node_text(type_node))
    return None


def _block_verdict(block: Node, name: str, before: int) -> bool | None:
    """Look for a declaration of ``name`` in this block, ahead of the call."""
    for statement in block.named_children:
        if statement.start_byte >= before:
            break
        for declaration in _declarations(statement):
            verdict = _declaration_verdict(declaration, name)
            if verdict is not None:
                return verdict
    return None


def _declarations(statement: Node) -> list[Node]:
    if statement.type in ("short_var_declaration", "var_spec"):
        return [statement]
    if statement.type in ("var_declaration", "const_declaration"):
        return list(statement.named_children)
    return []


def _declaration_verdict(declaration: Node, name: str) -> bool | None:
    if declaration.type == "var_spec":
        names = [node_text(n) for n in declaration.children_by_field_name("name")]
        if name not in names:
            return None
        type_node = declaration.child_by_field_name("type")
        if type_node is not None:
            return is_router_type(node_text(type_node))
        value = declaration.child_by_field_name("value")
        return _value_verdict(value, declaration, name)
    if declaration.type == "short_var_declaration":
        left = declaration.child_by_field_name("left")
        right = declaration.child_by_field_name("right")
        if left is None or right is None:
            return None
        names = [node_text(n) for n in left.named_children]
        if name not in names:
            return None
        values = list(right.named_children) if right.type == "expression_list" else [right]
        index = names.index(name)
        value = values[index] if index < len(values) else None
        return _value_verdict(value, declaration, name)
    return None


def _value_verdict(value: Node | None, declaration: Node, name: str) -> bool | None:
    if value is None:
        return None
    if value.type == "call_expression":
        return _builds_router(value)
    return None


def _builds_router(call: Node) -> bool:
    """Whether a constructor call plausibly returns a router."""
    function = call.child_by_field_name("function")
    if function is None:
        return True
    text = node_text(function)
    name = text.split(".")[-1]
    # chi's With() returns a router carrying extra middleware, so registration
    # calls made on its result are still real endpoints.
    if name == "With":
        return True
    if any(word in name for word in ("Router", "Route", "Mux", "Engine", "Group")):
        return True
    qualifier = text.split(".")[-2] if "." in text else ""
    return qualifier in _ROUTER_PACKAGES


def is_router_type(type_text: str) -> bool:
    base = type_text.strip().lstrip("*").split("[")[0].split(".")[-1]
    return base in _ROUTER_TYPES
