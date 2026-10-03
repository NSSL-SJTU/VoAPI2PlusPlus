#!/usr/bin/env python3
"""Parameter structs declared at the registration site.

Both Gitea and Cloudreve name the struct a route binds right where the route is
registered -- ``bind(api.MarkdownOption{})`` and
``controllers.FromJSON[adminsvc.SlavePingService](ctx{})`` -- which is a more
reliable signal than tracing the decode call inside the handler. Cloudreve uses
it for 110 of its 197 routes.
"""

from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Node

from code_analyzer.go.parser import node_text


# Middleware whose name says where the bound struct's fields travel.
_QUERY_BINDERS = ("FromQuery", "FromURI", "FromForm")
_BODY_BINDERS = ("FromJSON", "FromBody", "bind", "Bind")


@dataclass(frozen=True)
class RegistrationBinding:
    location: str  # "body" or "query"
    type_name: str
    qualifier: str = ""


def find_registration_binding(
    args: list[Node], skip_first: bool = True
) -> RegistrationBinding | None:
    """Inspect a registration's middleware arguments for a bound struct.

    ``skip_first`` skips the path argument. A verb chained off ``Combo`` carries
    no path, so there every argument is middleware or the handler.
    """
    for arg in (args[1:] if skip_first else args):
        binding = _from_generic_call(arg) or _from_bind_call(arg)
        if binding is not None:
            return binding
    return None


def _from_generic_call(arg: Node) -> RegistrationBinding | None:
    """``controllers.FromJSON[pkg.Service](ctx{})``.

    The grammar reads this as a type conversion over a generic type, because
    ``T(x)`` and ``f[T](x)`` are spelled the same way.
    """
    if arg.type != "type_conversion_expression":
        return None
    generic = arg.named_children[0] if arg.named_children else None
    if generic is None or generic.type != "generic_type":
        return None
    base = generic.child_by_field_name("type")
    arguments = generic.child_by_field_name("type_arguments")
    if base is None or arguments is None or not arguments.named_children:
        return None
    location = _binder_location(_last_segment(node_text(base)))
    if location is None:
        return None
    qualifier, name = _split_qualified(node_text(arguments.named_children[0]))
    return RegistrationBinding(location, name, qualifier)


def _from_bind_call(arg: Node) -> RegistrationBinding | None:
    """``bind(api.MarkdownOption{})``."""
    if arg.type != "call_expression":
        return None
    function = arg.child_by_field_name("function")
    if function is None:
        return None
    location = _binder_location(_last_segment(node_text(function)))
    if location is None:
        return None
    arguments = arg.child_by_field_name("arguments")
    if arguments is None:
        return None
    for value in arguments.named_children:
        if value.type != "composite_literal":
            continue
        type_node = value.child_by_field_name("type")
        if type_node is not None:
            qualifier, name = _split_qualified(node_text(type_node))
            return RegistrationBinding(location, name, qualifier)
    return None


def _binder_location(name: str) -> str | None:
    if name in _QUERY_BINDERS:
        return "query"
    if name in _BODY_BINDERS:
        return "body"
    return None


def _last_segment(text: str) -> str:
    return text.strip().lstrip("*").split(".")[-1]


def _split_qualified(text: str) -> tuple[str, str]:
    """('api', 'MarkdownOption') for ``api.MarkdownOption``."""
    cleaned = text.strip().lstrip("*")
    if "." in cleaned:
        qualifier, _, name = cleaned.rpartition(".")
        return qualifier.split(".")[-1], name
    return "", cleaned
