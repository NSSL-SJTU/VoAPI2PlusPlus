#!/usr/bin/env python3
"""Recover request parameters from a Go handler body.

Go has no parameter annotations: a handler reads what it needs by calling into
the request. So the parameter names live in call arguments -- ``values.Get("q")``
-- and recovering them means recognising which receiver a ``Get`` is called on.
A read that travels through a helper -- request-baskets resolves ``max`` and
``skip`` inside ``getPage(values)`` -- is followed one level, which is where
that idiom lives. Anything deeper is left to LLM recovery at runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from code_analyzer.go.parser import iter_nodes, node_text, string_literal_value
from models.types import ParamType


# Accessors a handler calls to read one named value off the request. The name is
# the literal first argument; the method name says where it comes from and, for
# the typed variants, what it is. gin spells it c.Query, Gitea ctx.Query and
# ctx.QueryInt, net/http r.FormValue.
# Methods on a parameter container -- url.Values, or a project's own wrapper
# such as Navidrome's req.Params(r) -- that read one named value. The name is
# again the first argument, and the method name carries the type.
CONTAINER_ACCESSORS: dict[str, ParamType] = {
    "Get": ParamType.STRING,
    "String": ParamType.STRING,
    "StringPtr": ParamType.STRING,
    "StringOr": ParamType.STRING,
    "Strings": ParamType.STRING,
    "Times": ParamType.STRING,
    "TimeOr": ParamType.STRING,
    "Int": ParamType.INTEGER,
    "IntOr": ParamType.INTEGER,
    "Ints": ParamType.INTEGER,
    "Int64": ParamType.INTEGER,
    "Int64Or": ParamType.INTEGER,
    "Bool": ParamType.BOOLEAN,
    "BoolPtr": ParamType.BOOLEAN,
    "BoolOr": ParamType.BOOLEAN,
    "Float64Or": ParamType.NUMBER,
}

_ACCESSORS: dict[str, tuple[str, ParamType]] = {
    "Query": ("query", ParamType.STRING),
    "QueryTrim": ("query", ParamType.STRING),
    "QueryStrings": ("query", ParamType.STRING),
    "QueryInt": ("query", ParamType.INTEGER),
    "QueryInt64": ("query", ParamType.INTEGER),
    "QueryBool": ("query", ParamType.BOOLEAN),
    "DefaultQuery": ("query", ParamType.STRING),
    "PostForm": ("query", ParamType.STRING),
    "DefaultPostForm": ("query", ParamType.STRING),
    "FormValue": ("query", ParamType.STRING),
    "PostFormValue": ("query", ParamType.STRING),
    "FormString": ("query", ParamType.STRING),
    "FormTrim": ("query", ParamType.STRING),
    "FormInt": ("query", ParamType.INTEGER),
    "FormInt64": ("query", ParamType.INTEGER),
    "FormBool": ("query", ParamType.BOOLEAN),
    "GetHeader": ("header", ParamType.STRING),
    "Param": ("path", ParamType.STRING),
}


# Navidrome wraps the request in req.Params(r) before reading anything off it.
_PARAMS_CALL_RE = re.compile(r"(^|\.)Params\([^)]*\)$")


@dataclass
class HandlerParams:
    query: dict[str, ParamType] = field(default_factory=dict)
    header: dict[str, ParamType] = field(default_factory=dict)
    path: dict[str, ParamType] = field(default_factory=dict)

    def add(self, location: str, name: str, param_type: ParamType) -> None:
        getattr(self, location).setdefault(name, param_type)


def extract_handler_params(
    func_node: Node,
    functions: dict[str, Node] | None = None,
) -> HandlerParams:
    params = HandlerParams()
    containers = _query_containers(func_node)
    _collect(func_node, containers, params)
    for helper, forwarded in _helper_calls(func_node, containers, functions or {}):
        # The callee may build its own container from the request it was handed.
        _collect(helper, forwarded | _query_containers(helper), params)
    return params


def _collect(func_node: Node, containers: set[str], params: HandlerParams) -> None:
    for node in iter_nodes(func_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            continue
        field_node = function.child_by_field_name("field")
        if field_node is None:
            continue
        method = node_text(field_node)
        operand = function.child_by_field_name("operand")
        if operand is None:
            continue
        name = _first_string_argument(node)
        if name is None:
            continue
        operand_text = node_text(operand)
        if method == "Get" and (
            operand_text.endswith(".Header") or operand_text == "Header"
        ):
            params.add("header", name, ParamType.STRING)
            continue
        container_type = CONTAINER_ACCESSORS.get(method)
        if container_type is not None and (
            _is_query_source(operand_text) or operand_text in containers
        ):
            params.add("query", name, container_type)
            continue
        accessor = _ACCESSORS.get(method)
        # A framework accessor is called straight on the request or context, so
        # requiring a plain receiver keeps map and cache reads out of the model.
        if accessor is not None and operand.type == "identifier":
            location, param_type = accessor
            params.add(location, name, param_type)


def _helper_calls(
    func_node: Node,
    containers: set[str],
    functions: dict[str, Node],
) -> list[tuple[Node, set[str]]]:
    """Same-package callees the handler hands request-derived data to.

    Two shapes matter. request-baskets forwards a container
    (``getPage(values)``), and Navidrome forwards the request itself to a method
    that then builds its own container (``api.getAlbumList(r)`` doing
    ``p := req.Params(r)``). Both are followed one level; anything deeper is left
    to LLM recovery.
    """
    own_parameters = set(parameter_names(func_node))
    found: list[tuple[Node, set[str]]] = []
    for node in iter_nodes(func_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None:
            continue
        if function.type == "identifier":
            name = node_text(function)
        elif function.type == "selector_expression":
            field = function.child_by_field_name("field")
            name = node_text(field) if field is not None else ""
        else:
            continue
        callee = functions.get(name)
        if callee is None or callee == func_node:
            continue
        arg_list = node.child_by_field_name("arguments")
        if arg_list is None:
            continue
        args = [child for child in arg_list.named_children if child.type != "comment"]
        names = parameter_names(callee)
        forwarded: set[str] = set()
        carries_request_data = False
        for index, arg in enumerate(args):
            if arg.type != "identifier":
                continue
            text = node_text(arg)
            if text in containers:
                carries_request_data = True
                if index < len(names):
                    forwarded.add(names[index])
            elif text in own_parameters:
                carries_request_data = True
        if carries_request_data:
            found.append((callee, forwarded))
    return found


def parameter_names(func_node: Node) -> list[str]:
    parameters = func_node.child_by_field_name("parameters")
    if parameters is None:
        return []
    names: list[str] = []
    for declaration in parameters.named_children:
        if declaration.type != "parameter_declaration":
            continue
        for name_node in declaration.children_by_field_name("name"):
            names.append(node_text(name_node))
    return names


def _is_query_source(text: str) -> bool:
    """Whether an expression yields a container of request parameters."""
    collapsed = text.replace(" ", "")
    return collapsed.endswith("Query()") or _PARAMS_CALL_RE.search(collapsed) is not None


def _query_containers(func_node: Node) -> set[str]:
    """Locals bound to r.URL.Query(), so later ``x.Get("q")`` reads count."""
    containers: set[str] = set()
    for node in iter_nodes(func_node):
        if node.type == "short_var_declaration":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        elif node.type == "assignment_statement":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
        else:
            continue
        if left is None or right is None:
            continue
        names = list(left.named_children)
        values = list(right.named_children) if right.type == "expression_list" else [right]
        for name_node, value_node in zip(names, values):
            if value_node.type == "call_expression" and _is_query_source(node_text(value_node)):
                containers.add(node_text(name_node))
    return containers


def _first_string_argument(call: Node) -> str | None:
    """The literal name an accessor reads, e.g. ``c.DefaultQuery("page", "1")``."""
    arg_list = call.child_by_field_name("arguments")
    if arg_list is None:
        return None
    args = [child for child in arg_list.named_children if child.type != "comment"]
    if not args:
        return None
    return string_literal_value(args[0])


# Decoders that bind a request body into a struct. gin's ShouldBindJSON and
# BindJSON are listed now so the gin rule needs no change here later.
_BODY_BINDERS = frozenset({"Unmarshal", "Decode", "BindJSON", "ShouldBindJSON", "ShouldBind"})


def find_body_struct(
    func_node: Node,
    method_results: dict[str, set[str]] | None = None,
) -> str | None:
    """Name the struct type the handler decodes the request body into.

    ``method_results`` maps a method name to the result types declared for it in
    the package, which is how request-baskets' ``config := basket.Config()`` is
    resolved. A name declared with more than one result type is ambiguous, and
    guessing there would invent body fields, so it resolves to nothing.
    """
    for target in _decode_targets(func_node):
        type_name = _local_var_type(func_node, target, method_results or {})
        if type_name:
            return type_name
    return None


def _decode_targets(func_node: Node) -> list[str]:
    targets: list[str] = []
    for node in iter_nodes(func_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            continue
        field_node = function.child_by_field_name("field")
        if field_node is None or node_text(field_node) not in _BODY_BINDERS:
            continue
        arg_list = node.child_by_field_name("arguments")
        if arg_list is None:
            continue
        for arg in arg_list.named_children:
            if arg.type != "unary_expression":
                continue
            operator = arg.child_by_field_name("operator")
            operand = arg.child_by_field_name("operand")
            if operator is None or node_text(operator) != "&" or operand is None:
                continue
            if operand.type == "identifier":
                targets.append(node_text(operand))
    return targets


def _local_var_type(
    func_node: Node, target: str, method_results: dict[str, set[str]]
) -> str | None:
    for node in iter_nodes(func_node):
        if node.type == "var_spec":
            names = [node_text(n) for n in node.children_by_field_name("name")]
            type_node = node.child_by_field_name("type")
            if target in names and type_node is not None:
                return node_text(type_node).lstrip("*")
        elif node.type == "short_var_declaration":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            names = [node_text(n) for n in left.named_children]
            values = list(right.named_children) if right.type == "expression_list" else [right]
            for name, value in zip(names, values):
                if name != target:
                    continue
                if value.type == "composite_literal":
                    type_node = value.child_by_field_name("type")
                    if type_node is not None:
                        return node_text(type_node).lstrip("*")
                if value.type == "call_expression":
                    resolved = _call_result_type(value, method_results)
                    if resolved:
                        return resolved
    return None


def _call_result_type(call: Node, method_results: dict[str, set[str]]) -> str | None:
    function = call.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "selector_expression":
        field_node = function.child_by_field_name("field")
        name = node_text(field_node) if field_node is not None else None
    elif function.type == "identifier":
        name = node_text(function)
    else:
        name = None
    if name is None:
        return None
    candidates = method_results.get(name, set())
    if len(candidates) != 1:
        return None
    return next(iter(candidates)).lstrip("*")
