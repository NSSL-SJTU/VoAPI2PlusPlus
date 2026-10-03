#!/usr/bin/env python3
"""Fold Go path expressions into concrete route paths.

Real services rarely pass a bare literal: request-baskets registers
``router.GET(pathPrefix+"/"+serviceAPIPath+"/stats", GetStats)``. Recovering the
path therefore means resolving identifiers and folding ``+`` concatenation.
"""

from __future__ import annotations

from tree_sitter import Node

from code_analyzer.go.parser import iter_nodes, node_text, string_literal_value


STRING_LITERALS = ("interpreted_string_literal", "raw_string_literal")


def collect_string_constants(root: Node) -> dict[str, str]:
    """Map identifier -> string value for const/var declarations under ``root``."""
    constants: dict[str, str] = {}
    for node in iter_nodes(root):
        if node.type in ("const_spec", "var_spec"):
            names = node.children_by_field_name("name")
            value = node.child_by_field_name("value")
        elif node.type == "short_var_declaration":
            left = node.child_by_field_name("left")
            names = list(left.named_children) if left is not None else []
            value = node.child_by_field_name("right")
        else:
            continue
        if not names or value is None:
            continue
        values = (
            list(value.named_children)
            if value.type == "expression_list"
            else [value]
        )
        for name_node, value_node in zip(names, values):
            text = string_literal_value(value_node)
            if text is not None:
                constants[node_text(name_node)] = text
    return constants


def package_name(root: Node) -> str | None:
    """The name from the file's ``package`` clause."""
    for node in iter_nodes(root):
        if node.type == "package_clause":
            for child in node.named_children:
                if child.type == "package_identifier":
                    return node_text(child)
    return None


def collect_imports(root: Node) -> dict[str, str]:
    """Map the name a file refers to a package by onto that package's path."""
    imports: dict[str, str] = {}
    for node in iter_nodes(root):
        if node.type != "import_spec":
            continue
        path_node = node.child_by_field_name("path")
        if path_node is None:
            continue
        path = string_literal_value(path_node) or ""
        if not path:
            continue
        name_node = node.child_by_field_name("name")
        alias = node_text(name_node) if name_node is not None else path.rsplit("/", 1)[-1]
        imports[alias] = path
    return imports


def resolve_path_expression(
    node: Node,
    constants: dict[str, str],
    qualified: dict[tuple[str, str], str] | None = None,
) -> str | None:
    """Return the path the expression evaluates to, or None when unresolvable.

    A part that is only known at runtime -- request-baskets computes its
    ``pathPrefix`` from configuration, and it is empty unless deployed behind a
    prefix -- contributes an empty string. That is only safe while some other
    part of the expression is concrete: an expression that resolves to nothing
    at all would invent an endpoint, so it yields None instead.
    """
    text, concrete = _resolve(node, constants, qualified or {})
    if not concrete:
        return None
    return text


def _resolve(
    node: Node,
    constants: dict[str, str],
    qualified: dict[tuple[str, str], str],
) -> tuple[str, bool]:
    """Return (text, concrete), where concrete marks a statically known part."""
    if node.type in STRING_LITERALS:
        return string_literal_value(node) or "", True
    if node.type == "identifier":
        value = constants.get(node_text(node))
        if value is None:
            return "", False
        return value, True
    if node.type == "selector_expression":
        # Cloudreve builds its prefix from constants.APIPrefix, declared in
        # another package, so a qualified name has to resolve too.
        operand = node.child_by_field_name("operand")
        field = node.child_by_field_name("field")
        if (
            operand is not None
            and field is not None
            and operand.type in ("package_identifier", "identifier")
        ):
            value = qualified.get((node_text(operand), node_text(field)))
            if value is not None:
                return value, True
        return "", False
    if node.type == "parenthesized_expression":
        inner = node.named_children[0] if node.named_children else None
        return _resolve(inner, constants, qualified) if inner is not None else ("", False)
    if node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if operator is None or node_text(operator) != "+" or left is None or right is None:
            return "", False
        left_text, left_concrete = _resolve(left, constants, qualified)
        right_text, right_concrete = _resolve(right, constants, qualified)
        return left_text + right_text, left_concrete or right_concrete
    return "", False
