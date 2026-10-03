#!/usr/bin/env python3
"""Go struct types and the request bodies they describe.

Struct tags carry what a Java DTO needs annotations and getters for: the wire
name and the type of every field. That makes the body the best-recovered part
of a Go endpoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from code_analyzer.go.parser import iter_nodes, node_text
from models.types import ParamType


_TAG_RE = re.compile(r'(\w+):"([^"]*)"')
# Which struct tag names a field for which part of the request.
TAG_LOCATIONS = {"json": "body", "form": "query", "query": "query", "uri": "path"}

_INTEGER_TYPES = {
    "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64", "byte", "rune",
}
_NUMBER_TYPES = {"float32", "float64"}


@dataclass
class GoField:
    name: str
    go_type: str
    param_type: ParamType
    tags: dict[str, str] = field(default_factory=dict)
    # A []T field carries the element's ParamType and this flag. The SSRF
    # parameter of Alist's offline download (Urls []string) and of Cloudreve's
    # remote download (Src []string) are both slices, so dropping them hid the
    # only cross-privilege finding on those targets.
    is_array: bool = False


@dataclass
class GoStruct:
    name: str
    fields: list[GoField] = field(default_factory=list)


def element_type(go_type: str) -> tuple[ParamType, bool] | None:
    """(ParamType, is_array) for a field type, or None when unmodelled.

    ``[]string`` yields (STRING, True); a slice of an unmodelled element type
    stays unmodelled rather than being guessed at.
    """
    text = go_type.strip().lstrip("*")
    if text.startswith("[]"):
        inner = map_go_type(text[2:])
        return (inner, True) if inner is not None else None
    inner = map_go_type(text)
    return (inner, False) if inner is not None else None


def map_go_type(go_type: str) -> ParamType | None:
    """Map a Go scalar type to a ParamType, or None for one we do not model."""
    base = go_type.strip().lstrip("*")
    if base == "string":
        return ParamType.STRING
    if base in _INTEGER_TYPES:
        return ParamType.INTEGER
    if base in _NUMBER_TYPES:
        return ParamType.NUMBER
    if base == "bool":
        return ParamType.BOOLEAN
    return None


def collect_struct_types(root: Node) -> dict[str, GoStruct]:
    structs: dict[str, GoStruct] = {}
    for node in iter_nodes(root):
        if node.type != "type_spec":
            continue
        name_node = node.child_by_field_name("name")
        type_node = node.child_by_field_name("type")
        if name_node is None or type_node is None or type_node.type != "struct_type":
            continue
        structs[node_text(name_node)] = GoStruct(
            name=node_text(name_node),
            fields=_struct_fields(type_node),
        )
    return structs


def _struct_fields(struct_node: Node) -> list[GoField]:
    fields: list[GoField] = []
    for declaration in iter_nodes(struct_node):
        if declaration.type != "field_declaration":
            continue
        type_node = declaration.child_by_field_name("type")
        if type_node is None:
            continue
        go_type = node_text(type_node)
        resolved = element_type(go_type)
        if resolved is None:
            continue
        param_type, is_array = resolved
        tag_node = declaration.child_by_field_name("tag")
        tags = parse_tags(node_text(tag_node)) if tag_node is not None else {}
        wire_name = tags.get("json")
        for name_node in declaration.children_by_field_name("name"):
            field_name = node_text(name_node)
            if not field_name[:1].isupper():
                # An unexported field never takes part in JSON decoding.
                continue
            fields.append(
                GoField(wire_name or field_name, go_type, param_type, tags, is_array)
            )
    return fields


def parse_tags(tag_text: str) -> dict[str, str]:
    """Struct tag values keyed by tag name, dropping options like ",omitempty"."""
    tags: dict[str, str] = {}
    for key, value in _TAG_RE.findall(tag_text):
        name = value.split(",")[0].strip()
        if name and name != "-":
            tags[key] = name
    return tags


