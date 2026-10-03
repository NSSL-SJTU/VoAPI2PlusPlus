#!/usr/bin/env python3
"""
Parameter resolution helpers: location, names, defaults, object flattening.
"""

from __future__ import annotations

import re
from typing import Optional, TYPE_CHECKING

from models.parameter import BasicParameter, ArrayParameter, Parameter, PropertyParameter
from models.types import ParamType
from code_analyzer.java.type_utils import map_java_type
from code_analyzer.java.indexer import JavaIndexer
from code_analyzer.java.type_utils import BASIC_TYPES

if TYPE_CHECKING:
    from tree_sitter import Node
    from code_analyzer.java.java_parser import JavaClass

class ParamResolver:

    def __init__(self, indexer: JavaIndexer):
        self.indexer = indexer

    def determine_location(self, ann_text: str, param_type: str, http_method: str) -> str:
        base_type = self.indexer.simple_type_name(param_type)
        if "PathVariable" in ann_text:
            return "path"
        if "RequestHeader" in ann_text:
            return "header"
        if "RequestBody" in ann_text:
            return "body"
        if "RequestParam" in ann_text:
            if base_type == "MultipartFile":
                return "body"
            return "query"

        basic = BASIC_TYPES
        if base_type in {"Map", "HashMap"} or base_type in basic:
            return "query"
        # A type that is not a known command object still binds from the query string on a
        # method that carries no body; only a body-carrying method defaults to the body.
        return "query" if http_method in {"GET", "DELETE"} else "body"

    def extract_reqparam_name(self, code: str, ann_node: Node) -> Optional[str]:
        """Extract name/value from @RequestParam annotation."""
        # Match: @RequestParam("name") or @RequestParam(value="name") or @RequestParam(name="name")
        query = """
        (annotation
          arguments: (annotation_argument_list
            [
              (string_literal) @v
              (element_value_pair
                key: (identifier) @_k
                value: (string_literal) @v
                (#match? @_k "^(value|name)$"))
            ]))
        """
        vals = self.indexer.query(ann_node, query).get("v", [])
        if vals:
            return self.indexer.extract_text(code, vals[0]).strip("\"'")
        return None

    def extract_reqparam_default(self, code: str, ann_node: Node) -> Optional[str]:
        """Extract defaultValue from @RequestParam annotation."""
        query = """
        (annotation
          arguments: (annotation_argument_list
            (element_value_pair
              key: (identifier) @_k
              value: (string_literal) @v
              (#eq? @_k "defaultValue"))))
        """
        vals = self.indexer.query(ann_node, query).get("v", [])
        if vals:
            return self.indexer.extract_text(code, vals[0]).strip("\"'")
        return None

    @staticmethod
    def paramtype_to_java(p: ParamType) -> str:
        return {
            ParamType.INTEGER: "Integer",
            ParamType.STRING: "String",
            ParamType.BOOLEAN: "Boolean",
            ParamType.NUMBER: "Double",
            ParamType.ARRAY: "List<Object>",
            ParamType.OBJECT: "Map<String,Object>",
            ParamType.DATETIME: "LocalDateTime",
            ParamType.DATE: "LocalDate",
        }.get(p, "String")

    def flatten_object_param(
        self,
        java_type: str,
        context_code: str | None = None,
        _seen: frozenset[str] | None = None,
    ) -> dict[str, Parameter]:
        self.indexer.index_java_types()
        seen = _seen or frozenset()
        base = java_type.split("<")[0].strip()
        jc = self.indexer.resolve_class_by_type(base, context_code)
        if not jc:
            return {}
        # Break recursion on self-referential types (a Node holding List<Node>);
        # otherwise flattening the element type below would recurse without end.
        if jc.full_name in seen:
            return {}
        inner_seen = seen | {jc.full_name}
        out: dict[str, Parameter] = {}
        for f in self.indexer.fields_with_supers(jc):
            # skip serialization helper fields
            if f.name in {"serialVersionUID", "SERIAL_VERSION_UID"}:
                continue
            if f.ignored:
                continue
            # List/Set fields -> ArrayParameter whose item follows the element type
            if f.is_list or f.type.strip().startswith("List<"):
                inner_java_type = f.generic_types[0] if f.generic_types else "String"
                item = self._build_collection_item(
                    inner_java_type, f.name + "Item", context_code, inner_seen
                )
                out[f.json_name] = ArrayParameter(f.json_name, item=item, is_required=False)
                continue
            # default: scalar/object/collection based on the mapped Java type
            ptype, ex, dft = map_java_type(f.type, f.name)
            # An enum field falls through map_java_type to STRING/"VoAPITestString",
            # which the server rejects because it is not a valid constant. Resolve the
            # declaring enum and emit its real constant names instead. (The first
            # constant is what actually gets sent; exercising the others -- e.g. driving
            # editorType to RICHTEXT -- is a separate value-exploration concern.)
            if ptype == ParamType.STRING:
                enum_class = self.indexer.resolve_class_by_type(f.type, context_code)
                if not (enum_class and enum_class.is_enum):
                    # The field may be declared String with the constraint documented
                    # instead of typed: Chat2DB writes `private String status;` under
                    # `@see StatusEnum`, and 55 of its request fields across 45 files
                    # follow that pattern. The javadoc reference is the only place the
                    # accepted values exist, so read it before giving up -- otherwise
                    # the field gets "VoAPITestString", the server stores it (200,
                    # "success":true), and the resource lands in a state no screen ever
                    # renders, which is indistinguishable from the endpoint being safe.
                    enum_class = self._enum_from_doc(f.doc, context_code)
                if enum_class and enum_class.is_enum and enum_class.enum_values:
                    out[f.json_name] = BasicParameter(
                        f.json_name,
                        ParamType.STRING,
                        example=list(enum_class.enum_values),
                        default=[],
                        is_required=False,
                    )
                    continue
            if ptype == ParamType.ARRAY:
                # Same rule as the list branch: the declared element type decides the
                # item, otherwise a String placeholder lands in a typed array and the
                # server rejects the whole body.
                inner_java_type = f.generic_types[0] if f.generic_types else "String"
                item = self._build_collection_item(
                    inner_java_type, f.json_name + "Item", context_code, inner_seen
                )
                out[f.json_name] = ArrayParameter(f.json_name, item=item, is_required=False)
            elif ptype == ParamType.OBJECT:
                out[f.json_name] = PropertyParameter(f.json_name, properties={}, is_required=False)
            else:
                out[f.json_name] = BasicParameter(
                    f.json_name, ptype, example=ex, default=dft, is_required=False
                )
        return out

    # `@see X`, `{@link X}` and `{@link X#Y}` are the three forms Java projects use
    # to point a String field at the enum that constrains it. Only the simple name
    # matters; resolve_class_by_type maps it through the file's own imports.
    _DOC_TYPE_REF = re.compile(r"@see\s+([\w.]+)|\{@link(?:plain)?\s+([\w.#]+)")

    def _enum_from_doc(self, doc: str, context_code: str) -> Optional["JavaClass"]:
        """The enum a field's javadoc refers to, or None.

        Returns the first reference that actually resolves to an enum carrying
        constants, so a javadoc that merely links a helper class is ignored.
        """
        if not doc:
            return None
        for see_ref, link_ref in self._DOC_TYPE_REF.findall(doc):
            ref = (see_ref or link_ref).split("#")[0]
            if not ref:
                continue
            resolved = self.indexer.resolve_class_by_type(ref, context_code)
            if resolved and resolved.is_enum and resolved.enum_values:
                return resolved
        return None

    def _build_collection_item(
        self,
        inner_java_type: str,
        item_name: str,
        context_code: str | None,
        seen: frozenset[str],
    ) -> Parameter:
        """Build the element parameter for a collection field.

        The element type drives the shape: an enum yields a STRING item carrying the
        real constants, a flattenable DTO yields a nested object (so Set<PostMetaParam>
        materializes as [{...}] instead of ["VoAPITestString"], which Jackson rejects),
        and everything else falls back to the scalar mapping.
        """
        inner_class = self.indexer.resolve_class_by_type(inner_java_type, context_code)
        if inner_class and inner_class.is_enum and inner_class.enum_values:
            return BasicParameter(
                item_name,
                ParamType.STRING,
                example=list(inner_class.enum_values),
                default=[],
            )
        if inner_class and not inner_class.is_enum:
            props = self.flatten_object_param(inner_java_type, context_code, seen)
            if props:
                return PropertyParameter(item_name, properties=props)
        item_pt, item_ex, item_dft = map_java_type(inner_java_type, item_name)
        return BasicParameter(item_name, item_pt, example=item_ex, default=item_dft)
