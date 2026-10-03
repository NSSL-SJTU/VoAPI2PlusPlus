#!/usr/bin/env python3
"""
Build ResponseStructure from Java return types.
"""

from __future__ import annotations

from models.structure import ResponseStructure
from models.parameter import ArrayParameter, BasicParameter, Parameter, PropertyParameter
from models.types import ParamType
from code_analyzer.java.type_utils import map_java_type
from code_analyzer.java.indexer import JavaIndexer
import re


class ResponseBuilder:

    def __init__(self, indexer: JavaIndexer):
        self.indexer = indexer

    def fill_response_from_return_type(
        self,
        response: ResponseStructure,
        return_type: str,
        context_code: str | None = None,
    ):
        self.indexer.index_java_types()
        custom_types = self._custom_type_names(return_type)
        for type_name in custom_types:
            for name, param in self._field_parameters_for_type(type_name, context_code).items():
                response.body[name] = param

        wrapper = self._wrapper_type(return_type)
        payload_type = custom_types[-1] if custom_types else ""
        payload = self._field_parameters_for_type(payload_type, context_code)
        if wrapper in {"RestResult", "Result", "R"} and payload:
            response.body.setdefault(
                "data",
                PropertyParameter("data", properties=payload),
            )
        elif wrapper in {"PageBean", "Page"} and payload:
            response.body.setdefault(
                "rows",
                ArrayParameter("rows", item=PropertyParameter("rowsItem", payload)),
            )

    def _field_parameters_for_type(
        self,
        type_name: str,
        context_code: str | None = None,
    ) -> dict[str, Parameter]:
        if not type_name:
            return {}
        out: dict[str, Parameter] = {}
        jc = self.indexer.resolve_class_by_type(type_name, context_code)
        if not jc or jc.is_enum:
            return out
        for f in self.indexer.fields_with_supers(jc):
            if f.name in {"serialVersionUID", "SERIAL_VERSION_UID"}:
                continue
            if f.ignored:
                continue
            pt, ex, dft = map_java_type(f.type, f.name)
            if pt == ParamType.ARRAY:
                item = BasicParameter(f.json_name + "Item", ParamType.STRING)
                out[f.json_name] = ArrayParameter(f.json_name, item=item)
            elif pt == ParamType.OBJECT:
                out[f.json_name] = PropertyParameter(f.json_name, properties={})
            else:
                out[f.json_name] = BasicParameter(f.json_name, pt, example=ex, default=dft)
        return out

    def _wrapper_type(self, return_type: str) -> str:
        match = re.match(r"\s*([A-Za-z_][\w.$]*)\s*<", return_type or "")
        if not match:
            return ""
        return match.group(1).split(".")[-1]

    def _custom_type_names(self, return_type: str) -> list[str]:
        wrappers = self._wrapper_names()
        out: list[str] = []
        for token in re.findall(r"[A-Za-z_][\w.$]*", return_type or ""):
            simple = token.split(".")[-1]
            if simple in wrappers:
                continue
            if simple not in out and self.indexer.resolve_class_by_type(simple):
                out.append(simple)
        return out

    def _wrapper_names(self) -> set[str]:
        return {
            "void",
            "Void",
            "Object",
            "String",
            "Integer",
            "int",
            "Long",
            "long",
            "Double",
            "double",
            "Float",
            "float",
            "Boolean",
            "boolean",
            "Byte",
            "byte",
            "Short",
            "short",
            "Date",
            "LocalDate",
            "LocalDateTime",
            "Map",
            "HashMap",
            "List",
            "Set",
            "Collection",
            "Optional",
            "RestResult",
            "PageBean",
            "Page",
            "Result",
            "R",
            "ResponseEntity",
        }
