#!/usr/bin/env python3
"""
Lightweight indexing and common utilities for Java code analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Dict, TYPE_CHECKING
import re

from code_analyzer.java.java_parser import JavaParser
from tree_sitter import Node

if TYPE_CHECKING:
    from code_analyzer.java.java_parser import JavaClass, JavaField


class JavaIndexer:

    def __init__(
        self,
        java_parser: JavaParser,
        project_path: Path,
        java_files: list[Path],
    ):
        self.java_parser = java_parser
        self.project_path = project_path
        self.java_files = java_files
        self._indexed = False

    def index_java_types(self):
        if self._indexed:
            return
        for jf in self.java_files:
            jc = self.java_parser.analyze_java_file(str(jf))
            if jc:
                self.java_parser.classes[jc.full_name] = jc
        self._indexed = True

    def find_java_file_by_class(self, simple_class_name: str) -> Optional[Path]:
        for p in self.java_files:
            if p.name == f"{simple_class_name}.java":
                return p
        return None

    def resolve_class_by_type(
        self,
        type_name: str,
        context_code: str | None = None,
    ) -> Optional["JavaClass"]:
        self.index_java_types()
        simple = self.simple_type_name(type_name)
        if not simple:
            return None

        if "." in type_name:
            direct = self.java_parser.find_class_by_type(type_name)
            if direct:
                return direct

        if context_code:
            package, imports = self.parse_imports_and_package(context_code)
            imported = imports.get(simple)
            if imported and not imported.endswith(".*"):
                direct = self.java_parser.find_class_by_type(imported)
                if direct:
                    return direct
            if package:
                direct = self.java_parser.find_class_by_type(f"{package}.{simple}")
                if direct:
                    return direct
            for imported in imports.values():
                if not imported.endswith(".*"):
                    continue
                prefix = imported[:-2]
                direct = self.java_parser.find_class_by_type(f"{prefix}.{simple}")
                if direct:
                    return direct

        return self.java_parser.find_class_by_type(simple)

    @staticmethod
    def simple_type_name(type_name: str) -> str:
        text = (type_name or "").strip()
        if not text:
            return ""
        text = text.split("<", 1)[0].strip()
        while text.endswith("[]"):
            text = text[:-2]
        return text.split(".")[-1]

    def fields_with_supers(self, java_class: "JavaClass") -> list["JavaField"]:
        return self._fields_with_supers(java_class, set())

    def _fields_with_supers(
        self,
        java_class: "JavaClass",
        seen: set[str],
    ) -> list["JavaField"]:
        if java_class.full_name in seen:
            return []
        seen.add(java_class.full_name)

        fields: list["JavaField"] = []
        if java_class.extends:
            parent = self.resolve_class_by_type(java_class.extends, self._class_code(java_class))
            if parent:
                fields.extend(self._fields_with_supers(parent, seen))
        by_name: dict[str, "JavaField"] = {}
        for field in fields + java_class.fields:
            by_name[field.json_name] = field
        return list(by_name.values())

    def _class_code(self, java_class: "JavaClass") -> str:
        try:
            return Path(java_class.file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def parse_field_types(self, code: str) -> dict[str, str]:
        # matches: @Autowired private MenuDao menuMapper; or private MenuService menuService;
        field_types: dict[str, str] = {}
        pattern = re.compile(
            r"(?:@\w+(?:\([^)]*\))?\s+)*?"
            r"(?:private|protected|public)?\s*([\w.$<>]+)\s+(\w+)\s*;"
        )
        for m in pattern.finditer(code):
            type_name = m.group(1)
            var_name = m.group(2)
            field_types[var_name] = type_name
        return field_types

    def parse_imports_and_package(self, code: str) -> tuple[str, Dict[str, str]]:
        pkg_match = re.search(r"package\s+([\w\.]+)\s*;", code)
        package = pkg_match.group(1) if pkg_match else ""
        imports: dict[str, str] = {}
        for m in re.finditer(r"import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;", code):
            fq = m.group(1)
            simple = fq.split(".")[-1]
            imports[simple] = fq
        return package, imports

    def query(self, node: Node, q: str) -> dict[str, list[Node]]:
        return self.java_parser.language.query(q).captures(node)

    def extract_text(self, code: str, node: Node) -> str:
        return self.java_parser.extract_text_from_bytes(code, node.start_byte, node.end_byte)

    @staticmethod
    def extract_method_code(code: str, method_node: Node) -> str:
        start = method_node.start_byte
        end = method_node.end_byte
        return code.encode("utf-8")[start:end].decode("utf-8", errors="ignore")
