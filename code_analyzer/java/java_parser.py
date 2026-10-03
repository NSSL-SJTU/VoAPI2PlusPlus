#!/usr/bin/env python3

import re
import logging
from typing import Optional
from dataclasses import dataclass, field

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser, Tree


@dataclass
class JavaField:

    name: str
    type: str
    json_name: str
    ignored: bool = False
    default_value: Optional[str] = None
    is_list: bool = False
    is_map: bool = False
    generic_types: list[str] = field(default_factory=list)
    # The javadoc block immediately above the field, verbatim. Kept because a
    # constraint is often documented there rather than expressed in the type:
    # Chat2DB writes `private String status;` with `@see StatusEnum` above it,
    # and without the comment there is nothing that says the only accepted
    # values are DRAFT and RELEASE.
    doc: str = ""


@dataclass
class JavaClass:

    name: str
    package: str
    full_name: str
    file_path: str
    fields: list[JavaField] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    extends: Optional[str] = None
    is_enum: bool = False
    enum_values: list[str] = field(default_factory=list)
    description: str = ""


class JavaParser:

    def __init__(self):
        self.language = Language(tsjava.language())
        self.parser = Parser(self.language)
        self.classes: dict[str, JavaClass] = {}
        self._logger = logging.getLogger(__name__)

        self._q_package = self.language.query(
            """
        (package_declaration
          (scoped_identifier) @package_name
        )
        """
        )

        self._q_field = self.language.query(
            """
        (field_declaration
          type: (_) @field_type
          declarator: (variable_declarator
            name: (identifier) @field_name
          )
        )
        """
        )

        self._q_field_decl = self.language.query(
            """
        (field_declaration) @field_decl
        """
        )

        self._q_class = self.language.query(
            """
        (class_declaration
          name: (identifier) @class_name
        )
        """
        )

        self._q_enum_decl = self.language.query(
            """
        (enum_declaration
          name: (identifier) @enum_name
        )
        """
        )

        self._q_enum_const = self.language.query(
            """
        (enum_constant
          name: (identifier) @constant_name
        )
        """
        )

        # A collection field may be declared with any of these interfaces and may
        # carry a package prefix (java.util.Set<Integer>). Treat them all as lists so
        # the element type in <> is not dropped.
        self._re_list = re.compile(r"(?:[\w.]+\.)?(?:List|Set|Collection|Iterable)<(.+)>")
        self._re_map = re.compile(r"(?:[\w.]+\.)?Map<(.+),\s*(.+)>")
        self._re_generic = re.compile(r"(?:[\w.]+\.)?(\w+)<(.+)>")

    def extract_text_from_bytes(self, code: str, start_byte: int, end_byte: int) -> str:
        """ extract text from position of bytes """
        try:
            return code.encode("utf-8")[start_byte:end_byte].decode("utf-8")
        except UnicodeDecodeError as exc:
            self._logger.debug("extract_text_from_bytes failed: %s", exc)
            return ""

    def extract_package_name(self, code: str, tree: Tree) -> str:
        captures = self._q_package.captures(tree.root_node)
        if "package_name" in captures and captures["package_name"]:
            package_node = captures["package_name"][0]
            return self.extract_text_from_bytes(
                code, package_node.start_byte, package_node.end_byte
            )

        return ""

    def parse_type_info(self, type_str: str) -> tuple:
        type_str = type_str.strip()

        list_match = self._re_list.match(type_str)
        if list_match:
            inner_type = list_match.group(1).strip()
            return (inner_type, True, False, [inner_type])

        map_match = self._re_map.match(type_str)
        if map_match:
            key_type = map_match.group(1).strip()
            value_type = map_match.group(2).strip()
            return (type_str, False, True, [key_type, value_type])

        generic_match = self._re_generic.match(type_str)
        if generic_match:
            base_type = generic_match.group(1)
            generic_types = [t.strip() for t in generic_match.group(2).split(",")]
            return (base_type, False, False, generic_types)

        return (type_str, False, False, [])

    def extract_fields(self, code: str) -> list[JavaField]:
        tree = self.parser.parse(code.encode("utf-8"))
        fields = []

        field_decls = self._q_field_decl.captures(tree.root_node).get("field_decl", [])

        for field_decl in field_decls:
            captures = self._q_field.captures(field_decl)
            field_types = captures.get("field_type", [])
            field_names = captures.get("field_name", [])
            if not field_types:
                continue
            field_decl_text = self.extract_text_from_bytes(
                code, field_decl.start_byte, field_decl.end_byte
            )
            field_type = self.extract_text_from_bytes(
                code, field_types[0].start_byte, field_types[0].end_byte
            )
            if not field_type:
                continue
            field_doc = self._preceding_doc(code, field_decl)
            _base_type, is_list, is_map, generic_types = self.parse_type_info(field_type)
            for name_node in field_names:
                field_name = self.extract_text_from_bytes(
                    code, name_node.start_byte, name_node.end_byte
                )
                if not field_name:
                    continue
                fields.append(
                    JavaField(
                        name=field_name,
                        type=field_type,
                        json_name=self._json_field_name(field_decl_text, field_name, len(field_names)),
                        ignored=self._is_json_ignored(field_decl_text),
                        is_list=is_list,
                        is_map=is_map,
                        generic_types=generic_types,
                        doc=field_doc,
                    )
                )

        return fields

    def _preceding_doc(self, code: str, node) -> str:
        """The comment directly above a declaration, or "" if there is none.

        Annotations belong to the declaration node itself, so the javadoc is the
        immediately preceding sibling; grammars name it block_comment, line_comment
        or plain comment depending on version, hence the substring test.
        """
        prev = node.prev_sibling
        if prev is None or "comment" not in prev.type:
            return ""
        return self.extract_text_from_bytes(code, prev.start_byte, prev.end_byte) or ""

    def _json_field_name(
        self,
        field_decl_text: str,
        field_name: str,
        declarator_count: int,
    ) -> str:
        if declarator_count != 1:
            return field_name
        for ann_name in ("JsonProperty", "SerializedName"):
            match = re.search(
                rf"@{ann_name}\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']",
                field_decl_text,
            )
            if match:
                return match.group(1)
        return field_name

    def _is_json_ignored(self, field_decl_text: str) -> bool:
        return bool(re.search(r"@(?:JsonIgnore|JsonIgnoreProperties)\b", field_decl_text))

    def extract_extends(self, code: str, class_name: str) -> Optional[str]:
        """Best-effort extraction of a single Java superclass."""
        match = re.search(
            rf"\bclass\s+{re.escape(class_name)}\s+extends\s+([A-Za-z_][\w.$<>]*)",
            code,
        )
        if not match:
            return None
        return match.group(1).split(".")[-1].split("<", 1)[0]

    def analyze_java_file(self, file_path: str) -> Optional[JavaClass]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = self.parser.parse(code.encode("utf-8"))

            captures = self._q_class.captures(tree.root_node)
            enum_captures = self._q_enum_decl.captures(tree.root_node)

            class_nodes = captures.get("class_name")
            if class_nodes:
                class_name_node = class_nodes[0]
                is_enum = False
            else:
                enum_nodes = enum_captures.get("enum_name")
                if not enum_nodes:
                    return None
                class_name_node = enum_nodes[0]
                is_enum = True

            class_name = self.extract_text_from_bytes(
                code, class_name_node.start_byte, class_name_node.end_byte
            )

            package_name = self.extract_package_name(code, tree)
            full_name = f"{package_name}.{class_name}" if package_name else class_name
            imports = self.extract_imports(code)

            fields = self.extract_fields(code)

            enum_values = self.extract_enum_values(code) if is_enum else []

            java_class = JavaClass(
                name=class_name,
                package=package_name,
                full_name=full_name,
                file_path=file_path,
                fields=fields,
                imports=imports,
                extends=self.extract_extends(code, class_name),
                is_enum=is_enum,
                enum_values=enum_values,
            )

            return java_class

        except (OSError, UnicodeDecodeError) as exc:
            self._logger.warning("Analyze file failed %s: %s", file_path, exc)
            return None

    def extract_enum_values(self, code: str) -> list[str]:
        tree = self.parser.parse(code.encode("utf-8"))
        enum_values = []

        captures = self._q_enum_const.captures(tree.root_node)

        if "constant_name" in captures:
            # captures() does not return nodes in document order (and the order varies
            # between calls), so sort by position. This keeps enum_values in source /
            # ordinal order, which the runtime now depends on: example[0] is what gets
            # sent, and value exploration walks the ordered set.
            for constant_node in sorted(
                captures["constant_name"], key=lambda n: n.start_byte
            ):
                constant_name = self.extract_text_from_bytes(
                    code, constant_node.start_byte, constant_node.end_byte
                )
                if constant_name:
                    enum_values.append(constant_name)

        return enum_values

    def find_class_by_type(self, type_name: str) -> Optional[JavaClass]:
        if type_name in self.classes:
            return self.classes[type_name]

        for _full_name, java_class in self.classes.items():
            if java_class.name == type_name:
                return java_class

        return None

    def extract_imports(self, code: str) -> dict[str, str]:
        imports: dict[str, str] = {}
        for match in re.finditer(r"import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;", code):
            full_name = match.group(1)
            simple = full_name.split(".")[-1]
            imports[simple] = full_name
        return imports
