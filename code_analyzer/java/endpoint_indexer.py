#!/usr/bin/env python3
"""
Endpoint code indexer:
Builds a snippet-based index for a specific Spring endpoint by collecting
relevant Java code fragments (controller method, DTOs, wrappers, service signature).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Iterable
import re

from tree_sitter import Node

from code_analyzer.java.java_parser import JavaParser
from code_analyzer.java.indexer import JavaIndexer
from code_analyzer.java.type_utils import BASIC_TYPES
from code_analyzer.java.project_roots import collect_java_files, index_roots
from code_analyzer.java.spring_annotations import (
    annotation_name,
    default_methods_for_handler,
    mapping_values,
    string_values,
)


WRAPPER_TYPES = {
    "RestResult",
    "PageBean",
    "Page",
    "ResponseEntity",
    "Result",
    "R",
}

COLLECTION_TYPES = {
    "List",
    "Map",
    "Set",
    "Collection",
    "Iterable",
    "Optional",
}

PRIMITIVE_TYPES = {
    "void",
    "Void",
    "Object",
    "byte",
    "short",
    "int",
    "long",
    "float",
    "double",
    "boolean",
    "char",
}


@dataclass
class CodeSnippet:
    file: str
    start_line: int
    end_line: int
    reason: str
    code: str


@dataclass
class EndpointIndex:
    method: str
    path: str
    controller: str
    method_name: str
    snippets: list[CodeSnippet] = field(default_factory=list)
    truncated: bool = False
    total_chars: int = 0
    total_files: int = 0


class EndpointCodeIndexer:
    """
    Build a snippet-based index for one endpoint.
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.java_parser = JavaParser()
        self._index_roots = index_roots(self.project_path)
        self.java_files: list[Path] = collect_java_files(self._index_roots)
        self.indexer = JavaIndexer(self.java_parser, self.project_path, self.java_files)
        self.indexer.index_java_types()
        self._mybatis_analyzer = None

    def build_index(
        self,
        method: str,
        path: str,
        *,
        max_depth: int = 2,
        max_chars: int = 20000,
        max_files: int = 12,
        include_service: bool = True,
        include_wrappers: bool = True,
        include_db: bool = True,
    ) -> Optional[EndpointIndex]:
        match = self._find_endpoint(method, path)
        if not match:
            return None
        controller_file, code, class_node, method_node = match
        return self._build_index_from_match(
            controller_file,
            code,
            class_node,
            method_node,
            method=str(method).upper(),
            path=path,
            max_depth=max_depth,
            max_chars=max_chars,
            max_files=max_files,
            include_service=include_service,
            include_wrappers=include_wrappers,
            include_db=include_db,
        )

    def build_project_indices(
        self,
        *,
        max_depth: int = 2,
        max_chars: int = 20000,
        max_files: int = 12,
        include_service: bool = True,
        include_wrappers: bool = True,
        include_db: bool = True,
    ) -> list[EndpointIndex]:
        indices: list[EndpointIndex] = []
        seen: set[tuple[str, str, str, str]] = set()
        for match in self._iter_endpoints():
            controller_file, code, class_node, method_node, http_method, full_path = match
            controller_name = self._extract_class_name(code, class_node) or controller_file.stem
            method_name = self._extract_method_name(code, method_node) or "<unknown>"
            key = (http_method, full_path, controller_name, method_name)
            if key in seen:
                continue
            seen.add(key)
            idx = self._build_index_from_match(
                controller_file,
                code,
                class_node,
                method_node,
                method=http_method,
                path=full_path,
                max_depth=max_depth,
                max_chars=max_chars,
                max_files=max_files,
                include_service=include_service,
                include_wrappers=include_wrappers,
                include_db=include_db,
            )
            if idx:
                indices.append(idx)
        return indices


    def _build_index_from_match(
        self,
        controller_file: Path,
        code: str,
        class_node: Node,
        method_node: Node,
        *,
        method: str,
        path: str,
        max_depth: int,
        max_chars: int,
        max_files: int,
        include_service: bool,
        include_wrappers: bool,
        include_db: bool,
    ) -> EndpointIndex:
        controller_name = self._extract_class_name(code, class_node) or controller_file.stem
        method_name = self._extract_method_name(code, method_node) or "<unknown>"
        index = EndpointIndex(
            method=method,
            path=path,
            controller=controller_name,
            method_name=method_name,
        )

        used_keys: set[tuple[str, int, int]] = set()

        def try_add(snippet: CodeSnippet) -> None:
            key = (snippet.file, snippet.start_line, snippet.end_line)
            if key in used_keys:
                return
            if index.total_files >= max_files:
                index.truncated = True
                return
            if index.total_chars + len(snippet.code) > max_chars:
                index.truncated = True
                return
            index.snippets.append(snippet)
            used_keys.add(key)
            index.total_files = len({s.file for s in index.snippets})
            index.total_chars += len(snippet.code)

        ctx_snip = self._extract_controller_context(controller_file, code, class_node)
        if ctx_snip:
            try_add(ctx_snip)

        method_snip = self._extract_method_snippet(controller_file, code, method_node)
        if method_snip:
            try_add(method_snip)

        seed_types = []
        seed_types += self._extract_param_types(code, method_node)
        seed_types += self._extract_return_types(code, method_node)
        custom_types = self._filter_custom_types(seed_types, include_wrappers=include_wrappers)

        queue: list[tuple[str, int]] = [(t, 0) for t in custom_types]
        visited: set[str] = set()
        while queue:
            tname, depth = queue.pop(0)
            if tname in visited:
                continue
            visited.add(tname)
            class_file = self._find_java_file_for_type(tname)
            if not class_file:
                continue
            ccode = class_file.read_text(encoding="utf-8", errors="ignore")
            class_node = self._find_class_node(ccode, tname)
            if not class_node:
                continue
            class_snip = self._extract_class_snippet(class_file, ccode, class_node, tname)
            if class_snip:
                try_add(class_snip)
            if depth >= max_depth:
                continue
            field_types = self._extract_field_types_from_class(ccode, class_node)
            next_types = self._filter_custom_types(field_types, include_wrappers=include_wrappers)
            for nt in next_types:
                if nt not in visited:
                    queue.append((nt, depth + 1))

        if include_service:
            svc_snip = self._extract_service_signature_snippet(code, method_node, controller_file)
            if svc_snip:
                try_add(svc_snip)

        if include_db:
            for db_snip in self._extract_mybatis_snippets(code, method_node):
                try_add(db_snip)

        return index

    # -------- Endpoint matching --------
    def _find_endpoint(
        self, method: str, path: str
    ) -> Optional[tuple[Path, str, Node, Node]]:
        target_method = str(method).upper()
        target_path = self._norm_path(path)
        for java_file in self.java_files:
            code = java_file.read_text(encoding="utf-8", errors="ignore")
            tree = self.java_parser.parser.parse(code.encode("utf-8"))
            class_caps = self._query(tree.root_node, "(class_declaration) @c")
            for class_node in class_caps.get("c", []):
                if not self._is_controller(code, class_node):
                    continue
                bases = self._extract_class_base_paths(code, class_node)
                method_caps = self._query(class_node, "(method_declaration) @m")
                for method_node in method_caps.get("m", []):
                    mappings = self._extract_http_methods_and_paths(code, method_node)
                    for http_method, rel_path in mappings:
                        for base in bases:
                            full_path = self._build_full_path(base, rel_path)
                            if (
                                http_method == target_method
                                and self._norm_path(full_path) == target_path
                            ):
                                return java_file, code, class_node, method_node
        return None

    def _iter_endpoints(
        self,
    ) -> Iterable[tuple[Path, str, Node, Node, str, str]]:
        for java_file in self.java_files:
            code = java_file.read_text(encoding="utf-8", errors="ignore")
            tree = self.java_parser.parser.parse(code.encode("utf-8"))
            class_caps = self._query(tree.root_node, "(class_declaration) @c")
            for class_node in class_caps.get("c", []):
                if not self._is_controller(code, class_node):
                    continue
                bases = self._extract_class_base_paths(code, class_node)
                method_caps = self._query(class_node, "(method_declaration) @m")
                for method_node in method_caps.get("m", []):
                    mappings = self._extract_http_methods_and_paths(code, method_node)
                    for http_method, rel_path in mappings:
                        for base in bases:
                            full_path = self._build_full_path(base, rel_path)
                            yield java_file, code, class_node, method_node, http_method, full_path

    def _build_full_path(self, base: str, rel: str) -> str:
        full_path = (
            f"{base.rstrip('/')}/{rel.lstrip('/')}"
            if base and rel
            else (base or rel or "/")
        )
        return self._strip_colon_patterns(full_path)

    @staticmethod
    def _norm_path(path: str) -> str:
        p = path.strip()
        if p.startswith("/"):
            p = p[1:]
        return p

    def _is_controller(self, code: str, class_node: Node) -> bool:
        q = """
        (class_declaration
          (modifiers
            [
              (annotation name: [(identifier) @ann (scoped_identifier) @ann])
              (marker_annotation name: [(identifier) @ann (scoped_identifier) @ann])
            ]*
          )?
        ) @class
        """
        caps = self._query(class_node, q)
        anns = caps.get("ann", [])
        for n in anns:
            text = self.java_parser.extract_text_from_bytes(code, n.start_byte, n.end_byte)
            if text.endswith("Controller") or text.endswith("RestController"):
                return True
        return False

    def _extract_class_base_path(self, code: str, class_node: Node) -> str:
        paths = self._extract_class_base_paths(code, class_node)
        return paths[0] if paths else ""

    def _extract_class_base_paths(self, code: str, class_node: Node) -> list[str]:
        q = """
        (class_declaration (modifiers [ (annotation) @a (marker_annotation) @a ]*))
        """
        caps = self._query(class_node, q)
        for ann_node in caps.get("a", []):
            ann_text = self.indexer.extract_text(code, ann_node)
            if annotation_name(ann_text) != "RequestMapping":
                continue
            return string_values(ann_text, ("value", "path")) or [""]
        return [""]

    def _extract_annotation_name(self, code: str, ann_node: Node) -> Optional[str]:
        name_q = """
        [
            (annotation        name: [(identifier) (scoped_identifier)] @n)
            (marker_annotation name: [(identifier) (scoped_identifier)] @n)
        ]
        """
        caps = self._query(ann_node, name_q)
        if not caps.get("n"):
            return None
        return self.indexer.extract_text(code, caps["n"][0])

    def _extract_path_from_annotation(self, code: str, ann_node: Node) -> str:
        values = string_values(self.indexer.extract_text(code, ann_node), ("value", "path"))
        return values[0] if values else ""

    def _extract_method_from_request_mapping(self, code: str, ann_node: Node) -> Optional[str]:
        mappings = mapping_values(self.indexer.extract_text(code, ann_node))
        return mappings[0].method if mappings else None

    def _extract_http_method_and_path(
        self, code: str, method_node: Node
    ) -> Optional[tuple[str, str]]:
        mappings = self._extract_http_methods_and_paths(code, method_node)
        return mappings[0] if mappings else None

    def _extract_http_methods_and_paths(
        self, code: str, method_node: Node
    ) -> list[tuple[str, str]]:
        ann_query = "[ (annotation) @a (marker_annotation) @a ]"
        anns = self._query(method_node, ann_query).get("a", [])
        default_methods = default_methods_for_handler(
            self.indexer.extract_text(code, method_node)
        )
        for ann_node in anns:
            values = mapping_values(
                self.indexer.extract_text(code, ann_node), default_methods
            )
            if values:
                return [(mapping.method, mapping.path) for mapping in values]
        return []

    @staticmethod
    def _strip_colon_patterns(path: str) -> str:
        pattern = re.compile(r"\{([^}:]+):[^}]+\}")
        return pattern.sub(r"{\1}", path)

    # -------- Snippet extraction --------
    def _extract_method_snippet(
        self, file_path: Path, code: str, method_node: Node
    ) -> CodeSnippet:
        snippet = self.indexer.extract_method_code(code, method_node)
        start_line = self._line_no(code, method_node.start_byte)
        end_line = self._line_no(code, method_node.end_byte)
        return CodeSnippet(
            file=str(file_path),
            start_line=start_line,
            end_line=end_line,
            reason="endpoint method",
            code=snippet,
        )

    def _extract_controller_context(
        self, file_path: Path, code: str, class_node: Node
    ) -> Optional[CodeSnippet]:
        field_caps = self._query(class_node, "(field_declaration) @f")
        fields = field_caps.get("f", [])
        if not fields:
            return None
        start_byte = class_node.start_byte
        end_byte = max(n.end_byte for n in fields)
        snippet = code.encode("utf-8")[start_byte:end_byte].decode("utf-8", errors="ignore")
        return CodeSnippet(
            file=str(file_path),
            start_line=self._line_no(code, start_byte),
            end_line=self._line_no(code, end_byte),
            reason="controller context (fields)",
            code=snippet,
        )

    def _extract_class_snippet(
        self, file_path: Path, code: str, class_node: Node, type_name: str
    ) -> CodeSnippet:
        snippet = code.encode("utf-8")[class_node.start_byte:class_node.end_byte].decode(
            "utf-8", errors="ignore"
        )
        return CodeSnippet(
            file=str(file_path),
            start_line=self._line_no(code, class_node.start_byte),
            end_line=self._line_no(code, class_node.end_byte),
            reason=f"type: {type_name}",
            code=snippet,
        )

    def _extract_service_signature_snippet(
        self, controller_code: str, method_node: Node, controller_file: Path
    ) -> Optional[CodeSnippet]:
        method_code = self.indexer.extract_method_code(controller_code, method_node)
        call_m = re.search(r"(\w+)\.(\w+)\s*\(", method_code)
        if not call_m:
            return None
        var_name, method_name = call_m.group(1), call_m.group(2)
        field_types = self.indexer.parse_field_types(controller_code)
        service_type = field_types.get(var_name)
        if not service_type:
            return None
        svc_file = self._find_java_file_for_type(service_type)
        if not svc_file:
            return None
        svc_code = svc_file.read_text(encoding="utf-8", errors="ignore")
        sig = self._find_method_signature(svc_code, method_name)
        if not sig:
            return None
        start_byte, end_byte = sig
        snippet = svc_code.encode("utf-8")[start_byte:end_byte].decode("utf-8", errors="ignore")
        return CodeSnippet(
            file=str(svc_file),
            start_line=self._line_no(svc_code, start_byte),
            end_line=self._line_no(svc_code, end_byte),
            reason=f"service signature: {service_type}.{method_name}",
            code=snippet,
        )

    def _find_method_signature(self, code: str, method_name: str) -> Optional[tuple[int, int]]:
        # Match single-line signatures or start of multi-line signatures
        pattern = re.compile(
            r"(?m)^[ \t]*(public|protected|private|default|static)?[^{;\\n]*\\b"
            + re.escape(method_name)
            + r"\\s*\\([^;{]*\\)"
        )
        m = pattern.search(code)
        if not m:
            return None
        start = m.start()
        end = m.end()
        # extend to line end
        line_end = code.find("\n", end)
        if line_end != -1:
            end = line_end
        return start, end

    def _extract_mybatis_snippets(
        self, controller_code: str, method_node: Node
    ) -> list[CodeSnippet]:
        self._ensure_mybatis_analyzer()
        if not self._mybatis_analyzer:
            return []
        snippets: list[CodeSnippet] = []
        method_code = self.indexer.extract_method_code(controller_code, method_node)
        call_iter = list(re.finditer(r"(\w+)\.(\w+)\s*\(", method_code))
        if not call_iter:
            return snippets
        controller_fields = self.indexer.parse_field_types(controller_code)

        for call in call_iter:
            svc_var, svc_method = call.group(1), call.group(2)
            service_type = controller_fields.get(svc_var)
            if not service_type:
                continue
            impl_name = service_type if service_type.endswith("Impl") else service_type + "Impl"
            impl_file = self.indexer.find_java_file_by_class(impl_name)
            if not impl_file:
                continue
            impl_code = impl_file.read_text(encoding="utf-8", errors="ignore")

            impl_method_node = self._find_method_node_by_name(impl_code, svc_method)
            if impl_method_node:
                impl_snip = CodeSnippet(
                    file=str(impl_file),
                    start_line=self._line_no(impl_code, impl_method_node.start_byte),
                    end_line=self._line_no(impl_code, impl_method_node.end_byte),
                    reason=f"service impl method: {impl_name}.{svc_method}",
                    code=self.indexer.extract_method_code(impl_code, impl_method_node),
                )
                snippets.append(impl_snip)

            impl_body = (
                self.indexer.extract_method_code(impl_code, impl_method_node)
                if impl_method_node
                else impl_code
            )
            dao_call = re.search(r"(\w+)\.(\w+)\s*\(", impl_body)
            if not dao_call:
                continue
            dao_var, dao_method = dao_call.group(1), dao_call.group(2)
            dao_type = self.indexer.parse_field_types(impl_code).get(dao_var)
            if not dao_type:
                continue

            dao_file = self.indexer.find_java_file_by_class(dao_type)
            if dao_file:
                dao_code = dao_file.read_text(encoding="utf-8", errors="ignore")
                sig = self._find_method_signature(dao_code, dao_method)
                if sig:
                    start_byte, end_byte = sig
                    dao_snip = CodeSnippet(
                        file=str(dao_file),
                        start_line=self._line_no(dao_code, start_byte),
                        end_line=self._line_no(dao_code, end_byte),
                        reason=f"mapper signature: {dao_type}.{dao_method}",
                        code=dao_code.encode("utf-8")[start_byte:end_byte].decode(
                            "utf-8", errors="ignore"
                        ),
                    )
                    snippets.append(dao_snip)

            namespace = self._resolve_namespace(impl_code, dao_type)
            if not namespace:
                continue
            mapper = self._mybatis_analyzer.mappers.get(namespace)
            if not mapper:
                continue
            op = mapper.operations.get(dao_method)
            if not op or not getattr(op, "xml_text", None):
                continue
            xml_path = Path(mapper.file_path)
            if not xml_path.exists():
                continue
            xml_code = xml_path.read_text(encoding="utf-8", errors="ignore")
            start_line, end_line, xml_snippet = self._find_xml_snippet(
                xml_code, op.xml_text
            )
            if xml_snippet:
                snippets.append(
                    CodeSnippet(
                        file=str(xml_path),
                        start_line=start_line,
                        end_line=end_line,
                        reason=f"mybatis xml: {namespace}.{dao_method}",
                        code=xml_snippet,
                    )
                )
        return snippets

    def _find_method_node_by_name(self, code: str, method_name: str) -> Optional[Node]:
        tree = self.java_parser.parser.parse(code.encode("utf-8"))
        q = """
        (method_declaration name: (identifier) @n) @m
        """
        caps = self._query(tree.root_node, q)
        for name_node, method_node in zip(caps.get("n", []), caps.get("m", [])):
            name = self.java_parser.extract_text_from_bytes(
                code, name_node.start_byte, name_node.end_byte
            )
            if name == method_name:
                return method_node
        return None

    def _resolve_namespace(self, impl_code: str, dao_type: str) -> Optional[str]:
        pkg, imports = self.indexer.parse_imports_and_package(impl_code)
        if dao_type in imports:
            return imports[dao_type]
        if pkg:
            return f"{pkg}.{dao_type}"
        return dao_type

    def _find_xml_snippet(
        self, xml_code: str, xml_text: str
    ) -> tuple[int, int, str]:
        idx = xml_code.find(xml_text)
        if idx == -1:
            # fallback: try normalize whitespace
            compact_xml = re.sub(r"\s+", " ", xml_text.strip())
            compact_code = re.sub(r"\s+", " ", xml_code)
            cidx = compact_code.find(compact_xml)
            if cidx == -1:
                return 1, 1, ""
            # approximate by using compact index as byte position
            idx = cidx
        start_line = xml_code[:idx].count("\n") + 1
        end_line = xml_code[: idx + len(xml_text)].count("\n") + 1
        return start_line, end_line, xml_text

    def _ensure_mybatis_analyzer(self) -> None:
        if self._mybatis_analyzer is not None:
            return
        try:
            from code_analyzer.java.mybatis_analyzer import MyBatisAnalyzer
        except Exception:
            self._mybatis_analyzer = None
            return
        analyzer = MyBatisAnalyzer()
        analyzer.analyze_project_roots(self._index_roots)
        self._mybatis_analyzer = analyzer

    # -------- Type extraction --------
    def _extract_param_types(self, code: str, method_node: Node) -> list[str]:
        types: list[str] = []
        param_query = """
        (method_declaration parameters: (formal_parameters (formal_parameter) @p))
        """
        param_caps = self._query(method_node, param_query)
        for param_node in param_caps.get("p", []):
            q = """
            (formal_parameter
              type: (_) @t
              name: (identifier) @n)
            """
            caps = self._query(param_node, q)
            param_type = caps.get("t", [])
            if not param_type:
                continue
            t = self.java_parser.extract_text_from_bytes(
                code, param_type[0].start_byte, param_type[0].end_byte
            )
            if t:
                types.append(t)
        return types

    def _extract_return_types(self, code: str, method_node: Node) -> list[str]:
        rtq = "(method_declaration type: (_) @t)"
        rcaps = self._query(method_node, rtq)
        if not rcaps.get("t"):
            return []
        tnode = rcaps["t"][0]
        rt = self.java_parser.extract_text_from_bytes(code, tnode.start_byte, tnode.end_byte)
        return [rt] if rt else []

    def _filter_custom_types(
        self, type_strs: Iterable[str], *, include_wrappers: bool
    ) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for t in type_strs:
            for ident in self._extract_identifiers(t):
                if ident in seen:
                    continue
                if ident in BASIC_TYPES or ident in PRIMITIVE_TYPES:
                    continue
                if ident in COLLECTION_TYPES:
                    continue
                if ident in WRAPPER_TYPES and not include_wrappers:
                    continue
                # Likely custom class
                seen.add(ident)
                out.append(ident)
        return out

    @staticmethod
    def _extract_identifiers(type_str: str) -> list[str]:
        return re.findall(r"[A-Za-z_][\w$]*", type_str or "")

    def _find_java_file_for_type(self, type_name: str) -> Optional[Path]:
        # use parser index first
        jc = self.indexer.resolve_class_by_type(type_name)
        if jc and jc.file_path:
            return Path(jc.file_path)
        return self.indexer.find_java_file_by_class(type_name)

    def _find_class_node(self, code: str, class_name: str) -> Optional[Node]:
        tree = self.java_parser.parser.parse(code.encode("utf-8"))
        q = """
        (class_declaration name: (identifier) @class_name) @c
        """
        caps = self._query(tree.root_node, q)
        for name_node, class_node in zip(caps.get("class_name", []), caps.get("c", [])):
            name = self.java_parser.extract_text_from_bytes(
                code, name_node.start_byte, name_node.end_byte
            )
            if name == class_name:
                return class_node
        # try enum
        q_enum = """
        (enum_declaration name: (identifier) @enum_name) @e
        """
        caps = self._query(tree.root_node, q_enum)
        for name_node, enum_node in zip(caps.get("enum_name", []), caps.get("e", [])):
            name = self.java_parser.extract_text_from_bytes(
                code, name_node.start_byte, name_node.end_byte
            )
            if name == class_name:
                return enum_node
        return None

    def _extract_field_types_from_class(self, code: str, class_node: Node) -> list[str]:
        field_query = """
        (field_declaration
          type: (_) @field_type
        )
        """
        caps = self._query(class_node, field_query)
        field_types = []
        for tnode in caps.get("field_type", []):
            t = self.java_parser.extract_text_from_bytes(code, tnode.start_byte, tnode.end_byte)
            if t:
                field_types.append(t)
        return field_types

    def _extract_class_name(self, code: str, class_node: Node) -> Optional[str]:
        q = "(class_declaration name: (identifier) @n)"
        caps = self._query(class_node, q)
        if not caps.get("n"):
            return None
        node = caps["n"][0]
        return self.java_parser.extract_text_from_bytes(code, node.start_byte, node.end_byte)

    def _extract_method_name(self, code: str, method_node: Node) -> Optional[str]:
        q = "(method_declaration name: (identifier) @n)"
        caps = self._query(method_node, q)
        if not caps.get("n"):
            return None
        node = caps["n"][0]
        return self.java_parser.extract_text_from_bytes(code, node.start_byte, node.end_byte)

    def _query(self, node: Node, q: str) -> dict[str, list[Node]]:
        return self.java_parser.language.query(q).captures(node)

    @staticmethod
    def _line_no(code: str, byte_index: int) -> int:
        return code.encode("utf-8")[:byte_index].decode("utf-8", errors="ignore").count("\n") + 1


class EndpointCodeContextProvider:
    """
    Lazy code context provider for LLM prompts.
    Caches code blobs per endpoint to avoid repeated scans.
    """

    def __init__(
        self,
        indexer: EndpointCodeIndexer,
        *,
        max_depth: int = 2,
        max_chars: int = 20000,
        max_files: int = 12,
        include_service: bool = True,
        include_wrappers: bool = True,
        include_db: bool = True,
    ):
        self.indexer = indexer
        self.max_depth = max_depth
        self.max_chars = max_chars
        self.max_files = max_files
        self.include_service = include_service
        self.include_wrappers = include_wrappers
        self.include_db = include_db
        self._cache: dict[tuple[str, str], Optional[str]] = {}

    def get_code_blob(self, method: str, path: str) -> Optional[str]:
        key = (str(method).upper(), str(path))
        if key in self._cache:
            return self._cache[key]
        idx = self.indexer.build_index(
            key[0],
            key[1],
            max_depth=self.max_depth,
            max_chars=self.max_chars,
            max_files=self.max_files,
            include_service=self.include_service,
            include_wrappers=self.include_wrappers,
            include_db=self.include_db,
        )
        if not idx:
            self._cache[key] = None
            return None
        blob = self.render_code_blob(idx)
        self._cache[key] = blob
        return blob

    @staticmethod
    def render_code_blob(index: EndpointIndex) -> str:
        parts: list[str] = []
        for snip in index.snippets:
            parts.append(
                f"[FILE] {snip.file}#L{snip.start_line}-L{snip.end_line} ({snip.reason})"
            )
            parts.append(snip.code)
            if not snip.code.endswith("\n"):
                parts.append("")
        return "\n".join(parts).strip()
