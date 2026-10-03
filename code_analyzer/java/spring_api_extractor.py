#!/usr/bin/env python3
"""
Extract Spring MVC endpoints and produce APIModel instances using the
code_analyzer Java parsers and MyBatis analyzer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, cast
from pathlib import Path
import re
from tree_sitter import Node
from code_analyzer.java.java_parser import JavaParser
from code_analyzer.java.mybatis_analyzer import MyBatisAnalyzer
from code_analyzer.java.type_utils import map_java_type
from code_analyzer.java.indexer import JavaIndexer
from code_analyzer.java.param_resolver import ParamResolver
from code_analyzer.java.map_resolver import MapResolver
from code_analyzer.java.response_builder import ResponseBuilder
from code_analyzer.java.type_utils import BASIC_TYPES
from code_analyzer.java.project_roots import collect_java_files, index_roots
from code_analyzer.java.spring_annotations import (
    annotation_name,
    bool_value,
    default_methods_for_handler,
    mapping_values,
    string_values,
)

from models.structure import RequestStructure, ResponseStructure
from models.parameter import BasicParameter, PropertyParameter, Parameter, ArrayParameter
from models.types import ParamType
from models.api_model import APIModel
import logging


logger = logging.getLogger(__name__)

# Argument types a Spring resolver assembles from request parameters it names itself.
# Keyed by simple type name; the declared parameter name is irrelevant to the wire.
RESOLVER_WIRE_PARAMS: dict[str, tuple[tuple[str, str], ...]] = {
    "Pageable": (("page", "Integer"), ("size", "Integer"), ("sort", "String")),
    "Sort": (("sort", "String"),),
}


@dataclass
class EndpointParam:
    name: str
    java_type: str
    location: str  # path|query|header|body
    is_required: bool = False
    context_code: Optional[str] = None


class SpringApiExtractor:

    def __init__(self, project_path: str):
        self.java_parser = JavaParser()
        self.mybatis_analyzer = MyBatisAnalyzer()
        self.project_path: Path = Path(project_path)
        self._index_roots = index_roots(self.project_path)
        self.mybatis_analyzer.analyze_project_roots(self._index_roots)
        self._java_files: list[Path] = collect_java_files(self._index_roots)
        logger.info(f"Found {len(self._java_files)} Java files")
        self.indexer = JavaIndexer(self.java_parser, self.project_path, self._java_files)
        self.param_resolver = ParamResolver(self.indexer)
        self.map_resolver = MapResolver(self.mybatis_analyzer, self.indexer)
        self.response_builder = ResponseBuilder(self.indexer)

    def _is_framework_param_type(self, java_type: str) -> bool:
        base = java_type.strip().split("<", 1)[0].split(".")[-1]
        return base in {
            "HttpServletRequest",
            "HttpServletResponse",
            "ServletRequest",
            "ServletResponse",
            "Model",
            "ModelMap",
            "BindingResult",
            "Principal",
            "Authentication",
            "HttpSession",
            # Supplied by the container rather than bound from the request. Keeping this
            # list short left them looking like ordinary parameters once unflattenable
            # types stopped being discarded.
            "RedirectAttributes",
            "SessionStatus",
            "UriComponentsBuilder",
            "Errors",
            "Locale",
            "TimeZone",
            "ZoneId",
            "WebRequest",
            "NativeWebRequest",
            "ServletContext",
            "HttpMethod",
            "MultipartHttpServletRequest",
            "InputStream",
            "OutputStream",
            "Reader",
            "Writer",
        }

    def build_api_model(
        self,
        http_method: str,
        path: str,
        params: List[EndpointParam],
    ) -> APIModel:
        logger.info(f"Building API model for {http_method} {path}")
        # Build request structure
        req = RequestStructure()

        for p in params:
            ptype, examples, defaults = map_java_type(p.java_type, p.name)
            if ptype in {ParamType.OBJECT} and p.location in {"query"}:
                # flattening object into query: leave as empty for now
                req.query[p.name] = PropertyParameter(p.name, properties={})
                continue

            if p.location == "body":
                basic_types = BASIC_TYPES | {"MultipartFile"}
                jt = p.java_type.strip()
                raw_jt = self.indexer.simple_type_name(jt)
                if not (
                    raw_jt in basic_types
                    or raw_jt in {"Map", "HashMap", "List", "Set", "Collection", "Iterable"}
                ):
                    flat = self.param_resolver.flatten_object_param(jt, p.context_code)
                    if flat:
                        props = cast(dict[str, Parameter], flat)
                        for k, v in props.items():
                            req.body[k] = v
                        continue

            # Arrays should be represented as ArrayParameter, not BasicParameter
            if ptype == ParamType.ARRAY:
                # best-effort: use STRING item for now, except for file arrays
                # (MultipartFile[] / List<MultipartFile>), whose items are files
                elem_jt = p.java_type.strip()
                if elem_jt.endswith("[]"):
                    elem_jt = elem_jt[:-2]
                elif "<" in elem_jt:
                    elem_jt = elem_jt.split("<", 1)[1].rsplit(">", 1)[0]
                item_type = (
                    ParamType.FILE
                    if self.indexer.simple_type_name(elem_jt) == "MultipartFile"
                    else ParamType.STRING
                )
                item = BasicParameter(
                    p.name + "Item", item_type
                )
                arr = ArrayParameter(p.name, item=item, is_required=p.is_required)
                if p.location == "path":
                    req.path[p.name] = arr
                elif p.location == "header":
                    req.header[p.name] = arr
                elif p.location == "query":
                    req.query[p.name] = arr
                else:
                    req.body[p.name] = arr
                continue

            param = BasicParameter(
                p.name, ptype, example=examples, default=defaults, is_required=p.is_required
            )
            if p.location == "path":
                req.path[p.name] = param
            elif p.location == "header":
                req.header[p.name] = param
            elif p.location == "query":
                req.query[p.name] = param
            else:
                req.body[p.name] = param

        # Minimal response structure placeholder
        resp = ResponseStructure()

        return APIModel(
            api_url=path,
            api_method=http_method,
            request_structure=req,
            response_structure=resp,
        )

    # -------- Controller scanning and APIModel building --------
    def _query(self, node: Node, q: str) -> dict[str, list[Node]]:
        return self.java_parser.language.query(q).captures(node)

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
        caps = self.indexer.query(class_node, q)
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
        caps = self.indexer.query(class_node, q)
        for ann_node in caps.get("a", []):
            ann_text = self.indexer.extract_text(code, ann_node)
            if annotation_name(ann_text) != "RequestMapping":
                continue
            paths = string_values(ann_text, ("value", "path")) or [""]
            for path in paths:
                logger.info("Extracted base path: %s", path)
            return paths
        return [""]

    def _extract_annotation_name(self, code: str, ann_node: Node) -> Optional[str]:
        """Extract annotation name from annotation node."""
        name_q = """
        [
            (annotation        name: [(identifier) (scoped_identifier)] @n)
            (marker_annotation name: [(identifier) (scoped_identifier)] @n)
        ]
        """
        caps = self.indexer.query(ann_node, name_q)
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
        if not mappings:
            return None
        return mappings[0]

    def _extract_http_methods_and_paths(
        self, code: str, method_node: Node
    ) -> list[tuple[str, str]]:
        """Extract Spring method mappings, including array paths/methods."""
        ann_query = "[ (annotation) @a (marker_annotation) @a ]"
        anns = self.indexer.query(method_node, ann_query).get("a", [])
        default_methods = default_methods_for_handler(
            self.indexer.extract_text(code, method_node)
        )
        for ann_node in anns:
            values = mapping_values(
                self.indexer.extract_text(code, ann_node), default_methods
            )
            if not values:
                continue
            return [(mapping.method, mapping.path) for mapping in values]
        return []


    def _strip_colon_patterns(self, path: str) -> str:
        pattern = re.compile(r"\{([^}:]+):[^}]+\}")
        return pattern.sub(r"{\1}", path)


    def _analyze_method_to_api(
        self,
        code: str,
        class_base: str,
        method_node: Node,
        controller_code: str,
        http_method_and_path: Optional[tuple[str, str]] = None,
    ) -> Optional[APIModel]:
        http_method_and_path = http_method_and_path or self._extract_http_method_and_path(
            code, method_node
        )
        if not http_method_and_path:
            return None
        http_method, rel_path = http_method_and_path
        logger.info(f"Extracted HTTP method and path: {http_method} {rel_path}")
        full_path = (
            f"{class_base.rstrip('/')}/{rel_path.lstrip('/')}"
            if class_base and rel_path
            else (class_base or rel_path or "/")
        )
        full_path = self._strip_colon_patterns(full_path)
        # parameters
        params: List[EndpointParam] = []
        implicit_form_body = False
        param_query = """
        (method_declaration parameters: (formal_parameters (formal_parameter) @p))
        """
        param_caps = self.indexer.query(method_node, param_query)
        for param_node in param_caps.get("p", []):
            # type, name, annotations
            q = """
            (formal_parameter
              (modifiers [ (annotation) @a (marker_annotation) @a ]*)?
              type: (_) @t
              name: (identifier) @n)
            """
            caps = self.indexer.query(param_node, q)
            param_type = caps.get("t", [])
            param_name = caps.get("n", [])
            ann_nodes = caps.get("a", [])
            if not param_type or not param_name:
                continue
            ptype = self.java_parser.extract_text_from_bytes(code, param_type[0].start_byte, param_type[0].end_byte)
            pname = self.java_parser.extract_text_from_bytes(code, param_name[0].start_byte, param_name[0].end_byte)
            if self._is_framework_param_type(ptype):
                continue
            ann_text = " ".join(
                self.java_parser.extract_text_from_bytes(code, a.start_byte, a.end_byte)
                for a in ann_nodes
            )
            location = self.param_resolver.determine_location(ann_text, ptype, http_method)
            simple_ptype = self.indexer.simple_type_name(ptype)
            # Spring resolves a few argument types from query parameters whose names have
            # nothing to do with the declared parameter: a Pageable is assembled from
            # page/size/sort, so modeling it as one parameter named "pageable" would invent
            # a parameter the server never reads. The resolver reads the query string for
            # every request method, so this runs before the method-specific branches.
            wire_params = RESOLVER_WIRE_PARAMS.get(simple_ptype)
            if wire_params:
                for wire_name, wire_type in wire_params:
                    if not any(ep.name == wire_name for ep in params):
                        params.append(
                            EndpointParam(
                                name=wire_name,
                                java_type=wire_type,
                                location="query",
                                is_required=False,
                            )
                        )
                continue
            if (
                http_method not in {"GET", "DELETE"}
                and location == "body"
                and "RequestBody" not in ann_text
                and simple_ptype != "MultipartFile"
            ):
                implicit_form_body = True
            
            # Find Spring binding annotation node for name/default/required extraction.
            binding_param_node = None
            for ann_node in ann_nodes:
                ann_name = self._extract_annotation_name(code, ann_node)
                if ann_name in {"RequestParam", "PathVariable", "RequestHeader"}:
                    binding_param_node = ann_node
                    break
            
            alt_name = pname
            default_value = None
            required_value = None
            if binding_param_node:
                binding_text = self.indexer.extract_text(code, binding_param_node)
                extracted = string_values(binding_text, ("value", "name"))
                extracted_name = extracted[0] if extracted else None
                if extracted_name:
                    alt_name = extracted_name
                default_values = string_values(binding_text, ("defaultValue",))
                default_value = default_values[0] if default_values else None
                required_value = bool_value(binding_text, "required")
            is_required = default_value is None and required_value is not False

            # Map<String,Object> params expansion via MyBatis + Query constructor
            if simple_ptype in {"Map", "HashMap"}:
                mb = self.map_resolver.resolve_service_to_dao(controller_code, method_node, pname)
                qk = self.map_resolver.augment_with_query_constructor(
                    controller_code, method_node, pname
                )
                if mb:
                    for k, (pt, _ex, _def) in mb.items():
                        params.append(
                            EndpointParam(
                                name=k,
                                java_type=self.param_resolver.paramtype_to_java(pt),
                                location="query",
                                is_required=False,
                            )
                        )
                if qk:
                    for k, v in qk.items():
                        pt, _ex, _def, req_flag = v
                        # if already exists (e.g., added by MyBatis), update is_required/java_type
                        found = False
                        for ep in params:
                            if ep.name == k and ep.location == "query":
                                found = True
                                if req_flag:
                                    ep.is_required = True
                                # prefer Integer for pagination keys
                                new_jt = self.param_resolver.paramtype_to_java(pt)
                                ep.java_type = new_jt
                                break
                        if not found:
                            params.append(
                                EndpointParam(
                                    name=k,
                                    java_type=self.param_resolver.paramtype_to_java(pt),
                                    location="query",
                                    is_required=bool(req_flag),
                                )
                            )
                # A Map carries no declared keys, so fall back to the common pagination
                # names only when neither the mapper nor the Query constructor told us
                # what this endpoint actually reads. Adding them on top of resolved keys
                # invents parameters the application never looks at.
                if not mb and not qk:
                    for k in ["offset", "limit", "page", "sort", "order"]:
                        if not any(ep.name == k for ep in params):
                            jt = "Integer" if k in {"offset", "limit", "page"} else "String"
                            params.append(
                                EndpointParam(
                                    name=k, java_type=jt, location="query", is_required=False
                                )
                            )
                continue

            # Custom object flattening. @RequestBody names the location outright, so
            # it outranks the GET/DELETE heuristic -- flattening a declared body into
            # query drops collection payloads entirely, since they have no fields.
            if not (simple_ptype in {"Map", "HashMap"} or simple_ptype in (BASIC_TYPES | {"MultipartFile"})):
                if http_method in {"GET", "DELETE"} and "RequestBody" not in ann_text:
                    flat = self.param_resolver.flatten_object_param(ptype, controller_code)
                    # An empty result means "this type is not a command object" -- an enum,
                    # or a type declared outside the project -- not "this parameter does not
                    # exist". Fall through so the parameter is kept as itself.
                    if flat:
                        for fk, fp in flat.items():
                            params.append(
                                EndpointParam(
                                    name=fk,
                                    java_type=self.param_resolver.paramtype_to_java(fp.param_type),
                                    location="query",
                                    is_required=False,
                                )
                            )
                        continue

            params.append(
                EndpointParam(
                    name=alt_name,
                    java_type=ptype,
                    location=location,
                    is_required=is_required,
                    context_code=controller_code,
                )
            )

        # Build model
        api = self.build_api_model(http_method, full_path, params)

        # consumes/produces -> headers
        # parse consumes/produces from annotation again
        aq = """
        (annotation name: (identifier) @n) @a
        """
        acaps = self.indexer.query(method_node, aq)
        for a in acaps.get("a", []):
            ann_text = self.indexer.extract_text(code, a)
            m = re.search(r'consumes\s*=\s*"([^"]+)"', ann_text)
            if m:
                val = m.group(1)
                api.request_structure.header["Content-Type"] = BasicParameter(
                    "Content-Type", ParamType.STRING, example=[val], default=[]
                )
            m = re.search(r'produces\s*=\s*"([^"]+)"', ann_text)
            if m:
                val = m.group(1)
                api.request_structure.header["Accept"] = BasicParameter(
                    "Accept", ParamType.STRING, example=[val], default=[]
                )

        if implicit_form_body and "Content-Type" not in api.request_structure.header:
            api.request_structure.header["Content-Type"] = BasicParameter(
                "Content-Type",
                ParamType.STRING,
                example=["application/x-www-form-urlencoded"],
                default=[],
            )

        # response structure from return type (shallow)
        rtq = "(method_declaration type: (_) @t)"
        rcaps = self.indexer.query(method_node, rtq)
        if rcaps.get("t"):
            rt = self.java_parser.extract_text_from_bytes(
                code, rcaps["t"][0].start_byte, rcaps["t"][0].end_byte
            )
            self.indexer.index_java_types()
            self.response_builder.fill_response_from_return_type(
                api.response_structure, rt, controller_code
            )

        return api

    def analyze_controller_file(self, file_path: str) -> List[APIModel]:
        code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        tree = self.java_parser.parser.parse(code.encode("utf-8"))
        # find classes
        class_query = """
        (class_declaration) @c
        """
        class_caps = self._query(tree.root_node, class_query)
        apis: List[APIModel] = []
        for class_node in class_caps.get("c", []):
            if not self._is_controller(code, class_node):
                continue
            bases = self._extract_class_base_paths(code, class_node)
            # methods
            method_query = "(method_declaration) @m"
            method_caps = self._query(class_node, method_query)
            for method_node in method_caps.get("m", []):
                mappings = self._extract_http_methods_and_paths(code, method_node)
                for base in bases:
                    for mapping in mappings:
                        api = self._analyze_method_to_api(
                            code, base, method_node, code, mapping
                        )
                        if api:
                            apis.append(api)
        return apis

    def scan_project(self, project_path: Optional[str] = None) -> List[APIModel]:
        root = Path(project_path) if project_path else (self.project_path or Path("."))
        self.indexer.index_java_types()
        api_models: List[APIModel] = []
        for java_file in root.rglob("*.java"):
            # logger.info(f"Analyzing {java_file}")
            try:
                api_models.extend(self.analyze_controller_file(str(java_file)))
            except (OSError, UnicodeDecodeError):
                continue
        return api_models
