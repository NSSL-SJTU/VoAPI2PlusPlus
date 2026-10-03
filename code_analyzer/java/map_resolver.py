#!/usr/bin/env python3
"""
Resolve Map<String,Object> parameters via MyBatis mapper and Query constructor patterns.
"""

from __future__ import annotations

import re
from typing import Optional

from models.types import ParamType
from code_analyzer.java.type_utils import map_java_type
from code_analyzer.java.mybatis_analyzer import MyBatisAnalyzer
from code_analyzer.java.indexer import JavaIndexer
from tree_sitter import Node


class MapResolver:

    def __init__(self, mybatis: MyBatisAnalyzer, indexer: JavaIndexer):
        self.mybatis = mybatis
        self.indexer = indexer

    def infer_from_mybatis(
        self, dao_namespace: str, method_name: str
    ) -> dict[str, tuple[ParamType, list, list]]:
        mapper = self.mybatis.mappers.get(dao_namespace)
        if not mapper:
            return {}
        op = mapper.operations.get(method_name)
        if not op:
            return {}
        ans: dict[str, tuple[ParamType, list, list]] = {}
        for p in op.parameters:
            ptype, ex, dft = map_java_type("String", p.param_name)
            lname = p.param_name.lower()
            if lname in {"offset", "limit", "page"}:
                ptype, ex, dft = map_java_type("Integer", p.param_name)
            if lname in {"sort", "order"}:
                ptype, ex, dft = map_java_type("String", p.param_name)
            ans[p.param_name] = (ptype, ex, dft)
        return ans

    def resolve_service_to_dao(
        self, controller_code: str, method_node: Node, param_name: str
    ) -> dict[str, tuple[ParamType, list, list]]:
        method_code = self.indexer.extract_method_code(controller_code, method_node)
        # service.method(param_name)
        call_m = re.search(r"(\w+)\.(\w+)\s*\(\s*" + re.escape(param_name) + r"\s*\)", method_code)
        if not call_m:
            # fallback: allow renamed arg
            call_m = re.search(r"(\w+)\.(\w+)\s*\(\s*\w+\s*\)", method_code)
        if not call_m:
            return {}
        service_var, service_method = call_m.group(1), call_m.group(2)
        fields = self.indexer.parse_field_types(controller_code)
        service_type = fields.get(service_var)
        if not service_type:
            return {}
        impl_name = service_type + "Impl" if not service_type.endswith("Impl") else service_type
        impl_file = self.indexer.find_java_file_by_class(impl_name)
        if not impl_file:
            return {}
        impl_code = impl_file.read_text(encoding="utf-8", errors="ignore")
        meth_pat = re.compile(
            r"(public|protected|private)\s+\w+[\<\>\w\[\]\s,]*\s+"
            + re.escape(service_method)
            + r"\s*\(.*?\)\s*\{",
            re.DOTALL,
        )
        mm = meth_pat.search(impl_code)
        impl_body = impl_code[mm.start() :] if mm else impl_code
        dao_call = re.search(
            r"(\w+)\.(\w+)\s*\(\s*" + re.escape(param_name) + r"\s*\)", impl_body
        ) or re.search(r"(\w+)\.(list|count)\s*\(\s*\w+\s*\)", impl_body)
        if not dao_call:
            return {}
        dao_var, dao_method = dao_call.group(1), dao_call.group(2)
        dao_type = self.indexer.parse_field_types(impl_code).get(dao_var)
        if not dao_type:
            return {}
        pkg, imports = self.indexer.parse_imports_and_package(impl_code)
        namespace = imports.get(dao_type, f"{pkg}.{dao_type}" if pkg else dao_type)
        return self.infer_from_mybatis(namespace, dao_method)

    def augment_with_query_constructor(
        self, controller_code: str, method_node: Node, map_param_name: str
    ) -> dict[str, tuple[ParamType, list, list, bool]]:
        """Read Query constructor to infer pagination keys and required flags.
        Returns mapping: name -> (ParamType, examples, defaults, is_required)
        """
        mcode = self.indexer.extract_method_code(controller_code, method_node)
        # accept any variable passed to Query(...)
        if not re.search(r"new\s+Query\s*\(\s*\w+\s*\)", mcode):
            return {}
        qfile = self.indexer.find_java_file_by_class("Query")
        if not qfile:
            return {}
        qcode = qfile.read_text(encoding="utf-8", errors="ignore")
        keys: set[str] = set()
        required_keys: set[str] = set()
        # params.get("k") usage -> required
        for pat in [
            r'Integer\.parseInt\([^)]*params\.get\("([^"]+)"\)',
            r'Long\.parseLong\([^)]*params\.get\("([^"]+)"\)',
            r'Double\.parseDouble\([^)]*params\.get\("([^"]+)"\)',
            r'params\.get\("([^"]+)"\)\.toString\(\)',
            r'params\.get\("([^"]+)"\)',
        ]:
            for mm in re.finditer(pat, qcode):
                if mm.group(1):
                    k = mm.group(1)
                    keys.add(k)
                    required_keys.add(k)
        # A key the constructor writes back (`this.put("page", offset / limit + 1)`) is
        # derived server side: a client that sends it has the value overwritten, so it is
        # not a request parameter. Only the keys read off `params` above count.
        out: dict[str, tuple[ParamType, list, list, bool]] = {}
        # Ensure offset/limit present; page not required
        all_keys = keys | {"offset", "limit"}
        for k in all_keys:
            base_type = "Integer" if k in {"offset", "limit", "page"} else "String"
            p, ex, d = map_java_type(base_type, k)
            is_required = (k in required_keys) and (k != "page")
            out[k] = (p, ex, d, is_required)
        return out
