#!/usr/bin/env python3
"""Endpoint code context for Go projects.

Every Go target in the benchmark ships without an OpenAPI spec, so this is what
feeds endpoint source to payload generation and to vulnerability retries -- the
Go counterpart of code_analyzer/java/endpoint_indexer.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tree_sitter import Node

from code_analyzer.go.api_extractor import GoApiExtractor, GoRoute, normalize_route_path
from code_analyzer.go.parser import GoParser, iter_nodes, node_text


logger = logging.getLogger(__name__)


@dataclass
class GoEndpointIndex:
    route: GoRoute
    handler_source: Optional[str] = None
    declarations: list[str] = field(default_factory=list)


class GoEndpointCodeIndexer:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.parser = GoParser()
        self._index: dict[tuple[str, str], GoEndpointIndex] = {}
        self._functions: dict[str, str] = {}
        self._built = False

    def build(self) -> None:
        if self._built:
            return
        self._built = True
        for go_file in sorted(self.project_path.rglob("*.go")):
            if go_file.name.endswith("_test.go"):
                continue
            try:
                code = go_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            tree = self.parser.parse(code)
            self._collect_functions(tree.root_node)
        for route in GoApiExtractor(str(self.project_path)).collect_routes():
            url, _ = normalize_route_path(route.path)
            key = (route.method.upper(), url)
            self._index[key] = GoEndpointIndex(
                route=route,
                handler_source=self._functions.get(_handler_name(route.handler)),
            )

    def _collect_functions(self, root: Node) -> None:
        for node in iter_nodes(root):
            if node.type not in ("function_declaration", "method_declaration"):
                continue
            name = node.child_by_field_name("name")
            if name is None:
                continue
            self._functions[node_text(name)] = node_text(node)

    def lookup(self, method: str, path: str) -> Optional[GoEndpointIndex]:
        self.build()
        return self._index.get((method.upper(), path))


def _handler_name(handler: str) -> str:
    """``controllers.GetBasket`` and ``GetBasket`` name the same function."""
    return handler.strip().split(".")[-1]


@dataclass
class GoEndpointCodeContextProvider:
    indexer: GoEndpointCodeIndexer

    def get_code_blob(self, method: str, path: str) -> Optional[str]:
        entry = self.indexer.lookup(method, path)
        if entry is None:
            return None
        parts = [f"// route: {entry.route.method} {entry.route.path} -> {entry.route.handler}"]
        if entry.handler_source:
            parts.append(entry.handler_source)
        parts.extend(entry.declarations)
        return "\n\n".join(parts)
