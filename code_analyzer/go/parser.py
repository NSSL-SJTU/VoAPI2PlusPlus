#!/usr/bin/env python3
"""Go syntax parsing, mirroring code_analyzer/java/java_parser.py."""

from __future__ import annotations

from typing import Iterator

import tree_sitter_go as tsgo
from tree_sitter import Language, Node, Parser, Tree


class GoParser:
    def __init__(self) -> None:
        self.language = Language(tsgo.language())
        self.parser = Parser(self.language)

    def parse(self, code: str) -> Tree:
        return self.parser.parse(code.encode("utf-8"))


def iter_nodes(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.children)


def node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace")


def string_literal_value(node: Node) -> str | None:
    """Return the text of a Go string literal, or None for anything else."""
    if node.type in ("interpreted_string_literal", "raw_string_literal"):
        return node_text(node)[1:-1]
    return None
