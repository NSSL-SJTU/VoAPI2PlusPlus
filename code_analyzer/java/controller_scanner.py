#!/usr/bin/env python3
"""
Scan controllers and methods from Java source.
"""

from __future__ import annotations

from typing import Optional
from tree_sitter import Node

from code_analyzer.java.indexer import JavaIndexer


class ControllerScanner:

    def __init__(self, indexer: JavaIndexer):
        self.indexer = indexer

    def is_controller(self, code: str, class_node: Node) -> bool:
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
            text = self.indexer.extract_text(code, n)
            if text.endswith("Controller") or text.endswith("RestController"):
                return True
        return False

    def extract_class_base_path(self, code: str, class_node: Node) -> str:
        q = """
        (class_declaration (modifiers (annotation
          name: (identifier) @name
          arguments: (annotation_argument_list (string_literal) @value)?
        )))
        """
        caps = self.indexer.query(class_node, q)
        names = caps.get("name", [])
        values = caps.get("value", [])
        for i, name_node in enumerate(names):
            name_text = self.indexer.extract_text(code, name_node)
            if name_text == "RequestMapping" and i < len(values):
                val = self.indexer.extract_text(code, values[i])
                return val.strip("\"'")
        return ""
