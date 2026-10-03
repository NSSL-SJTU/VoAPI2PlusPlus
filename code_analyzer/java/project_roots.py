#!/usr/bin/env python3
"""Project-root helpers for Java source indexing."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


def read_maven_modules(pom_path: Path) -> set[str]:
    if not pom_path.exists():
        return set()
    try:
        root = ET.parse(pom_path).getroot()
    except ET.ParseError:
        return set()
    modules: set[str] = set()
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] == "module" and node.text:
            modules.add(node.text.strip())
    return modules


def index_roots(project_path: Path) -> list[Path]:
    roots = [project_path]
    parent = project_path.parent
    modules = read_maven_modules(parent / "pom.xml")
    if project_path.name in modules:
        sibling_roots = [parent / module for module in modules if (parent / module).exists()]
        if sibling_roots:
            roots = sibling_roots
    return roots


def collect_java_files(roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        for java_file in root.rglob("*.java"):
            if java_file in seen:
                continue
            seen.add(java_file)
            files.append(java_file)
    return files
