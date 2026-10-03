"""Language dispatch for source-code API extraction.

``code_analyzer`` has two language-specific surfaces, and a new language has to
implement both: an extractor that turns a project into ``APIModel`` instances,
and a context provider that hands an endpoint's code to the LLM recovery path.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional, Protocol

from code_analyzer.payload_agent import CodeContextProvider

if TYPE_CHECKING:
    from models.api_model import APIModel


GO_BUILD_FILES = ("go.mod",)
MAX_BUILD_FILE_DEPTH = 3
JAVA_BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


def detect_project_language(project_path: str | Path) -> str:
    """Name the language of the project rooted at ``project_path``.

    The build file is not always at the root -- Chat2DB keeps its ``pom.xml`` in
    a server module one level down -- so search a few levels and let the
    shallowest hit win. Returns ``"unknown"`` rather than guessing when nothing
    is found; callers decide what to fall back to.
    """
    root = Path(project_path)
    for depth in range(MAX_BUILD_FILE_DEPTH + 1):
        prefix = "*/" * depth
        go_hits = list(root.glob(prefix + "go.mod"))
        java_hits = [
            hit for name in JAVA_BUILD_FILES for hit in root.glob(prefix + name)
        ]
        if go_hits and not java_hits:
            return "go"
        if java_hits:
            # A tree holding both stays on Java, which is what every existing
            # --spring_project run expects; --code_lang overrides it.
            return "java"
    return "unknown"


class ApiExtractor(Protocol):
    """Turns a source project into the APIModel list the pipeline runs on."""

    def scan_project(self) -> list["APIModel"]:
        ...


class UnsupportedProjectLanguage(RuntimeError):
    """Raised when no extractor front end exists for the detected language."""


def build_api_extractor(
    project_path: str | Path,
    language: Optional[str] = None,
) -> ApiExtractor:
    """Pick the extractor front end for ``project_path``.

    A project with no recognizable build file falls back to Java, because every
    existing ``--spring_project`` invocation relies on that behaviour.
    """
    lang = language or detect_project_language(project_path)
    if lang in ("java", "unknown"):
        from code_analyzer.java.spring_api_extractor import SpringApiExtractor

        return SpringApiExtractor(str(project_path))
    if lang == "go":
        from code_analyzer.go.api_extractor import GoApiExtractor

        return GoApiExtractor(str(project_path))
    raise UnsupportedProjectLanguage(
        f"no source extractor for language {lang!r} (project: {project_path}); "
        "supported languages: java, go"
    )


def build_code_context_provider(
    project_path: str | Path,
    language: Optional[str] = None,
) -> "CodeContextProvider":
    """Pick the LLM code-context front end for ``project_path``.

    Source-only targets have no spec, so this is what feeds endpoint code to
    payload generation and vulnerability retries -- not an optional extra.
    """
    lang = language or detect_project_language(project_path)
    if lang in ("java", "unknown"):
        from code_analyzer.java.endpoint_indexer import (
            EndpointCodeContextProvider,
            EndpointCodeIndexer,
        )

        return EndpointCodeContextProvider(EndpointCodeIndexer(str(project_path)))
    if lang == "go":
        from code_analyzer.go.endpoint_indexer import (
            GoEndpointCodeContextProvider,
            GoEndpointCodeIndexer,
        )

        return GoEndpointCodeContextProvider(GoEndpointCodeIndexer(str(project_path)))
    raise UnsupportedProjectLanguage(
        f"no code context provider for language {lang!r} (project: {project_path}); "
        "supported languages: java, go"
    )
