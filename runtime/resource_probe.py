"""Locate the read endpoints that render a resource a scan injected into.

A stored-XSS payload written through ``PUT /api/admin/posts/{postId}/status/draft/content``
renders only on a page whose URL a *sibling* endpoint returns (Halo's
``GET /api/admin/posts/{postId}/preview`` hands back a token URL). After the scan, calling
those sibling GETs with the concrete id the scan used makes the app surface those render
URLs, which the response harvester then feeds to the XSS walker -- no hardcoded endpoint
knowledge, just "the injected resource's own read endpoints".
"""

from __future__ import annotations

from typing import Any, Iterable


def resource_prefix(template: str) -> str | None:
    """The path up to and including the first ``{param}`` segment, or None if there is none.

    ``/api/admin/posts/{postId}/status/draft/content`` -> ``/api/admin/posts/{postId}``.
    """
    segments = template.split("/")
    for i, segment in enumerate(segments):
        if segment.startswith("{") and segment.endswith("}"):
            return "/".join(segments[: i + 1])
    return None


def resource_base(template: str) -> str | None:
    """The injection path minus its trailing action segment.

    ``/api/operation/saved/create`` -> ``/api/operation/saved``. The read endpoints that
    reflect what we stored live under this base (``/api/operation/saved/list``).
    """
    trimmed = template.rstrip("/")
    if "/" not in trimmed.lstrip("/"):
        return None
    return trimmed.rsplit("/", 1)[0] or None


def read_endpoints(injection_templates: Iterable[str], apis: Iterable[Any]) -> list[Any]:
    """GET endpoints sharing an injected resource's base path.

    These list/read endpoints echo the field we injected into, so the render-probe can
    fetch them and re-render the reflected value the way the frontend does. Used for
    stored XSS whose render is a client-side HTML sink, not a URL.
    """
    bases = {
        base
        for template in injection_templates
        if (base := resource_base(template)) is not None
    }
    if not bases:
        return []

    out: list[Any] = []
    seen: set[str] = set()
    for api in apis:
        method = getattr(api.api_method, "value", api.api_method)
        if str(method).upper() != "GET":
            continue
        url = api.api_url
        if url in seen:
            continue
        if any(url == base or url.startswith(base + "/") for base in bases):
            seen.add(url)
            out.append(api)
    return out


def path_param_names(template: str) -> list[str]:
    return [
        segment[1:-1]
        for segment in template.split("/")
        if segment.startswith("{") and segment.endswith("}")
    ]


def sibling_read_targets(
    injection_templates: Iterable[str],
    apis: Iterable[Any],
    resource_ids: dict[str, Any],
) -> list[tuple[Any, dict[str, Any]]]:
    """Return ``(api, path)`` for GET endpoints that share an injected resource's ``{id}``
    prefix and whose every path param has a concrete value from ``resource_ids``.

    ``apis`` items need ``.api_url`` and ``.api_method`` (with a ``.value`` or str). ``path``
    is the concrete path-parameter dict to send.
    """
    prefixes = {
        prefix
        for template in injection_templates
        if (prefix := resource_prefix(template)) is not None
    }
    if not prefixes:
        return []

    targets: list[tuple[Any, dict[str, Any]]] = []
    seen: set[tuple[str, tuple]] = set()
    for api in apis:
        method = getattr(api.api_method, "value", api.api_method)
        if str(method).upper() != "GET":
            continue
        url = api.api_url
        if not any(url == prefix or url.startswith(prefix + "/") for prefix in prefixes):
            continue
        names = path_param_names(url)
        if not all(name in resource_ids for name in names):
            continue
        path = {name: resource_ids[name] for name in names}
        key = (url, tuple(sorted(path.items())))
        if key in seen:
            continue
        seen.add(key)
        targets.append((api, path))
    return targets
