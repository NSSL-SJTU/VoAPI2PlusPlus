#!/usr/bin/env python3
"""Endpoint-discovery rules, one entry per Go web framework.

Across the routers we support, a registration always spells the path first and
the handler last, with any middleware in between -- so the dialects differ only
in how they spell the verb, how they nest prefixes, and how they write path
placeholders.
"""

from __future__ import annotations


_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

# httprouter and gin spell the verb in upper case; chi and Gitea's web.Route
# wrapper spell it in title case.
REGISTRATION_METHODS = frozenset(_VERBS) | frozenset(verb.title() for verb in _VERBS)

# Calls that open a routed scope. The argument shape tells the dialects apart:
#   Route("/x", func(r chi.Router){...})  chi    -> prefix, bound lexically
#   Group("/x", func(){...})              Gitea  -> prefix, bound lexically
#   Group("/x")                           gin    -> prefix, returned into a variable
#   Group(func(r chi.Router){...})        chi    -> NO prefix, middleware scope only
GROUP_METHODS = frozenset({"Group", "Route"})

# Mount attaches a sub-router that was built elsewhere, so its prefix reaches the
# routes through a function's return value rather than through nesting:
#   r.Mount("/api/v1", apiv1.Routes())   Gitea, chi
MOUNT_METHODS = frozenset({"Mount"})

# A literal in the handler position means this was never a registration:
# ``cache.Get("key", "fallback")`` reads a cache, it does not serve traffic.
LITERAL_NODE_TYPES = frozenset(
    {
        "interpreted_string_literal",
        "raw_string_literal",
        "int_literal",
        "float_literal",
        "true",
        "false",
        "nil",
    }
)


# Method-agnostic registrations: chi's HandleFunc/Handle serve every verb with
# one handler. We record GET for them -- one verb already exercises that code
# path, and emitting several would multiply the scan budget without reaching any
# new code. Change this tuple to widen it.
ANY_METHOD_REGISTRATIONS = frozenset({"HandleFunc", "Handle", "Any", "Method"})
ANY_METHOD_VERBS = ("GET",)

# gin spells Handle as Handle(method, path, handlers...) and chi's Method is
# Method(method, pattern, handler), while chi's own Handle is path-first. Same
# names, different argument orders, so the first argument decides.
METHOD_FIRST_CANDIDATES = frozenset({"Handle", "Method"})

# Verbs the pipeline's APIMethod can represent. A WebDAV verb (PROPFIND, MOVE,
# MKCOL...) is a real registration we deliberately drop: it cannot be modelled,
# and none of the six vulnerability types targets it.
SUPPORTED_VERBS = frozenset(_VERBS) | frozenset({"TRACE", "CONNECT"})
EXTENSION_VERBS = frozenset(
    {
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "REPORT",
        "SEARCH",
        "ACL",
        "MKCALENDAR",
    }
)


def method_first_verb(first_argument: str | None) -> str | None:
    """The verb a method-first registration names, or None if not one."""
    if not first_argument:
        return None
    token = first_argument.strip().upper()
    if token in SUPPORTED_VERBS or token in EXTENSION_VERBS:
        return token
    return None


def http_method(call_name: str) -> str | None:
    """Return the HTTP method a registration call names, or None."""
    if call_name in REGISTRATION_METHODS:
        return call_name.upper()
    if call_name in ANY_METHOD_REGISTRATIONS:
        return ANY_METHOD_VERBS[0]
    return None
