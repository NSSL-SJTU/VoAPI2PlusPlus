#!/usr/bin/env python3
"""Project-local registration helpers.

A project may not register routes with the router's own methods. Navidrome's
Subsonic API -- 89 endpoints, more than the rest of the project put together --
goes through three of its own functions:

    h(r, "ping", api.Ping)
      -> hr(r, path, f)
           -> addHandler(r, path, handle)
                -> r.HandleFunc("/"+path, handle)
                -> r.HandleFunc("/"+path+".view", handle)

So a helper is described by which parameter carries the router, which carries the
path, and what paths it ends up registering *as a function of* that parameter.
The last part is held as a (left, right) pair around the parameter's position,
because real templates are plain concatenations.
"""

from __future__ import annotations

from dataclasses import dataclass


# Stands in for the helper's path parameter while its body is evaluated, so the
# surrounding literals can be read off the result.
PATH_SENTINEL = "\x00path\x00"


@dataclass(frozen=True)
class Registration:
    method: str
    left: str
    right: str

    def path_for(self, value: str) -> str:
        return self.left + value + self.right


@dataclass(frozen=True)
class HelperSpec:
    router_index: int
    path_index: int
    registrations: tuple[Registration, ...]

    def key(self) -> tuple:
        return (self.router_index, self.path_index, self.registrations)


def split_on_sentinel(resolved: str) -> tuple[str, str] | None:
    """Return the literals around the path parameter, or None if absent."""
    if PATH_SENTINEL not in resolved:
        return None
    left, _, right = resolved.partition(PATH_SENTINEL)
    return left, right
