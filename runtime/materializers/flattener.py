# runtime/materializers/flattener.py

from dataclasses import dataclass
from models.ref import FieldPath
from typing import Any

@dataclass(frozen=True)
class Flattened:
    path: FieldPath
    value: Any

def flatten_json(value: Any, base: FieldPath | None = None) -> list[Flattened]:
    base = base or FieldPath(segments=(), array_index=None)
    out: list[Flattened] = []

    if isinstance(value, dict):
        for k, v in value.items():
            out.extend(flatten_json(v, base.child(k)))
    elif isinstance(value, list):
        for idx, v in enumerate(value):
            out.extend(flatten_json(v, base.with_index(idx)))
    else:
        out.append(Flattened(base, value))
    return out


