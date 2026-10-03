from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Tuple, Optional
from .api_model import APIModel
from .parameter import ParamType, Parameter
from .types import ParamLocation


@dataclass(frozen=True)
class FieldPath:
    segments: tuple[str, ...] = ()  # ("user", "address", "city")
    array_index: Optional[int] = None

    def dotted(self) -> str:
        return ".".join(self.segments) if self.segments else ""

    def child(self, k: str) -> FieldPath:
        return FieldPath(self.segments + (k,), self.array_index)

    def with_index(self, idx: int) -> FieldPath:
        return FieldPath(self.segments, idx)


@dataclass(frozen=True)
class FieldRef:
    api: APIModel
    location: ParamLocation
    name: str
    ptype: ParamType
    path: FieldPath
    param: Parameter

    def __repr__(self):
        return f"FieldRef(api={self.api.simple_repr()}, location={self.location}, name={self.name}, ptype={self.ptype}, path={self.path}, param={self.param})"
