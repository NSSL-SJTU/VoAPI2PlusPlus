# runtime/materialize/request.py

from dataclasses import dataclass, field
from optparse import Values
from models.api_model import APIModel
from models.parameter import Parameter, BasicParameter, ArrayParameter, PropertyParameter
from models.types import ParamType, ValueSource, ParamValuePriority
from typing import Any


@dataclass(frozen=True)
class RequestPayload:
    path: dict[str, Any]
    header: dict[str, Any]
    query: dict[str, Any]
    body: dict[str, Any] | list[Any]
    files: dict[str, Any] | None = None


@dataclass
class RequestMaterializer:


    header_default: dict[str, Any] = field(default_factory=dict)
    overrides: dict[str, Any] = field(default_factory=dict)
    open_required: bool = False

    # ---- public ----
    def materialize(self, api: APIModel) -> RequestPayload:
        path = self._section_dict(api.request_structure.path)
        header = {
            **self.header_default,
            **(self._section_dict(api.request_structure.header)),
        }
        query = self._section_dict(api.request_structure.query)
        body_params = api.request_structure.body
        if self.open_required and _count_leaf_params(body_params) < 5:
            # For small bodies, keep optional fields to avoid empty payloads
            prev = self.open_required
            self.open_required = False
            try:
                body = self._section_dict(body_params)
            finally:
                self.open_required = prev
        else:
            body = self._section_dict(body_params)
        # Unwrap legacy "__body__" wrapper for root body payloads
        if isinstance(body, dict) and "__body__" in body and len(body) == 1:
            body = body["__body__"]
        if (
            isinstance(body, dict)
            and self._is_form_content_type(header)
            and isinstance(body_params, dict)
        ):
            self._prune_weak_form_body_fields(body, body_params)
        return RequestPayload(path, header, query, body)

    def materialize_get_empty(self, api: APIModel) -> RequestPayload:
        path = self._section_dict(api.request_structure.path)
        header = {
            **self.header_default,
            **(self._section_dict(api.request_structure.header)),
        }
        query = {}
        body = {}
        return RequestPayload(path, header, query, body)


    # ---- internals ----
    def _section_dict(self, params: dict[str, Parameter]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, p in params.items():
            v = self._value_of(name, p)
            if v is not _SKIP:
                out[name] = v
        return out

    # def _section_dict_or_array(
    #     self,
    #     params:dict[str, Parameter],
    #     overrides:dict[str, Any]
    # ) ->dict[str, Any] | list[Any]:
    #     # maybe handle when body is an array
    #     return self._section_dict(params, overrides)

    def _value_of(self, name: str, p: Parameter) -> Any:
        # 1) not required and open_required → skip (unless this is the tested param)
        if self.open_required and not p.is_required:
            if not _contains_test_value(p):
                return _SKIP

        # 2) overrides
        if name in self.overrides and not _is_leaf(p):
            return self.overrides[name]
        

        if isinstance(p, BasicParameter):
            if p.param_type == ParamType.FILE:
                return _SKIP
            origin_source_rank = ParamValuePriority.get(p.value_source, 0)
            override_source_rank = ParamValuePriority.get(ValueSource.VoAPI_CUSTOM, 0)
            if name in self.overrides and origin_source_rank < override_source_rank:
                return self.overrides[name]
            return self._materialize_basic(p, open_required=self.open_required)
        if isinstance(p, ArrayParameter):
            item = p.item
            if item is None:
                return []
            elem = self._value_of(name, item)
            return [] if elem is _SKIP else [elem]
        if isinstance(p, PropertyParameter):
            obj: dict[str, Any] = {}
            for k, child in p.properties.items():
                v = self._value_of(k, child)
                if v is not _SKIP:
                    obj[k] = v
            return obj

        return _SKIP

    def _is_form_content_type(self, header: dict[str, Any]) -> bool:
        content_type = ""
        for key, value in header.items():
            if key.lower() == "content-type":
                content_type = str(value).lower()
                break
        return "application/x-www-form-urlencoded" in content_type

    def _prune_weak_form_body_fields(
        self,
        body: dict[str, Any],
        params: dict[str, Parameter],
    ) -> None:
        for name, param in params.items():
            if name not in body:
                continue
            if not _is_server_managed_form_field(name):
                continue
            if name in self.overrides:
                continue
            if _contains_test_value(param):
                continue
            if _strong_value_source(param):
                continue
            body.pop(name, None)

    def _materialize_basic(self, p: BasicParameter, open_required: bool = True) -> Any:
        if open_required and not p.is_required and p.value_source != ValueSource.VoAPI_TEST:
            return _SKIP
        if p.value_source == ValueSource.VoAPI_RANDOM:
            return p.get_random_value()
        if p.value_source == ValueSource.VoAPI_FORMAT:
            return p.get_format_value()
        if p.value is not None:
            return p.value
        return _fallback_for(p.param_type)


# ---- helpers ----
_SKIP = object()

_SERVER_MANAGED_FORM_FIELDS = {
    "id",
    "createdat",
    "updatedat",
    "createtime",
    "updatetime",
    "createuserid",
    "updateuserid",
    "createdby",
    "updatedby",
}


def _is_leaf(p: Parameter) -> bool:
    return isinstance(p, BasicParameter)


def _fallback_for(t: ParamType) -> Any:
    # fallback for each type
    if t == ParamType.INTEGER:
        return 0
    if t == ParamType.NUMBER:
        return 0.0
    if t == ParamType.BOOLEAN:
        return False
    if t == ParamType.OBJECT:
        return {}
    if t == ParamType.ARRAY:
        return []
    if t == ParamType.STRING:
        return ""
    return ""


def _contains_test_value(p: Parameter) -> bool:
    if isinstance(p, BasicParameter):
        return p.value_source == ValueSource.VoAPI_TEST
    if isinstance(p, ArrayParameter):
        return _contains_test_value(p.item) if p.item else False
    if isinstance(p, PropertyParameter):
        return any(_contains_test_value(child) for child in p.properties.values())
    return False


def _strong_value_source(p: Parameter) -> bool:
    strong_sources = {
        ValueSource.VoAPI_CUSTOM,
        ValueSource.VoAPI_PRODUCER,
        ValueSource.VoAPI_CONSUMER,
        ValueSource.VoAPI_TEST,
        ValueSource.VoAPI_SUCCESS,
    }
    if isinstance(p, BasicParameter):
        return p.value_source in strong_sources
    if isinstance(p, ArrayParameter):
        return _strong_value_source(p.item) if p.item else False
    if isinstance(p, PropertyParameter):
        return any(_strong_value_source(child) for child in p.properties.values())
    return False


def _is_server_managed_form_field(name: str) -> bool:
    normalized = "".join(ch for ch in name.lower() if ch.isalnum())
    return normalized in _SERVER_MANAGED_FORM_FIELDS


def _count_leaf_params(params: dict[str, Parameter]) -> int:
    total = 0
    for p in params.values():
        total += _leaf_count(p)
    return total


def _leaf_count(p: Parameter) -> int:
    if isinstance(p, BasicParameter):
        return 1
    if isinstance(p, ArrayParameter):
        return _leaf_count(p.item) if p.item else 0
    if isinstance(p, PropertyParameter):
        return sum(_leaf_count(child) for child in p.properties.values())
    return 0
