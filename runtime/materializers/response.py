# runtime/materializers/response.py

import logging
from dataclasses import dataclass
from models.api_model import APIModel
from models.types import ValueSource
from models.parameter import Parameter, BasicParameter, ArrayParameter, PropertyParameter
from .policy import ResponsePolicy
from .flattener import flatten_json
from models.ref import FieldRef, ParamLocation
from runtime.http.client import HTTPResponse
from runtime.payload_generator import DependencyManager
from typing import Any

logger = logging.getLogger(__name__)

@dataclass
class ResponseMaterializer:
    policy: ResponsePolicy
    producer_source: ValueSource = ValueSource.VoAPI_PRODUCER
    dep_manager: DependencyManager | None = None

    def apply(self, api: APIModel, http_response: HTTPResponse) -> None:
        if not http_response.ok:
            return
        ctype = http_response.headers.get("Content-Type", "")
        if "json" not in ctype.lower():
            return  # TODO: support other types

        payload = http_response.json()
        if not isinstance(payload, (dict, list)):
            return

        payload = self._align_to_model(payload, api.response_structure.body)

        flat = flatten_json(payload)
        values_by_key:dict[str, Any] = {}
        key_depth: dict[str, int] = {}
        
        extracted_keys = []
        for item in flat:
            if item.path.segments:
                key = item.path.segments[-1]
                depth = len(item.path.segments)
                prev_depth = key_depth.get(key)
                # Prefer shallower fields when the same leaf key appears multiple times.
                # Example: keep top-level "id" over nested "namespace.id".
                if prev_depth is None or depth < prev_depth:
                    values_by_key[key] = item.value
                    key_depth[key] = depth
                elif depth == prev_depth and key not in values_by_key:
                    values_by_key[key] = item.value
                extracted_keys.append(f"{key}={item.value}")
        
        logger.info(f"Extracted keys from response: {extracted_keys}")
        if self.dep_manager:
            self._store_dependencies(api, values_by_key)

        self._write_object_params(api.response_structure.body, values_by_key)
        self._write_object_params(api.response_structure.header, values_by_key)

    # ---- helpers ----

    def _align_to_model(self, payload: Any, modeled_body: dict[str, Parameter]) -> Any:
        """Descend past a response envelope to the subtree the static model describes.

        A global response advice wraps the real payload at runtime (Halo wraps every
        controller return value in BaseResponse as {status, message, data:{...}}), but
        the static response model was built from the unwrapped return type, so its
        fields sit at the top level. Rather than hardcode the wrapper key, pick the
        child subtree whose keys best cover the modeled field names -- so the envelope's
        generic keys (status/message) stop shadowing the resource's own fields. Ties
        favour the root, so a genuinely unwrapped body (or a return-type wrapper like
        RestResult<T>, whose `data` is already in the model) is left untouched.
        """
        if not isinstance(payload, dict) or not modeled_body:
            return payload
        expected = set(modeled_body.keys())
        if not expected:
            return payload

        def coverage(node: Any) -> int:
            return len(expected & node.keys()) if isinstance(node, dict) else 0

        best_key: str | None = None
        best = coverage(payload)
        for key, child in payload.items():
            score = coverage(child)
            if score > best:
                best, best_key = score, key
        return payload[best_key] if best_key is not None else payload

    def _write_object_params(self,
                             params:dict[str, Parameter],
                             values:dict[str, Any]) -> None:
        for name, p in params.items():
            self._write_param(name, p, values)

    def _write_param(self,
                     name: str,
                     p: Parameter,
                     values:dict[str, Any]) -> None:
        if isinstance(p, BasicParameter):
            if name in values:
                logger.info(f"  [MATCH] Param '{name}' matched value '{values[name]}'")
                self._maybe_set_basic(p, values[name])
            else:
                logger.info(f"  [MISS ] Param '{name}' NOT found in response keys")
            return
        if isinstance(p, PropertyParameter):
            for k, child in p.properties.items():
                self._write_param(k, child, values)
            return
        if isinstance(p, ArrayParameter):
            # Handle array: recursively process the item structure
            if p.item:
                if isinstance(p.item, BasicParameter):
                    # Array of basic types (e.g., ["val1", "val2"])
                    # Try to match the array name itself
                    if name in values:
                        logger.info(f"  [MATCH] Array[Basic] param '{name}' matched value '{values[name]}'")
                        self._maybe_set_basic(p.item, values[name])
                    else:
                        logger.info(f"  [MISS ] Array[Basic] param '{name}' NOT found in response keys")
                elif isinstance(p.item, PropertyParameter):
                    # Array of objects (e.g., [{id:1, name:"a"}, {id:2, name:"b"}])
                    # Recursively process the item's properties
                    logger.debug(f"  Processing Array[Object] param '{name}' with {len(p.item.properties)} properties")
                    for k, child in p.item.properties.items():
                        self._write_param(k, child, values)
                elif isinstance(p.item, ArrayParameter):
                    # Nested array (rare case): recursively process
                    logger.debug(f"  Processing nested Array param '{name}'")
                    self._write_param(name, p.item, values)
            return

    def _maybe_set_basic(self, p: BasicParameter, v: Any) -> None:
        existing_src = p.value_source
        logger.debug(f"Existing source: {existing_src}, Producer source: {self.producer_source}")
        if self.policy.should_write(existing_src, self.producer_source):
            logger.debug(f"Writing value: {v} to parameter: {p.param_name}")
            p.value = v
            p.value_source = self.producer_source
        else:
            logger.debug(f"Skipping write for parameter: {p.param_name}")

    def _store_dependencies(self, api: APIModel, values: dict[str, Any]) -> None:
        if not values:
            return
        resource = self._resource_name(api.api_url)
        alias = self._singularize(resource) if resource else None
        for key, value in values.items():
            self.dep_manager.set(key, value)
            if isinstance(key, str) and key.startswith("$"):
                self.dep_manager.set(key[1:], value)
            if alias and key in ("$id", "id"):
                self.dep_manager.set(alias, value)
                self.dep_manager.set(f"{alias}Id", value)
                self.dep_manager.set(f"{alias}_id", value)

    def _resource_name(self, path: str) -> str | None:
        parts = [p for p in path.split("/") if p]
        literal = [
            p for p in parts if not (p.startswith("{") and p.endswith("}"))
        ]
        if not literal:
            return None
        return literal[-1]

    def _singularize(self, name: str) -> str:
        if name.endswith("s") and len(name) > 1:
            return name[:-1]
        return name
