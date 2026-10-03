import json
import logging
from pathlib import Path
from typing import Optional
import re

from pydantic import BaseModel, Field

from matching.extractor import FieldExtractor
from models.api_model import APIModel
from models.ref import FieldRef
from matching.binding import Binding, MatchKind
from utils.llm_client import LLMClient
from utils.prompts import (
    build_dep_candidate_prompt,
    build_dep_key_fields_prompt,
    build_dep_mapping_prompt,
)


logger = logging.getLogger(__name__)


class KeyField(BaseModel):
    name: str = Field(..., description="Field name from the request fields list")
    location: str = Field(..., description="path/header/query/body")
    reason: str = Field(..., description="Short reason for dependency")


class KeyFieldSelection(BaseModel):
    key_fields: list[KeyField] = Field(default_factory=list)


class ApiRef(BaseModel):
    method: str = Field(..., description="HTTP method")
    path: str = Field(..., description="API path")


class CandidateSelection(BaseModel):
    top5_candidates: list[ApiRef] = Field(default_factory=list)


class FieldMapping(BaseModel):
    producer_method: str
    producer_path: str
    producer_field: str
    consumer_field: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str


class FieldMappingResult(BaseModel):
    mappings: list[FieldMapping] = Field(default_factory=list)


def run_dependency_poc(
    api_models: list[APIModel],
    output_dir: str | Path,
    model: Optional[str] = None,
    consumer_models: Optional[list[APIModel]] = None,
    project_name: str = "Unknown",
) -> Path:
    extractor = FieldExtractor()
    llm_client = LLMClient()
    output_path = Path(output_dir) / "llm_dep_poc.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    api_index = {}
    for api in api_models:
        key = (_normalize_method(api.api_method), _normalize_path(api.api_url))
        api_index[key] = api

    catalog_text = _build_api_catalog(api_models, extractor)
    logger.info("LLM dependency PoC catalog size: %d APIs", len(api_models))
    consumers = consumer_models or api_models
    logger.info("LLM dependency PoC consumer count: %d APIs", len(consumers))

    with output_path.open("w", encoding="utf-8") as f:
        for api in consumers:
            method = _normalize_method(api.api_method)
            path = _normalize_path(api.api_url)
            request_fields = extractor.request_fields(api)
            if not request_fields:
                continue
            request_fields_text = _format_fields(request_fields)

            key_prompt = build_dep_key_fields_prompt(
                method, path, request_fields_text, project_name
            )
            key_result, usage_key = llm_client.ask_with_usage(
                key_prompt, KeyFieldSelection, model=model, purpose="dep_poc_keyfield"
            )
            key_fields = key_result.key_fields or []
            key_fields_text = _format_key_fields(key_fields)

            candidates = []
            usage_candidates = _zero_usage()
            if key_fields_text:
                cand_prompt = build_dep_candidate_prompt(
                    method, path, key_fields_text, catalog_text, project_name
                )
                cand_result, usage_candidates = llm_client.ask_with_usage(
                    cand_prompt, CandidateSelection, model=model, purpose="dep_poc_candidate"
                )
                candidates = cand_result.top5_candidates or []

            candidate_models, missing_candidates = _resolve_candidates(
                candidates, api_index
            )
            producer_details = _format_producer_details(
                candidate_models,
                extractor,
                key_fields,
            )

            mappings = []
            usage_mapping = _zero_usage()
            if producer_details:
                mapping_prompt = build_dep_mapping_prompt(
                    method,
                    path,
                    request_fields_text,
                    producer_details,
                    project_name=project_name,
                )
                mapping_result, usage_mapping = llm_client.ask_with_usage(
                    mapping_prompt, FieldMappingResult, model=model, purpose="dep_poc_mapping"
                )
                mappings = mapping_result.mappings or []
                _log_mapping_summary(method, path, mappings)

            record = {
                "consumer": {"method": method, "path": path},
                "key_fields": [_model_to_dict(kf) for kf in key_fields],
                "top5_candidates": [_model_to_dict(c) for c in candidates],
                "missing_candidates": missing_candidates,
                "mappings": [_model_to_dict(m) for m in mappings],
                "usage": {
                    "key_fields": usage_key,
                    "candidates": usage_candidates,
                    "mappings": usage_mapping,
                },
            }
            f.write(json.dumps(record, ensure_ascii=True) + "\n")

    logger.info("LLM dependency PoC results written to: %s", output_path)
    return output_path


def resolve_dependencies_llm(
    consumer_api: APIModel,
    api_models: list[APIModel],
    model: Optional[str] = None,
    llm_client: Optional[LLMClient] = None,
    history_text: Optional[str] = None,
    project_name: str = "Unknown",
    purpose: str = "dep_resolve",
) -> list[Binding]:
    extractor = FieldExtractor()
    client = llm_client or LLMClient()
    api_index = {}
    for api in api_models:
        key = (_normalize_method(api.api_method), _normalize_path(api.api_url))
        api_index[key] = api

    request_fields = extractor.request_fields(consumer_api)
    if not request_fields:
        return []
    request_fields_text = _format_fields(request_fields)

    method = _normalize_method(consumer_api.api_method)
    path = _normalize_path(consumer_api.api_url)
    key_prompt = build_dep_key_fields_prompt(
        method, path, request_fields_text, project_name
    )
    key_result, _usage_key = client.ask_with_usage(
        key_prompt, KeyFieldSelection, model=model, purpose=f"{purpose}_keyfield"
    )
    key_fields = key_result.key_fields or []
    if not key_fields:
        return []

    catalog_text = _build_api_catalog(api_models, extractor)
    key_fields_text = _format_key_fields(key_fields)
    cand_prompt = build_dep_candidate_prompt(
        method, path, key_fields_text, catalog_text, project_name
    )
    cand_result, _usage_candidates = client.ask_with_usage(
        cand_prompt, CandidateSelection, model=model, purpose=f"{purpose}_candidate"
    )
    candidates = cand_result.top5_candidates or []
    candidate_models, _missing = _resolve_candidates(candidates, api_index)
    if not candidate_models:
        return []

    producer_details = _format_producer_details(
        candidate_models,
        extractor,
        key_fields,
    )
    if not producer_details:
        return []
    mapping_prompt = build_dep_mapping_prompt(
        method,
        path,
        request_fields_text,
        producer_details,
        history_text=history_text,
        project_name=project_name,
    )
    mapping_result, _usage_mapping = client.ask_with_usage(
        mapping_prompt, FieldMappingResult, model=model, purpose=f"{purpose}_mapping"
    )
    mappings = mapping_result.mappings or []
    _log_mapping_summary(method, path, mappings)

    return _mappings_to_bindings(
        mappings,
        consumer_api,
        candidate_models,
        extractor,
    )


def _normalize_method(method: object) -> str:
    if hasattr(method, "value"):
        method = getattr(method, "value")
    return str(method).upper()


def _normalize_path(path: str) -> str:
    return path if path.startswith("/") else "/" + path


def _allow_catalog_method(method: object) -> bool:
    return _normalize_method(method) not in {"HEAD", "DELETE"}


def _zero_usage() -> dict[str, int]:
    return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _model_to_dict(model: BaseModel) -> dict:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    if hasattr(model, "dict"):
        return model.dict()
    return json.loads(str(model))


def _build_api_catalog(api_models: list[APIModel], extractor: FieldExtractor) -> str:
    lines = []
    for api in api_models:
        if not _allow_catalog_method(api.api_method):
            continue
        method = _normalize_method(api.api_method)
        path = _normalize_path(api.api_url)
        req_keys = _request_key_summary(api, extractor)
        resp_keys = _response_key_summary(api, extractor)
        id_like = _id_like_response_keys(api, extractor)
        resource = _resource_hint(path)
        req_text = ", ".join(req_keys) if req_keys else "<none>"
        resp_text = ", ".join(resp_keys) if resp_keys else "<none>"
        id_text = ", ".join(id_like) if id_like else "<none>"
        lines.append(
            f"{method} {path} | resource: {resource} | request keys: {req_text} "
            f"| response keys: {resp_text} | id-like response keys: {id_text}"
        )
    return "\n".join(lines)


def _response_key_summary(
    api: APIModel, extractor: FieldExtractor, max_keys: int = 16
) -> list[str]:
    fields = extractor.response_fields(api)
    names = []
    for field in fields:
        name = field.path.dotted() or field.name
        names.append(name)
    unique = _unique_preserve_order(names)
    return unique[:max_keys]


def _request_key_summary(
    api: APIModel, extractor: FieldExtractor, max_keys: int = 12
) -> list[str]:
    fields = extractor.request_fields(api)
    names = []
    for field in fields:
        name = field.path.dotted() or field.name
        names.append(f"{field.location.value}.{name}")
    unique = _unique_preserve_order(names)
    return unique[:max_keys]


def _id_like_response_keys(
    api: APIModel, extractor: FieldExtractor, max_keys: int = 12
) -> list[str]:
    fields = extractor.response_fields(api)
    names = []
    for field in fields:
        dotted = field.path.dotted() or field.name
        tail = field.name.lower()
        if tail == "id" or tail.endswith("_id") or tail.endswith("id"):
            names.append(dotted)
    unique = _unique_preserve_order(names)
    return unique[:max_keys]


def _resource_hint(path: str) -> str:
    segments = [seg for seg in path.split("/") if seg]
    literals = [seg for seg in segments if not (seg.startswith("{") and seg.endswith("}"))]
    if not literals:
        return "<none>"
    return " > ".join(literals[-3:])


def _format_fields(fields: list[FieldRef]) -> str:
    lines = []
    for field in fields:
        dotted = field.path.dotted() or field.name
        required = " required" if getattr(field.param, "is_required", False) else ""
        lines.append(
            f"- {field.location.value}.{dotted} : {field.ptype.value}{required}"
        )
    return "\n".join(lines)


def _format_key_fields(key_fields: list[KeyField]) -> str:
    lines = []
    for field in key_fields:
        loc = field.location or "unknown"
        name = field.name
        reason = field.reason or ""
        line = f"- {loc}.{name}"
        if reason:
            line += f" (reason: {reason})"
        lines.append(line)
    return "\n".join(lines)


def _format_producer_details(
    api_models: list[APIModel],
    extractor: FieldExtractor,
    key_fields: list[KeyField],
) -> str:
    blocks = []
    for api in api_models:
        if not _allow_catalog_method(api.api_method):
            continue
        method = _normalize_method(api.api_method)
        path = _normalize_path(api.api_url)
        req_field_names = _producer_request_field_names(api, extractor)
        eligible_keys = [k for k in key_fields if k.name not in req_field_names]
        fields = extractor.response_fields(api)
        req_summary = ", ".join(_request_key_summary(api, extractor)) or "<none>"
        id_like = ", ".join(_id_like_response_keys(api, extractor)) or "<none>"
        if fields and eligible_keys:
            best_fields = _select_best_response_fields(fields, eligible_keys)
            detail = _format_fields(best_fields) if best_fields else "<no response fields>"
        elif fields and not eligible_keys and key_fields:
            detail = "<no eligible response fields (requires key field in request)>"
        else:
            detail = "<no response fields>"
        blocks.append(
            f"{method} {path}\n"
            f"request keys: {req_summary}\n"
            f"id-like response keys: {id_like}\n"
            f"{detail}"
        )
    return "\n\n".join(blocks)


def _unique_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _producer_request_field_names(
    api: APIModel, extractor: FieldExtractor
) -> set[str]:
    names = set()
    for field in extractor.request_fields(api):
        names.add(field.path.dotted() or field.name)
    return names


def _select_best_response_fields(
    fields: list[FieldRef], key_fields: list[KeyField]
) -> list[FieldRef]:
    if not fields:
        return []
    if not key_fields:
        return [fields[0]]
    chosen: list[FieldRef] = []
    used_ids: set[int] = set()
    for key in key_fields:
        best_field = None
        best_score = -1
        for field in fields:
            if id(field) in used_ids:
                continue
            field_name = field.path.dotted() or field.name
            score = _field_match_score(field_name, key.name)
            if score > best_score:
                best_score = score
                best_field = field
        if best_field is not None:
            chosen.append(best_field)
            used_ids.add(id(best_field))
    if not chosen:
        return [fields[0]]
    return chosen


def _field_match_score(field_name: str, key_name: str) -> int:
    field_tokens = _tokenize_name(field_name)
    key_tokens = _tokenize_name(key_name)
    score = 0
    if "id" in field_tokens and "id" in key_tokens:
        score += 3
    overlap = set(field_tokens) & set(key_tokens)
    score += len(overlap)
    field_flat = "".join(field_tokens)
    key_flat = "".join(key_tokens)
    if field_flat and key_flat:
        if field_flat in key_flat or key_flat in field_flat:
            score += 2
    if field_tokens and field_tokens[-1] == "id":
        score += 1
    if field_tokens and key_tokens and field_tokens[-1] == key_tokens[-1]:
        score += 1
    return score


def _tokenize_name(name: str) -> list[str]:
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", name)
    tokens: list[str] = []
    for part in cleaned.split():
        tokens.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", part))
    return [t.lower() for t in tokens if t]


def _resolve_candidates(
    candidates: list[ApiRef],
    api_index: dict[tuple[str, str], APIModel],
) -> tuple[list[APIModel], list[dict[str, str]]]:
    found = []
    missing = []
    seen = set()
    for cand in candidates:
        method = _normalize_method(cand.method)
        path = _normalize_path(cand.path)
        if not _allow_catalog_method(method):
            missing.append({"method": method, "path": path})
            continue
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        api_model = api_index.get(key)
        if api_model is None:
            missing.append({"method": method, "path": path})
            continue
        found.append(api_model)
    return found, missing


def _log_mapping_summary(
    method: str, path: str, mappings: list[FieldMapping]
) -> None:
    if not mappings:
        logger.info("LLM mapping: %s %s -> <no mappings>", method, path)
        return
    for mapping in mappings:
        logger.info(
            "LLM mapping: %s %s %s -> %s (confidence=%.2f)",
            mapping.producer_method,
            mapping.producer_path,
            mapping.producer_field,
            mapping.consumer_field,
            mapping.confidence,
        )


def _mappings_to_bindings(
    mappings: list[FieldMapping],
    consumer_api: APIModel,
    candidate_models: list[APIModel],
    extractor: FieldExtractor,
) -> list[Binding]:
    consumer_map = _fieldref_map(extractor.request_fields(consumer_api))
    producer_maps: dict[tuple[str, str], dict[str, FieldRef]] = {}
    for api in candidate_models:
        key = (_normalize_method(api.api_method), _normalize_path(api.api_url))
        producer_maps[key] = _fieldref_map(extractor.response_fields(api))

    bindings: list[Binding] = []
    for mapping in mappings:
        producer_key = (
            _normalize_method(mapping.producer_method),
            _normalize_path(mapping.producer_path),
        )
        prod_fields = producer_maps.get(producer_key, {})
        producer_ref = prod_fields.get(mapping.producer_field)
        consumer_ref = consumer_map.get(mapping.consumer_field)
        if not producer_ref or not consumer_ref:
            continue
        bindings.append(
            Binding(
                consumer=consumer_ref,
                producer=producer_ref,
                kind=MatchKind.VARIANT,
            )
        )
    return bindings


def _fieldref_map(fields: list[FieldRef]) -> dict[str, FieldRef]:
    mapping: dict[str, FieldRef] = {}
    for field in fields:
        dotted = field.path.dotted() or field.name
        key = f"{field.location.value}.{dotted}"
        mapping[key] = field
    return mapping
