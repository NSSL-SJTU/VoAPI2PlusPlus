import logging
from typing import Optional

from pydantic import BaseModel, Field

from matching.extractor import FieldExtractor
from models.api_model import APIModel
from utils.llm_client import LLMClient
from utils.prompts import build_repair_plan_prompt


logger = logging.getLogger(__name__)


class RepairApi(BaseModel):
    method: str = Field(..., description="HTTP method")
    path: str = Field(..., description="API path")
    reason: str = Field(default="", description="Short reason for choosing this API")


class RepairPlan(BaseModel):
    repair_apis: list[RepairApi] = Field(default_factory=list)


def plan_repairs(
    llm_client: LLMClient,
    failed_method: str,
    failed_path: str,
    status_code: str,
    response_text: str,
    api_models: list[APIModel],
    model: Optional[str] = None,
    project_name: str = "Unknown",
) -> list[RepairApi]:
    extractor = FieldExtractor()
    catalog = _build_repair_catalog(api_models, extractor)
    prompt = build_repair_plan_prompt(
        failed_method,
        failed_path,
        status_code,
        response_text,
        catalog,
        project_name,
    )
    result, _usage = llm_client.ask_with_usage(prompt, RepairPlan, model=model)
    return result.repair_apis or []


def resolve_repair_apis(
    repair_apis: list[RepairApi],
    api_models: list[APIModel],
) -> tuple[list[APIModel], list[dict[str, str]]]:
    api_index = {
        (_normalize_method(api.api_method), _normalize_path(api.api_url)): api
        for api in api_models
    }
    found = []
    missing = []
    seen = set()
    for api in repair_apis:
        method = _normalize_method(api.method)
        path = _normalize_path(api.path)
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        model = api_index.get(key)
        if model is None:
            missing.append({"method": method, "path": path})
            continue
        found.append(model)
    return found, missing


def _build_repair_catalog(
    api_models: list[APIModel],
    extractor: FieldExtractor,
    max_req_keys: int = 6,
    max_resp_keys: int = 6,
) -> str:
    lines = []
    for api in api_models:
        method = _normalize_method(api.api_method)
        path = _normalize_path(api.api_url)
        req_keys = _key_summary(extractor.request_fields(api), max_req_keys)
        resp_keys = _key_summary(extractor.response_fields(api), max_resp_keys)
        req_text = ", ".join(req_keys) if req_keys else "<none>"
        resp_text = ", ".join(resp_keys) if resp_keys else "<none>"
        lines.append(
            f"{method} {path} | request keys: {req_text} | response keys: {resp_text}"
        )
    return "\n".join(lines)


def _key_summary(fields, max_keys: int) -> list[str]:
    names: list[str] = []
    for field in fields:
        dotted = field.path.dotted() or field.name
        names.append(f"{field.location.value}.{dotted}")
    unique = _unique_preserve_order(names)
    return unique[:max_keys]


def _unique_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _normalize_method(method: object) -> str:
    if hasattr(method, "value"):
        method = getattr(method, "value")
    return str(method).upper()


def _normalize_path(path: str) -> str:
    return path if path.startswith("/") else "/" + path
