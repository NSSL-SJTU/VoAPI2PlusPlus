import json
from typing import Optional, Literal

from pydantic import BaseModel, Field

from utils.llm_client import LLMClient
from utils.prompts import build_failure_classification_prompt


class FailureClassification(BaseModel):
    error_type: Literal["dependency_error", "parameter_error", "unknown"]
    reason: str = ""
    missing_fields: list[str] = Field(default_factory=list)


def classify_failure(
    llm_client: LLMClient,
    consumer_method: str,
    consumer_path: str,
    failed_method: str,
    failed_path: str,
    status_code: str,
    response_text: str,
    request_payload: dict,
    model: Optional[str] = None,
    project_name: str = "Unknown",
) -> tuple[FailureClassification, dict[str, int]]:
    payload_text = _safe_json(request_payload)
    prompt = build_failure_classification_prompt(
        consumer_method=consumer_method,
        consumer_path=consumer_path,
        failed_method=failed_method,
        failed_path=failed_path,
        status_code=status_code,
        response_text=_truncate_text(response_text, 2000),
        request_payload=_truncate_text(payload_text, 2000),
        project_name=project_name,
    )
    return llm_client.ask_with_usage(prompt, FailureClassification, model=model)


def _safe_json(payload: dict) -> str:
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return "<unserializable payload>"


def _truncate_text(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n...<truncated>"
