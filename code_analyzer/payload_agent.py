import ast
import json
import logging
from dataclasses import dataclass
from typing import Optional, Protocol

from pydantic import BaseModel, Field

from models.api_model import APIModel
from utils.doc_loader import APIDocLoader
from utils.llm_client import LLMClient
from utils.prompts import (
    build_payload_factory_prompt,
    build_payload_factory_prompt_from_code,
    build_payload_factory_prompt_with_parse_error_from_base,
    build_payload_factory_prompt_with_runtime_error_from_base,
)


logger = logging.getLogger(__name__)


class CodeGenerationOutput(BaseModel):
    code: str = Field(..., description="Python code that returns a payload dict")
    explanation: str = Field(..., description="Brief reasoning or constraints used")


class CodeContextProvider(Protocol):
    def get_code_blob(self, method: str, path: str) -> Optional[str]:
        ...


@dataclass
class PayloadFactoryGenerator:
    doc_loader: Optional[APIDocLoader]
    llm_client: LLMClient
    project_name: str
    default_model: Optional[str] = None
    code_context_provider: Optional[CodeContextProvider] = None
    payload_context_source: str = "auto"

    def _validate_code(self, code: str) -> Optional[str]:
        if not code or not code.strip():
            return "empty code"
        wrapped = "def _payload_factory(ctx):\n" + "\n".join(
            "    " + line for line in code.splitlines()
        )
        try:
            ast.parse(wrapped)
        except SyntaxError as exc:
            return f"{exc.msg} at line {exc.lineno}"
        return None

    def _normalize_method(self, method: object) -> str:
        if hasattr(method, "value"):
            method = getattr(method, "value")
        return str(method).upper()

    def _parse_doc_json(self, doc_json: str) -> Optional[dict]:
        try:
            return json.loads(doc_json) if doc_json else None
        except json.JSONDecodeError:
            return None

    def _needs_payload(self, spec: Optional[dict]) -> bool:
        if not spec:
            return True
        params = spec.get("parameters") or []
        if isinstance(params, list) and params:
            return True
        request_body = spec.get("requestBody")
        if request_body:
            return True
        return False

    def _empty_payload_output(self) -> CodeGenerationOutput:
        return CodeGenerationOutput(
            code="return {'path': {}, 'query': {}, 'body': {}}",
            explanation="No request parameters or requestBody required for this endpoint.",
        )

    def _empty_usage(self) -> dict[str, int]:
        return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _log_code(self, method: str, url: str, code: str) -> None:
        snippet = code if len(code) <= 2000 else code[:2000] + "\n...<truncated>"
        logger.info("Payload factory code for %s %s:\n%s", method, url, snippet)

    def generate(
        self,
        api_model: APIModel,
        model: Optional[str] = None,
        max_attempts: int = 3,
        runtime_error: Optional[str] = None,
    ) -> tuple[Optional[CodeGenerationOutput], dict[str, int]]:
        usage_total = self._empty_usage()
        if model is None:
            model = self.default_model
        method = self._normalize_method(api_model.api_method)
        doc_json = self.doc_loader.get_doc(method, api_model.api_url) if self.doc_loader else ""
        spec = self._parse_doc_json(doc_json)

        use_spec = self.payload_context_source == "spec"
        if self.payload_context_source == "auto":
            use_spec = bool(doc_json and doc_json.strip() not in {"{}", "null"})

        code_blob = None
        if self.payload_context_source in {"code", "auto"} and self.code_context_provider:
            if not use_spec:
                code_blob = self.code_context_provider.get_code_blob(
                    method, api_model.api_url
                )

        if use_spec:
            if not self._needs_payload(spec):
                logger.info("No request params for %s %s, skipping LLM", method, api_model.api_url)
                out = self._empty_payload_output()
                api_model.payload_factory_code = out.code
                api_model.code_explanation = out.explanation
                self._log_code(method, api_model.api_url, out.code)
                return out, usage_total
            base_prompt = build_payload_factory_prompt(
                self.project_name, method, api_model.api_url, doc_json
            )
        elif code_blob:
            base_prompt = build_payload_factory_prompt_from_code(
                self.project_name, method, api_model.api_url, code_blob
            )
        else:
            # fallback to spec prompt with empty doc_json
            base_prompt = build_payload_factory_prompt(
                self.project_name, method, api_model.api_url, doc_json or "{}"
            )

        prompt = (
            build_payload_factory_prompt_with_runtime_error_from_base(
                base_prompt, runtime_error
            )
            if runtime_error
            else base_prompt
        )
        for attempt in range(1, max_attempts + 1):
            logger.info(
                "Generating payload factory for %s %s (attempt %d/%d)",
                method,
                api_model.api_url,
                attempt,
                max_attempts,
            )
            result, usage = self.llm_client.ask_with_usage(
                prompt, CodeGenerationOutput, model=model
            )
            usage_total["prompt_tokens"] += usage["prompt_tokens"]
            usage_total["completion_tokens"] += usage["completion_tokens"]
            usage_total["total_tokens"] += usage["total_tokens"]
            err = self._validate_code(result.code)
            if err is None:
                api_model.payload_factory_code = result.code
                api_model.code_explanation = result.explanation
                self._log_code(method, api_model.api_url, result.code)
                return result, usage_total
            logger.warning(
                "Invalid payload factory code for %s %s: %s",
                method,
                api_model.api_url,
                err,
            )
            prompt = build_payload_factory_prompt_with_parse_error_from_base(
                base_prompt, err
            )

        api_model.payload_factory_code = None
        api_model.code_explanation = None
        logger.error(
            "Failed to generate valid payload factory code for %s %s",
            method,
            api_model.api_url,
        )
        return None, usage_total
