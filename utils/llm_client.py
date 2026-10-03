import os
import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Type, TypeVar, Optional, Any
from dotenv import load_dotenv
from openai import OpenAI
import instructor
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type


load_dotenv()

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Every LLM call is tagged with what it was for, so cost and "calls per
# successful repair" can be attributed per module rather than reported as one
# opaque total.  Most call sites are identified by their response model; the
# dependency ones are not, because the same models serve both up-front
# resolution and failure-driven recovery, so those pass `purpose` explicitly.
_PURPOSE_BY_MODEL = {
    "CodeGenerationOutput": "payload_codegen",
    "FailureClassification": "failure_classify",
    "RepairPlan": "dep_repair_plan",
    "FileTypeChoice": "multipart_filetype",
    "FileGenCode": "multipart_filegen",
    "VulnPayloadPlan": "vuln_payload",
    "KeyFieldSelection": "dep_unlabelled",
    "CandidateSelection": "dep_unlabelled",
    "FieldMappingResult": "dep_unlabelled",
    "PingResponse": "ping",
}


class LLMClient:
    _global_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    _usage_by_purpose: dict[str, dict[str, int]] = {}

    @classmethod
    def reset_global_usage(cls) -> None:
        cls._global_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        cls._usage_by_purpose = {}

    @classmethod
    def global_usage(cls) -> dict[str, int]:
        return dict(cls._global_usage)

    @classmethod
    def global_call_count(cls) -> int:
        """Total LLM calls so far, used to attribute cost to a single endpoint."""
        return sum(v["calls"] for v in cls._usage_by_purpose.values())

    @classmethod
    def usage_by_purpose(cls) -> dict[str, dict[str, int]]:
        return {k: dict(v) for k, v in cls._usage_by_purpose.items()}

    @classmethod
    def log_usage_breakdown(cls) -> None:
        for purpose, u in sorted(
            cls._usage_by_purpose.items(), key=lambda kv: -kv[1]["total_tokens"]
        ):
            logger.info(
                "LLM usage by purpose: purpose=%s calls=%d cached=%d "
                "prompt=%d completion=%d total=%d",
                purpose,
                u["calls"],
                u["cached"],
                u["prompt_tokens"],
                u["completion_tokens"],
                u["total_tokens"],
            )

    def __init__(self):
        provider = os.getenv("LLM_PROVIDER", "openai").strip().lower()
        self._provider = provider
        if provider in {"openai", "openai_compat", "openai-compatible"}:
            api_key = os.getenv("API_KEY")
            # Unset BASE_URL falls back to the OpenAI SDK's own default endpoint.
            base_url = os.getenv("BASE_URL") or None

            if not api_key:
                raise ValueError("API_KEY is missing in .env")

            self.client = instructor.from_openai(
                OpenAI(api_key=api_key, base_url=base_url),
                mode=instructor.Mode.JSON,
            )
        elif provider in {"gemini", "genai"}:
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise ValueError("GOOGLE_API_KEY is missing in .env")
            try:
                from google import genai
            except Exception as exc:
                raise ValueError(
                    "google-genai is required for LLM_PROVIDER=gemini"
                ) from exc
            genai_client = genai.Client(api_key=api_key)
            self.client = instructor.from_genai(
                genai_client,
                mode=instructor.Mode.GENAI_STRUCTURED_OUTPUTS,
            )
        else:
            raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")
        self._total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        cache_path = os.getenv("LLM_CACHE_FILE", ".llm_cache.jsonl")
        # Setting LLM_CACHE_FILE to an empty value (or off/none/disabled) turns the
        # response cache off entirely.
        self._cache_enabled = cache_path.strip().lower() not in {
            "",
            "off",
            "none",
            "disabled",
            "false",
            "0",
        }
        self._cache_path = Path(cache_path) if self._cache_enabled else None
        self._cache: dict[str, dict[str, Any]] = {}
        if self._cache_enabled:
            self._load_cache()
        else:
            logger.info("LLM response cache disabled (LLM_CACHE_FILE=%r)", cache_path)

    def _ping(self, interval: int = 10, max_wait: int = 300) -> None:
        """Block until the LLM API is reachable again."""
        waited = 0
        while waited < max_wait:
            try:
                if self._provider in {"openai", "openai_compat", "openai-compatible"}:
                    self.client.client.chat.completions.create(
                        model=os.getenv("MODEL_NAME", "gpt-4o"),
                        messages=[{"role": "user", "content": "ping"}],
                        max_tokens=1,
                    )
                else:
                    self.client.create(
                        model=os.getenv("MODEL_NAME", "gpt-4o"),
                        response_model=None,
                        messages=[{"role": "user", "content": "ping"}],
                    )
                logger.info("LLM API ping OK after %ds", waited)
                return
            except Exception:
                logger.warning("LLM API unreachable, retrying in %ds... (%d/%ds)", interval, waited, max_wait)
                time.sleep(interval)
                waited += interval
        logger.warning("LLM API still unreachable after %ds, proceeding anyway", max_wait)


    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
    )
    def _ask_inner(
        self,
        prompt: str,
        response_model: Type[T],
        model: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> T:
        model_name = model or os.getenv("MODEL_NAME", "gpt-4o")
        purpose = self._resolve_purpose(purpose, response_model)
        cache_key = self._cache_key(prompt, model_name, response_model)
        cached = self._get_cached_response(cache_key, response_model)
        if cached is not None:
            logger.info("LLM cache hit: %s", cache_key)
            self._add_usage(self._zero_usage(), purpose, cached=True)
            return cached
        logger.info(
            "Requesting LLM completion with model: %s purpose=%s", model_name, purpose
        )
        logger.info("LLM prompt:\n%s", self._truncate_text(prompt))
        result, completion = self._create_with_completion(prompt, response_model, model_name)
        usage = self._usage_dict(completion)
        self._add_usage(usage, purpose)
        self._store_cache(cache_key, model_name, response_model, result, usage)
        return result

    def ask(
        self,
        prompt: str,
        response_model: Type[T],
        model: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> T:
        try:
            return self._ask_inner(prompt, response_model, model, purpose)
        except Exception:
            logger.warning("LLM ask failed after retries, pinging API...")
            self._ping()
            return self._ask_inner(prompt, response_model, model, purpose)

    def _usage_dict(self, usage) -> dict[str, int]:
        if not usage:
            return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        nested_usage = getattr(usage, "usage", None)
        if nested_usage is not None:
            usage = nested_usage
        if hasattr(usage, "usage_metadata"):
            usage = usage.usage_metadata
        if isinstance(usage, dict):
            return {
                "prompt_tokens": int(
                    usage.get("prompt_tokens")
                    or usage.get("prompt_token_count")
                    or usage.get("promptTokenCount")
                    or 0
                ),
                "completion_tokens": int(
                    usage.get("completion_tokens")
                    or usage.get("candidates_token_count")
                    or usage.get("candidatesTokenCount")
                    or 0
                ),
                "total_tokens": int(
                    usage.get("total_tokens")
                    or usage.get("total_token_count")
                    or usage.get("totalTokenCount")
                    or 0
                ),
            }
        if hasattr(usage, "prompt_token_count"):
            prompt_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
            completion_tokens = int(getattr(usage, "candidates_token_count", 0) or 0)
            total_tokens = int(getattr(usage, "total_token_count", 0) or 0)
            return {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }
        details = getattr(usage, "completion_tokens_details", None)
        return {
            "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
            "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
            "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
            # The relay folds reasoning into completion_tokens and reports
            # total = prompt + completion, so thinking inferred as
            # total - prompt - completion is 0 whether thinking ran or not. This
            # field is where the real count is, and it is what makes
            # LLM_THINKING=off checkable rather than merely requested.
            "reasoning_tokens": int(getattr(details, "reasoning_tokens", 0) or 0),
        }

    @staticmethod
    def _reasoning_kwargs() -> dict:
        """Extra request fields controlling the model's reasoning budget.

        LLM_THINKING=off sends a zero thinking budget via Gemini's own
        thinking_config. LLM_REASONING_EFFORT is read for providers that honour
        the reasoning_effort field. Both are unset by default.
        """
        kwargs: dict = {}
        temp = os.getenv("LLM_TEMPERATURE", "").strip()
        if temp:
            kwargs["temperature"] = float(temp)
        effort = os.getenv("LLM_REASONING_EFFORT", "").strip()
        if effort:
            kwargs["reasoning_effort"] = effort
        if os.getenv("LLM_THINKING", "").strip().lower() in {"off", "0", "none", "false"}:
            # Double-wrapped on purpose. The OpenAI SDK flattens its extra_body
            # argument into the top level of the request, so some relays only honour
            # a field literally named "extra_body"; the nested form below is what
            # reaches Gemini's thinking_config and switches thinking off.
            kwargs["extra_body"] = {
                "extra_body": {"google": {"thinking_config": {"thinking_budget": 0}}}
            }
        return kwargs

    def _create_with_completion(
        self,
        prompt: str,
        response_model: Type[T],
        model_name: str,
    ) -> tuple[T, Any]:
        messages = [{"role": "user", "content": prompt}]
        if self._provider in {"openai", "openai_compat", "openai-compatible"}:
            return self.client.chat.completions.create_with_completion(
                model=model_name,
                response_model=response_model,
                messages=messages,
                **self._reasoning_kwargs(),
            )
        return self.client.create_with_completion(
            model=model_name,
            response_model=response_model,
            messages=messages,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
    )
    def _ask_with_usage_inner(
        self,
        prompt: str,
        response_model: Type[T],
        model: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> tuple[T, dict[str, int]]:
        model_name = model or os.getenv("MODEL_NAME", "gpt-4o")
        purpose = self._resolve_purpose(purpose, response_model)
        cache_key = self._cache_key(prompt, model_name, response_model)
        cached = self._get_cached_response(cache_key, response_model)
        if cached is not None:
            logger.info("LLM cache hit: %s", cache_key)
            logger.info("LLM response:\n%s", self._truncate_text(self._model_to_text(cached)))
            usage = self._zero_usage()
            self._add_usage(usage, purpose, cached=True)
            return cached, usage
        logger.info(
            "Requesting LLM completion with model: %s purpose=%s", model_name, purpose
        )
        logger.info("LLM prompt:\n%s", self._truncate_text(prompt))
        result, completion = self._create_with_completion(prompt, response_model, model_name)
        logger.info("LLM response:\n%s", self._truncate_text(self._model_to_text(result)))
        usage = self._usage_dict(completion)
        self._add_usage(usage, purpose)
        self._store_cache(cache_key, model_name, response_model, result, usage)
        return result, usage

    def ask_with_usage(
        self,
        prompt: str,
        response_model: Type[T],
        model: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> tuple[T, dict[str, int]]:
        try:
            return self._ask_with_usage_inner(prompt, response_model, model, purpose)
        except Exception:
            logger.warning("LLM ask_with_usage failed after retries, pinging API...")
            self._ping()
            return self._ask_with_usage_inner(prompt, response_model, model, purpose)

    @staticmethod
    def _resolve_purpose(purpose: Optional[str], response_model: Type[BaseModel]) -> str:
        if purpose:
            return purpose
        return _PURPOSE_BY_MODEL.get(response_model.__name__, response_model.__name__)

    def _model_to_text(self, model: BaseModel) -> str:
        if hasattr(model, "model_dump_json"):
            return model.model_dump_json()
        if hasattr(model, "json"):
            return model.json()
        return str(model)

    def _truncate_text(self, text: str, max_len: int = 5000) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "\n...<truncated>"

    def _zero_usage(self) -> dict[str, int]:
        return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def _add_usage(
        self,
        usage: dict[str, int],
        purpose: str = "unknown",
        cached: bool = False,
    ) -> None:
        self._total_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
        self._total_usage["completion_tokens"] += usage.get("completion_tokens", 0)
        self._total_usage["total_tokens"] += usage.get("total_tokens", 0)
        self._total_usage["reasoning_tokens"] = (
            self._total_usage.get("reasoning_tokens", 0)
            + usage.get("reasoning_tokens", 0))
        LLMClient._global_usage["prompt_tokens"] += usage.get("prompt_tokens", 0)
        LLMClient._global_usage["completion_tokens"] += usage.get("completion_tokens", 0)
        LLMClient._global_usage["total_tokens"] += usage.get("total_tokens", 0)
        LLMClient._global_usage["reasoning_tokens"] = (
            LLMClient._global_usage.get("reasoning_tokens", 0)
            + usage.get("reasoning_tokens", 0))

        bucket = LLMClient._usage_by_purpose.setdefault(
            purpose,
            {"calls": 0, "cached": 0, "prompt_tokens": 0,
             "completion_tokens": 0, "total_tokens": 0},
        )
        bucket["calls"] += 1
        bucket["cached"] += int(cached)
        for k in ("prompt_tokens", "completion_tokens", "total_tokens",
                  "reasoning_tokens"):
            bucket[k] = bucket.get(k, 0) + usage.get(k, 0)

        # Per-call line so a run can be attributed offline without replaying it.
        logger.info(
            # thinking= is appended, never inserted: scripts/analyze_recovery.py:66
            # and scripts/llm_cost_report.py:32 both anchor on "completion=N total=N"
            # being adjacent, and a field between them would stop either parsing any
            # log written from here on.
            "LLM call done: purpose=%s cached=%s prompt=%d completion=%d total=%d "
            "thinking=%d",
            purpose,
            int(cached),
            usage.get("prompt_tokens", 0),
            usage.get("completion_tokens", 0),
            usage.get("total_tokens", 0),
            usage.get("reasoning_tokens", 0),
        )
        logger.info(
            "LLM token usage (global): prompt=%d completion=%d total=%d",
            LLMClient._global_usage["prompt_tokens"],
            LLMClient._global_usage["completion_tokens"],
            LLMClient._global_usage["total_tokens"],
        )

    def _cache_key(
        self, prompt: str, model_name: str, response_model: Type[BaseModel]
    ) -> str:
        payload = f"{self._provider}\n{model_name}\n{response_model.__name__}\n{prompt}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _load_cache(self) -> None:
        if self._cache_path is None or not self._cache_path.exists():
            return
        try:
            with self._cache_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = record.get("key")
                    response = record.get("response")
                    if isinstance(key, str) and response:
                        self._cache[key] = record
        except OSError as exc:
            logger.warning("Failed to load LLM cache: %s", exc)

    def _get_cached_response(
        self, key: str, response_model: Type[T]
    ) -> Optional[T]:
        if not self._cache_enabled:
            return None
        record = self._cache.get(key)
        if not record:
            return None
        response_text = record.get("response")
        if not response_text:
            return None
        try:
            if isinstance(response_text, str) and hasattr(response_model, "model_validate_json"):
                return response_model.model_validate_json(response_text)
            if isinstance(response_text, dict) and hasattr(response_model, "model_validate"):
                return response_model.model_validate(response_text)
        except Exception as exc:
            logger.warning("Failed to parse cached response: %s", exc)
        return None

    def _store_cache(
        self,
        key: str,
        model_name: str,
        response_model: Type[BaseModel],
        result: BaseModel,
        usage: dict[str, int],
    ) -> None:
        if not self._cache_enabled or self._cache_path is None:
            return
        record = {
            "key": key,
            "model": model_name,
            "response_model": response_model.__name__,
            "response": self._model_to_text(result),
            "usage": usage,
        }
        self._cache[key] = record
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError as exc:
            logger.warning("Failed to write LLM cache: %s", exc)
    
