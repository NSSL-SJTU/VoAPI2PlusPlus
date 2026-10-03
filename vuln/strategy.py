# vuln/strategy.py
from dataclasses import dataclass, field
from copy import deepcopy
import json
from typing import ClassVar, Iterable, Optional, Any, Literal
from urllib.parse import urlparse

import logging
from pydantic import BaseModel, Field
from runtime.bindings.applier import BindingApplier
from runtime.payload_generator import CodeBasedPayloadGenerator, GenerationContext
from runtime.llm_failure import classify_failure, FailureClassification
from vuln.recorder import VulnRecorder, VulnCase
from vuln.types import VulnType
from models.api_model import APIModel
from models.ref import FieldRef
from runtime.materializers.request import RequestMaterializer, RequestPayload
from runtime.http.client import HTTPClient, HTTPResponse
from runtime.form import FormHandler
from planning.graph import DependencyEdge
from models.types import ValueSource, ParamLocation, ParamType
from models.parameter import BasicParameter
from utils.llm_client import LLMClient
from code_analyzer.payload_agent import PayloadFactoryGenerator
from utils.prompts import build_vuln_payload_plan_prompt
from runtime.vuln_dependencies import (
    VulnDependencyPreparer,
    looks_unresolved_path_value,
)


logger = logging.getLogger(__name__)


class VulnPayloadPlan(BaseModel):
    error_type: Literal["dependency_error", "parameter_error", "unknown"]
    reason: str = ""
    payloads: list[str] = Field(default_factory=list, max_items=4)
    code: str = ""


@dataclass
class VulnStrategy:
    http: HTTPClient
    req_materializer: RequestMaterializer
    binding_applier: BindingApplier
    recorder: VulnRecorder
    attack_payloads: list[str]
    payload_factory_generator: Optional[PayloadFactoryGenerator] = None
    llm_payload_generator: Optional[CodeBasedPayloadGenerator] = None
    llm_client: Optional[LLMClient] = None
    llm_model: Optional[str] = None
    llm_max_tries: int = 2
    skip_retry_on_payload_error: bool = False
    enable_llm: bool = False
    project_name: str = "Unknown"
    form_handler: Optional[FormHandler] = None
    need_trigger: bool = False
    # Attempts whose oracle is an out-of-band callback file, kept for a second
    # look once the run is over.
    pending_cases: list[VulnCase] = field(default_factory=list)
    vuln_type: ClassVar[VulnType]
    # Whether evidence for this type can land after the request returns. An
    # offline-download endpoint answers with a task id and fetches the URL from
    # a background worker, so the callback arrives seconds later and the
    # immediate check misses it.
    defers_evidence: ClassVar[bool] = False

    def normal_test(
        self, target: APIModel, test_field_ref: FieldRef, attack_payload: str
    ) -> tuple[HTTPResponse, RequestPayload]:
        assert isinstance(test_field_ref.param, BasicParameter)
        test_field_ref.param.backup()
        test_field_ref.param.value = attack_payload
        test_field_ref.param.value_source = ValueSource.VoAPI_TEST
        request_payload = self.req_materializer.materialize(target)
        test_field_ref.param.restore()
        files = self._build_files(test_field_ref, attack_payload)
        response = self._send_request(target, request_payload, files=files)
        return response, request_payload

    def _send_request(
        self,
        target: APIModel,
        request_payload: RequestPayload,
        files: Optional[dict[str, Any]] = None,
    ) -> HTTPResponse:
        if self.form_handler and files is None:
            try:
                request_payload = self.form_handler.prepare_payload(
                    target, request_payload
                )
            except Exception as exc:
                logger.warning("Form handler failed: %s", exc)
        return self.http.send(
            target.api_method,
            target.api_url,
            request_payload=request_payload,
            files=files,
        )

    def _build_files(
        self, test_field_ref: FieldRef, attack_payload: str
    ) -> Optional[dict[str, Any]]:
        return None

    def has_vuln(self, vuln_case: VulnCase) -> bool:
        return False

    def format_attack_payload(self, attack_payload: str, test_field_ref: FieldRef) -> str:
        return attack_payload

    def prepare_parameter(self, target: APIModel, edges: Iterable[DependencyEdge]):
        target_edges = [e for e in edges if e.consumer == target]
        bindings = [binding for edge in target_edges for binding in edge.bindings]
        self.binding_applier.apply_to_consumer(bindings)

    def trigger(self, vuln_case: VulnCase):
        NotImplementedError("Subclass should implement this method")

    def execute(
        self,
        target: APIModel,
        test_field_refs: Iterable[FieldRef],
        edges: Iterable[DependencyEdge],
        all_api_list: Optional[list[APIModel]] = None,
        dependency_preparer: Optional[VulnDependencyPreparer] = None,
    ):
        if self.vuln_type == VulnType.XSS and target.api_method.value == "GET":
            logger.info(
                "Skip GET for %s vuln: %s %s",
                self.vuln_type.value,
                target.api_method,
                target.api_url,
            )
            return
        needs_path_preparation = (
            self._llm_enabled() and self._has_unresolved_path_dependencies(target)
        )
        self.prepare_parameter(target, edges)
        needs_path_preparation = needs_path_preparation or (
            self._llm_enabled() and self._has_unresolved_path_dependencies(target)
        )
        if needs_path_preparation:
            if not self._prepare_dependencies(
                target,
                dependency_preparer,
                reason="pre-test path dependency",
            ):
                return
        for test_field_ref in test_field_refs:
            failures: list[dict[str, Any]] = []
            any_success = False
            formatted_payloads: list[str] = []
            for attack_payload in self.attack_payloads:
                attack_payload = self.format_attack_payload(attack_payload, test_field_ref)
                formatted_payloads.append(attack_payload)
                response, request_payload = self.normal_test(
                    target, test_field_ref, attack_payload
                )
                if response.ok:
                    any_success = True
                else:
                    failures.append(
                        self._build_failure_record(attack_payload, response, request_payload)
                    )
                self._record_attempt(test_field_ref, attack_payload, response)

            if self._llm_enabled() and (not any_success) and failures:
                self._handle_llm_after_failures(
                    target,
                    test_field_ref,
                    formatted_payloads,
                    failures,
                    dependency_preparer,
                )

    def _llm_enabled(self) -> bool:
        return bool(self.enable_llm and self.llm_client)

    def _record_attempt(
        self,
        test_field_ref: FieldRef,
        attack_payload: str,
        response: HTTPResponse,
    ) -> None:
        vuln_case = VulnCase(test_field_ref, self.vuln_type, attack_payload, response)
        if self.need_trigger:
            self.trigger(vuln_case)
        if self.has_vuln(vuln_case):
            self.recorder.record(vuln_case)
        elif self.defers_evidence:
            self.pending_cases.append(vuln_case)

    def recheck_pending_evidence(self) -> int:
        """Record attempts whose evidence arrived after the request returned."""
        confirmed = 0
        for vuln_case in self.pending_cases:
            if self.has_vuln(vuln_case):
                self.recorder.record(vuln_case)
                confirmed += 1
                logger.info(
                    "Deferred evidence confirmed %s: %s %s param=%s",
                    self.vuln_type.name,
                    vuln_case.target_field.api.api_method.value,
                    vuln_case.target_field.api.api_url,
                    vuln_case.target_field.name,
                )
        self.pending_cases = []
        return confirmed

    def _build_failure_record(
        self,
        attack_payload: str,
        response: HTTPResponse,
        request_payload: RequestPayload,
    ) -> dict[str, Any]:
        return {
            "attack_payload": attack_payload,
            "status_code": response.status_code,
            "response_text": self._truncate_text(response.text or "", 1200),
            "request_payload": {
                "path": request_payload.path,
                "query": request_payload.query,
                "body": request_payload.body,
            },
        }

    def _handle_llm_after_failures(
        self,
        target: APIModel,
        test_field_ref: FieldRef,
        formatted_payloads: list[str],
        failures: list[dict[str, Any]],
        dependency_preparer: Optional[VulnDependencyPreparer],
    ) -> None:
        path_dependencies_attempted = False
        if self._should_retry_path_dependencies(target, failures):
            path_dependencies_attempted = True
            if self._retest_with_dependencies(
                target,
                test_field_ref,
                formatted_payloads,
                dependency_preparer,
            ):
                return
            return

        plan = self._plan_with_llm(target, failures)
        if plan is None:
            return
        if plan.error_type == "dependency_error":
            self._retest_with_dependencies(
                target,
                test_field_ref,
                formatted_payloads,
                dependency_preparer,
            )
            return
        if plan.error_type != "parameter_error":
            return
        if self.skip_retry_on_payload_error:
            logger.info(
                "Vuln LLM plan: payload error, skipping retries for %s %s",
                target.api_method,
                target.api_url,
            )
            return
        if (
            not path_dependencies_attempted
            and self._should_retry_path_dependencies(target, failures)
        ):
            if not self._prepare_dependencies(
                target,
                dependency_preparer,
                reason="before payload-plan retry",
            ):
                return
        self._retest_with_payload_plan(
            target,
            test_field_ref,
            plan,
            formatted_payloads,
        )

    def _plan_with_llm(
        self,
        target: APIModel,
        failures: list[dict[str, Any]],
        error_text: Optional[str] = None,
    ) -> Optional[VulnPayloadPlan]:
        if not self.llm_client:
            return None
        failures_text = self._safe_json(
            failures if not error_text else [*failures, {"execution_error": error_text}]
        )
        code_blob = self._get_code_blob(target)
        prompt = build_vuln_payload_plan_prompt(
            project_name=self.project_name,
            vuln_type=self.vuln_type.value,
            method=target.api_method.value,
            path=target.api_url,
            failures_json=failures_text,
            code_blob=code_blob,
        )
        plan, usage = self.llm_client.ask_with_usage(
            prompt,
            VulnPayloadPlan,
            model=self.llm_model,
        )
        logger.info(
            "Vuln LLM plan: %s reason=%s payloads=%d usage=%s",
            plan.error_type,
            plan.reason,
            len(plan.payloads),
            usage,
        )
        return plan

    def _get_code_blob(self, target: APIModel) -> Optional[str]:
        if not self.payload_factory_generator:
            return None
        provider = getattr(self.payload_factory_generator, "code_context_provider", None)
        if not provider:
            return None
        try:
            return provider.get_code_blob(target.api_method.value, target.api_url)
        except Exception as exc:
            logger.warning("Failed to build code context for %s %s: %s",
                           target.api_method, target.api_url, exc)
            return None

    def _retest_with_dependencies(
        self,
        target: APIModel,
        test_field_ref: FieldRef,
        attack_payloads: list[str],
        dependency_preparer: Optional[VulnDependencyPreparer],
    ) -> bool:
        if not self._prepare_dependencies(
            target,
            dependency_preparer,
            reason="dependency retry",
        ):
            return False
        any_success = False
        for attack_payload in attack_payloads:
            response, _request_payload = self.normal_test(
                target, test_field_ref, attack_payload
            )
            if response.ok:
                any_success = True
            self._record_attempt(test_field_ref, attack_payload, response)
        return any_success

    def _prepare_dependencies(
        self,
        target: APIModel,
        dependency_preparer: Optional[VulnDependencyPreparer],
        reason: str,
    ) -> bool:
        if dependency_preparer is None:
            logger.info(
                "Vuln dependency preparation unavailable for %s %s (%s)",
                target.api_method,
                target.api_url,
                reason,
            )
            return False
        result = dependency_preparer.prepare(target, reason=reason)
        if result.ready:
            return True
        unresolved = ", ".join(
            f"{field.location.value}.{field.path.dotted()}"
            for field in result.unresolved_paths
        ) or "<none>"
        logger.info(
            "Vuln dependency preparation not ready for %s %s (%s; unresolved=%s)",
            target.api_method,
            target.api_url,
            result.reason,
            unresolved,
        )
        return False

    def _retest_with_payload_plan(
        self,
        target: APIModel,
        test_field_ref: FieldRef,
        plan: VulnPayloadPlan,
        fallback_payloads: list[str],
    ) -> None:
        if not plan.code.strip():
            logger.info("Vuln LLM plan: empty code")
            return
        tried_replan = False
        current_plan = plan
        while True:
            payloads = current_plan.payloads[:4] if current_plan.payloads else []
            if self.vuln_type == VulnType.SSRF:
                payloads = self._filter_ssrf_payloads(payloads, fallback_payloads)
            elif self.vuln_type == VulnType.XSS:
                payloads = self._filter_xss_payloads(payloads, fallback_payloads)
            if not payloads:
                if not current_plan.payloads:
                    logger.info("Vuln LLM plan: empty payload list")
                else:
                    logger.info("Vuln LLM plan: payloads did not preserve core, fallback")
                payloads = fallback_payloads[:4]
            executed_any = False
            exec_error: Optional[str] = None
            for payload in payloads:
                attack_payload = self.format_attack_payload(payload, test_field_ref)
                request_payload, error = self._materialize_from_plan_code(
                    current_plan.code, attack_payload
                )
                if request_payload is None:
                    exec_error = error or exec_error
                    continue
                executed_any = True
                request_payload = self._merge_with_target_defaults(target, request_payload)
                self._apply_dependency_overrides(target, request_payload)
                self._apply_attack_payload(request_payload, test_field_ref, attack_payload)
                files = self._build_files(test_field_ref, attack_payload)
                response = self._send_request(target, request_payload, files=files)
                self._record_attempt(test_field_ref, attack_payload, response)
            if executed_any or tried_replan or not exec_error:
                break
            tried_replan = True
            repaired = self._plan_with_llm(
                target,
                failures=[],
                error_text=exec_error,
            )
            if repaired is None or not repaired.code.strip():
                break
            current_plan = repaired

    def _materialize_from_plan_code(
        self,
        code: str,
        payload: str,
    ) -> tuple[Optional[RequestPayload], Optional[str]]:
        context = self._build_generation_context()
        wrapped_code = (
            "def make_payload(ctx, payload):\n"
            + "\n".join("    " + line for line in code.splitlines())
            + "\nresult = make_payload(ctx, payload)"
        )
        local_scope: dict[str, Any] = {"ctx": context, "payload": payload, "result": None}
        try:
            exec(wrapped_code, {}, local_scope)
        except Exception as exc:
            logger.exception("Failed to execute vuln payload plan code")
            return None, str(exc)
        result = local_scope.get("result")
        if not isinstance(result, dict):
            logger.warning("Vuln payload plan code did not return a dict")
            return None, "payload plan code did not return dict"
        path = result.get("path", {})
        query = result.get("query", {})
        body = result.get("body", {})
        header = result.get("header", {})
        if not isinstance(path, dict):
            path = {}
        if not isinstance(query, dict):
            query = {}
        if not isinstance(header, dict):
            header = {}
        if not isinstance(body, (dict, list)):
            body = {}
        header_default = self.req_materializer.header_default
        if header_default:
            header = {**header_default, **header}
        return RequestPayload(path=path, header=header, query=query, body=body), None

    def _merge_with_target_defaults(
        self,
        target: APIModel,
        request_payload: RequestPayload,
    ) -> RequestPayload:
        baseline = self.req_materializer.materialize(target)
        path = dict(baseline.path or {})
        for key, value in (request_payload.path or {}).items():
            if self._looks_unresolved_path_value(value):
                continue
            path[key] = value

        header = {**(baseline.header or {}), **(request_payload.header or {})}
        query = {**(baseline.query or {}), **(request_payload.query or {})}
        body = self._merge_body_defaults(baseline.body, request_payload.body)
        return RequestPayload(
            path=path,
            header=header,
            query=query,
            body=body,
            files=request_payload.files,
        )

    def _merge_body_defaults(self, baseline: Any, override: Any) -> Any:
        if isinstance(baseline, dict) and isinstance(override, dict):
            merged = deepcopy(baseline)
            return self._deep_merge_dict(merged, override)
        if isinstance(override, list):
            return override if override else baseline
        if override in ({}, [], None):
            return baseline
        return override

    def _deep_merge_dict(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        for key, value in override.items():
            if (
                isinstance(value, dict)
                and isinstance(base.get(key), dict)
            ):
                self._deep_merge_dict(base[key], value)
            else:
                base[key] = value
        return base

    def _build_generation_context(self) -> GenerationContext:
        if self.llm_payload_generator:
            return GenerationContext(
                dep=self.llm_payload_generator.dep_manager,
                fake=self.llm_payload_generator.fake,
            )
        return GenerationContext()

    def _filter_ssrf_payloads(
        self,
        candidates: list[str],
        original_payloads: list[str],
    ) -> list[str]:
        cores = []
        for payload in original_payloads:
            parsed = urlparse(payload)
            if parsed.scheme and parsed.netloc:
                cores.append(f"{parsed.scheme}://{parsed.netloc}")
            else:
                cores.append(payload)
        filtered: list[str] = []
        for cand in candidates:
            if any(core in cand for core in cores):
                filtered.append(cand)
        return filtered

    def _filter_xss_payloads(
        self,
        candidates: list[str],
        original_payloads: list[str],
    ) -> list[str]:
        filtered: list[str] = []
        for cand in candidates:
            if any(orig in cand for orig in original_payloads):
                filtered.append(cand)
        return filtered

    def _should_retry_path_dependencies(
        self,
        target: APIModel,
        failures: list[dict[str, Any]],
    ) -> bool:
        path_fields = self._path_request_fields(target)
        if not path_fields or not failures:
            return False
        if self._has_unresolved_path_dependencies(target):
            return True

        for failure in failures:
            request_payload = failure.get("request_payload")
            if not isinstance(request_payload, dict):
                continue
            path_payload = request_payload.get("path")
            if not isinstance(path_payload, dict):
                continue
            for field in path_fields:
                value = self._get_by_path(
                    path_payload,
                    field.path.segments or (field.name,),
                )
                if self._looks_unresolved_path_value(value):
                    return True
        return False

    def _has_unresolved_path_dependencies(self, target: APIModel) -> bool:
        return any(
            isinstance(field.param, BasicParameter)
            and (
                field.param.value_source in (ValueSource.NONE, ValueSource.VoAPI_RANDOM)
                or self._looks_unresolved_path_value(field.param.value)
            )
            for field in self._path_request_fields(target)
        )

    def _path_request_fields(self, target: APIModel) -> list[FieldRef]:
        return [
            field
            for field in self.binding_applier.extractor.request_fields(target)
            if field.location == ParamLocation.PATH
        ]

    def _looks_unresolved_path_value(self, value: Any) -> bool:
        return looks_unresolved_path_value(value)

    def _is_permission_error(self, response: HTTPResponse) -> bool:
        if response.status_code in (401, 403):
            return True
        text = (response.text or "").lower()
        indicators = (
            "unauthorized",
            "forbidden",
            "permission",
            "missing scope",
            "insufficient scope",
            "not allowed",
            "access denied",
        )
        return any(ind in text for ind in indicators)

    def _classify_failure(
        self,
        target: APIModel,
        response: HTTPResponse,
        request_payload: RequestPayload,
    ) -> Optional[FailureClassification]:
        if not self.llm_client:
            return None
        payload_dict = {
            "path": request_payload.path,
            "query": request_payload.query,
            "body": request_payload.body,
        }
        result, usage = classify_failure(
            self.llm_client,
            consumer_method=target.api_method.value,
            consumer_path=target.api_url,
            failed_method=target.api_method.value,
            failed_path=target.api_url,
            status_code=str(response.status_code),
            response_text=response.text,
            request_payload=payload_dict,
            model=self.llm_model,
            project_name=self.project_name,
        )
        logger.info(
            "Vuln LLM failure classification: %s reason=%s missing=%s usage=%s",
            result.error_type,
            result.reason,
            result.missing_fields,
            usage,
        )
        return result

    def _build_payload_llm(
        self,
        target: APIModel,
        runtime_error: Optional[str] = None,
    ) -> Optional[RequestPayload]:
        if not self.llm_payload_generator:
            return None
        if self.payload_factory_generator and (runtime_error or not target.payload_factory_code):
            result, _usage = self.payload_factory_generator.generate(
                target,
                model=self.llm_model,
                max_attempts=2,
                runtime_error=runtime_error,
            )
            if result is None:
                return None
        try:
            return self.llm_payload_generator.generate(target)
        except Exception:
            logger.exception("Failed to materialize LLM payload for %s", target.api_url)
            return None

    def _apply_attack_payload(
        self,
        request_payload: RequestPayload,
        test_field_ref: FieldRef,
        attack_payload: str,
    ) -> None:
        if isinstance(test_field_ref.param, BasicParameter):
            if test_field_ref.param.param_type == ParamType.FILE:
                return
        target = self._section_for(test_field_ref.location, request_payload)
        if target is None:
            return
        segments = test_field_ref.path.segments or (test_field_ref.name,)
        self._set_by_path(target, segments, attack_payload)

    def _apply_dependency_overrides(
        self,
        target: APIModel,
        request_payload: RequestPayload,
    ) -> None:
        extractor = self.binding_applier.extractor
        for field in extractor.request_fields(target):
            param = field.param
            if not isinstance(param, BasicParameter):
                continue
            if param.value is None:
                continue
            if param.value_source not in (
                ValueSource.VoAPI_PRODUCER,
                ValueSource.VoAPI_CONSUMER,
            ):
                continue
            section = self._section_for(field.location, request_payload)
            if section is None:
                continue
            segments = field.path.segments or (field.name,)
            self._set_by_path(section, segments, param.value)

    def _section_for(
        self, location: ParamLocation, request_payload: RequestPayload
    ) -> Optional[dict[str, Any]]:
        if location == ParamLocation.PATH:
            return request_payload.path
        if location == ParamLocation.HEADER:
            return request_payload.header
        if location == ParamLocation.QUERY:
            return request_payload.query
        if location == ParamLocation.BODY:
            return request_payload.body if isinstance(request_payload.body, dict) else None
        return None

    def _set_by_path(
        self, target: dict[str, Any], segments: tuple[str, ...], value: Any
    ) -> None:
        if not segments:
            return
        cur = target
        for seg in segments[:-1]:
            child = cur.get(seg)
            if not isinstance(child, dict):
                child = {}
            cur[seg] = child
            cur = child
        cur[segments[-1]] = value

    def _get_by_path(self, target: dict[str, Any], segments: tuple[str, ...]) -> Any:
        cur: Any = target
        for seg in segments:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(seg)
        return cur

    def _build_runtime_error(
        self,
        response: HTTPResponse,
        request_payload: RequestPayload,
        prev_code: Optional[str],
    ) -> str:
        payload = {
            "path": request_payload.path,
            "query": request_payload.query,
            "body": request_payload.body,
        }
        code_snippet = prev_code or "<none>"
        return (
            "Request failed.\n"
            f"status_code: {response.status_code}\n"
            f"response: {response.text}\n"
            f"request_payload: {payload}\n"
            f"previous_code: {code_snippet}"
        )

    def _safe_json(self, payload: Any) -> str:
        try:
            return json.dumps(payload, ensure_ascii=False)
        except Exception:
            return "<unserializable payload>"

    def _truncate_text(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "\n...<truncated>"
