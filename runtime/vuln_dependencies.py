from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
from typing import Any, Callable, Iterable, Optional

from matching.binding import Binding
from matching.llm_dependency import resolve_dependencies_llm
from models.api_model import APIModel
from models.parameter import BasicParameter
from models.ref import FieldRef
from models.types import ParamLocation, ValueSource
from planning.graph import SequencePlan
from planning.sequence import OverrideResolver, SequencePlanner
from runtime.exec.executor import CallRecord, ExecutionResult, SequenceExecutor
from runtime.materializers.flattener import flatten_json
from utils.llm_client import LLMClient


logger = logging.getLogger(__name__)


def looks_unresolved_path_value(value: Any) -> bool:
    """Identify the placeholder values generated before a real dependency exists."""
    if value is None or value == "":
        return True
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return True
    if "{" in candidate and "}" in candidate:
        return True
    if re.fullmatch(r"test\d+", candidate):
        return True
    if re.fullmatch(r"566048da-ed19-4cd3-8e0a-b7e0e1ec4d\d+", candidate):
        return True
    return False


def _normalized_response_path(segments: tuple[str, ...]) -> tuple[str, ...]:
    """Drop parser-only root-array placeholders while keeping full field paths."""
    return tuple(segment for segment in segments if segment and segment != ".")


@dataclass(frozen=True)
class ResolvedDependencyValue:
    binding: Binding
    value: Any


@dataclass(frozen=True)
class DependencyPreparationResult:
    ready: bool
    reason: str
    bindings: tuple[Binding, ...] = ()
    resolved_values: tuple[ResolvedDependencyValue, ...] = ()
    unresolved_paths: tuple[FieldRef, ...] = ()
    plan: Optional[SequencePlan] = None
    execution: Optional[ExecutionResult] = None
    attempts: int = 0


@dataclass
class VulnDependencyPreparer:
    """Prepare real dependency values for a later vulnerability attack request.

    The sequence executor owns producer execution.  This class deliberately
    extracts values from the execution result rather than APIModel response
    state, so a failed producer can never leak a spec or stale value into the
    target request.
    """

    planner: SequencePlanner
    executor: SequenceExecutor
    all_api_list: list[APIModel]
    llm_client: LLMClient
    llm_model: Optional[str] = None
    project_name: str = "Unknown"
    max_tries: int = 1
    execute_plan: Optional[Callable[[SequencePlan], ExecutionResult]] = None
    llm_resolver: Callable[..., list[Binding]] = resolve_dependencies_llm
    _cache: dict[APIModel, DependencyPreparationResult] = field(
        default_factory=dict, init=False, repr=False
    )

    def prepare(
        self,
        target: APIModel,
        *,
        reason: str,
    ) -> DependencyPreparationResult:
        cached = self._cache.get(target)
        if cached is not None:
            logger.info(
                "Vuln dependency preparation cache hit for %s %s: ready=%s",
                target.api_method,
                target.api_url,
                cached.ready,
            )
            if cached.ready:
                self._apply_resolved_values(cached.resolved_values)
            return cached

        if not self.all_api_list:
            return self._cache_result(
                target,
                DependencyPreparationResult(
                    ready=False,
                    reason="missing API catalog",
                ),
            )

        last_result = DependencyPreparationResult(
            ready=False,
            reason="LLM returned no usable dependency bindings",
        )
        history_entries: list[str] = []
        for attempt in range(1, max(1, int(self.max_tries)) + 1):
            history_text = "\n\n".join(history_entries) if history_entries else None
            try:
                llm_bindings = self.llm_resolver(
                    target,
                    self.all_api_list,
                    model=self.llm_model,
                    llm_client=self.llm_client,
                    history_text=history_text,
                    project_name=self.project_name,
                    purpose="dep_resolve_vuln",
                )
            except Exception as exc:
                logger.warning(
                    "Vuln dependency preparation failed to resolve bindings for %s %s: %s",
                    target.api_method,
                    target.api_url,
                    exc,
                )
                last_result = DependencyPreparationResult(
                    ready=False,
                    reason=f"LLM dependency resolution failed: {exc}",
                    attempts=attempt,
                )
                history_entries.append(last_result.reason)
                continue

            llm_bindings = [
                binding
                for binding in llm_bindings
                if binding.consumer.api == target and binding.producer.api != target
            ]
            if not llm_bindings:
                last_result = DependencyPreparationResult(
                    ready=False,
                    reason="LLM returned no target dependency bindings",
                    attempts=attempt,
                )
                history_entries.append(last_result.reason)
                continue

            merged_bindings = self._merge_bindings(target, llm_bindings)
            resolver = OverrideResolver(self.planner.resolver, {target: merged_bindings})
            plan = SequencePlanner(resolver=resolver).build(target, self.all_api_list)
            preparation_plan = plan.remove_target_api()
            execution = self._run(preparation_plan)
            resolved = self._collect_fresh_values(
                llm_bindings,
                plan,
                preparation_plan,
                execution,
            )
            result = self._validate_and_apply(
                target,
                llm_bindings,
                resolved,
                plan,
                execution,
                attempt,
            )
            if result.ready:
                logger.info(
                    "Vuln dependency preparation ready for %s %s after %d attempt(s)",
                    target.api_method,
                    target.api_url,
                    attempt,
                )
                return self._cache_result(target, result)

            last_result = result
            history_entries.append(self._history_entry(attempt, result))

        logger.info(
            "Vuln dependency preparation not ready for %s %s (%s)",
            target.api_method,
            target.api_url,
            last_result.reason,
        )
        return self._cache_result(target, last_result)

    def _cache_result(
        self,
        target: APIModel,
        result: DependencyPreparationResult,
    ) -> DependencyPreparationResult:
        self._cache[target] = result
        return result

    def _run(self, plan: SequencePlan) -> ExecutionResult:
        if self.execute_plan is not None:
            return self.execute_plan(plan)
        return self.executor.run(plan)

    def _merge_bindings(
        self,
        target: APIModel,
        llm_bindings: list[Binding],
    ) -> list[Binding]:
        pool = [api for api in self.all_api_list if api != target]
        merged = list(self.planner.resolver.resolve(target, pool))
        seen = {self._binding_key(binding) for binding in merged}
        for binding in llm_bindings:
            key = self._binding_key(binding)
            if key in seen:
                continue
            merged.append(binding)
            seen.add(key)
        return merged

    def _collect_fresh_values(
        self,
        bindings: list[Binding],
        full_plan: SequencePlan,
        preparation_plan: SequencePlan,
        execution: ExecutionResult,
    ) -> list[ResolvedDependencyValue]:
        calls = self._latest_calls(preparation_plan, execution)
        successful_chain: dict[APIModel, bool] = {}
        resolved: list[ResolvedDependencyValue] = []

        for binding in bindings:
            producer = binding.producer.api
            if not self._producer_chain_succeeded(
                producer,
                full_plan,
                preparation_plan,
                calls,
                successful_chain,
                set(),
            ):
                logger.info(
                    "Vuln dependency producer chain failed: %s %s",
                    producer.api_method,
                    producer.api_url,
                )
                continue

            call = calls.get(self._api_key(producer))
            if call is None:
                continue
            value = self._response_value(call, binding.producer)
            if value is None or value == "" or looks_unresolved_path_value(value):
                logger.info(
                    "Vuln dependency value unavailable for %s -> %s",
                    binding.producer,
                    binding.consumer,
                )
                continue
            resolved.append(ResolvedDependencyValue(binding, value))
        return resolved

    def _validate_and_apply(
        self,
        target: APIModel,
        bindings: list[Binding],
        resolved: list[ResolvedDependencyValue],
        plan: SequencePlan,
        execution: ExecutionResult,
        attempts: int,
    ) -> DependencyPreparationResult:
        values_by_consumer: dict[tuple, ResolvedDependencyValue] = {}
        conflicts: set[tuple] = set()
        for item in resolved:
            key = self._field_key(item.binding.consumer)
            previous = values_by_consumer.get(key)
            if previous is not None and previous.value != item.value:
                conflicts.add(key)
                continue
            values_by_consumer[key] = item

        path_fields = self._path_fields(target)
        unresolved_paths: list[FieldRef] = []
        for field in path_fields:
            key = self._field_key(field)
            item = values_by_consumer.get(key)
            if (
                key in conflicts
                or item is None
                or not isinstance(field.param, BasicParameter)
                or looks_unresolved_path_value(item.value)
            ):
                unresolved_paths.append(field)

        if path_fields and unresolved_paths:
            return DependencyPreparationResult(
                ready=False,
                reason="not every path field has a fresh producer value",
                bindings=tuple(bindings),
                resolved_values=tuple(resolved),
                unresolved_paths=tuple(unresolved_paths),
                plan=plan,
                execution=execution,
                attempts=attempts,
            )

        if not path_fields and not values_by_consumer:
            return DependencyPreparationResult(
                ready=False,
                reason="no fresh dependency values were produced",
                bindings=tuple(bindings),
                resolved_values=tuple(resolved),
                plan=plan,
                execution=execution,
                attempts=attempts,
            )

        # Apply only after the complete gate passes.  Partial results must not
        # become persistent target state for a later vulnerability request.
        self._apply_resolved_values(values_by_consumer.values())

        return DependencyPreparationResult(
            ready=True,
            reason="all required path fields resolved from this execution",
            bindings=tuple(bindings),
            resolved_values=tuple(values_by_consumer.values()),
            plan=plan,
            execution=execution,
            attempts=attempts,
        )

    def _apply_resolved_values(
        self,
        resolved_values: Iterable[ResolvedDependencyValue],
    ) -> None:
        for item in resolved_values:
            consumer = item.binding.consumer
            if not isinstance(consumer.param, BasicParameter):
                continue
            consumer.param.value = item.value
            consumer.param.value_source = ValueSource.VoAPI_CONSUMER

    def _latest_calls(
        self,
        plan: SequencePlan,
        execution: ExecutionResult,
    ) -> dict[tuple, CallRecord]:
        plan_keys = {self._api_key(api) for api in plan.ordered_apis}
        latest: dict[tuple, CallRecord] = {}
        for call in execution.calls:
            key = (call.api_method, call.api_url)
            if key in plan_keys:
                latest[key] = call
        return latest

    def _producer_chain_succeeded(
        self,
        api: APIModel,
        full_plan: SequencePlan,
        preparation_plan: SequencePlan,
        calls: dict[tuple, CallRecord],
        cache: dict[APIModel, bool],
        visiting: set[APIModel],
    ) -> bool:
        if api in cache:
            return cache[api]
        if api in visiting:
            cache[api] = False
            return False

        call = calls.get(self._api_key(api))
        if call is None or not call.response.ok:
            cache[api] = False
            return False

        planned_apis = set(preparation_plan.ordered_apis)
        visiting.add(api)
        for edge in full_plan.edges:
            if edge.consumer != api or edge.producer not in planned_apis:
                continue
            if not self._producer_chain_succeeded(
                edge.producer,
                full_plan,
                preparation_plan,
                calls,
                cache,
                visiting,
            ):
                visiting.remove(api)
                cache[api] = False
                return False
        visiting.remove(api)
        cache[api] = True
        return True

    def _response_value(self, call: CallRecord, field: FieldRef) -> Any:
        if field.location == ParamLocation.HEADER:
            wanted = field.path.segments or (field.name,)
            if len(wanted) != 1:
                return None
            for name, value in call.response.headers.items():
                if name.lower() == wanted[0].lower():
                    return value
            return None

        payload = call.response.json()
        if payload is None:
            return None
        wanted = _normalized_response_path(field.path.segments)
        for item in flatten_json(payload):
            path = _normalized_response_path(item.path.segments)
            if path == wanted:
                return item.value
        return None

    def _path_fields(self, target: APIModel) -> list[FieldRef]:
        return [
            field
            for field in self.executor.binding_applier.extractor.request_fields(target)
            if field.location == ParamLocation.PATH
        ]

    def _history_entry(
        self,
        attempt: int,
        result: DependencyPreparationResult,
    ) -> str:
        unresolved = ", ".join(
            f"{field.location.value}.{field.path.dotted()}"
            for field in result.unresolved_paths
        ) or "<none>"
        return (
            f"Attempt {attempt}: {result.reason}; "
            f"unresolved path fields: {unresolved}"
        )

    def _binding_key(self, binding: Binding) -> tuple:
        return (
            self._field_key(binding.consumer),
            binding.producer.api,
            binding.producer.location,
            binding.producer.path.segments,
            binding.producer.path.array_index,
        )

    def _field_key(self, field: FieldRef) -> tuple:
        return (
            field.location,
            field.path.segments,
            field.path.array_index,
        )

    def _api_key(self, api: APIModel) -> tuple:
        return (api.api_method, api.api_url)
