# runtime/exec/executor.py

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import re

from urllib3 import request
from matching.binding import Binding
from code_analyzer.payload_agent import PayloadFactoryGenerator
from models.parameter import BasicParameter
from planning.graph import SequencePlan, DependencyEdge
from models.api_model import APIModel
from runtime.bindings.applier import BindingApplier
from runtime.materializers.request import RequestMaterializer
from runtime.materializers.response import ResponseMaterializer
from runtime.url_harvest import harvest_urls
from runtime.http.client import HTTPClient, HTTPResponse, ERROR_STATUS_CODE
from models.types import APIMethod, ParamLocation, ValueSource
from typing import Any, Optional
import logging
from dataclasses import replace

from runtime.multipart import MultipartHandler
from runtime.form import FormHandler

logger = logging.getLogger(__name__)

@dataclass
class CallRecord:
    api_url: str
    api_method: APIMethod
    request_dump: dict[str, Any]
    response: HTTPResponse

    def __repr__(self):
        return f"CallRecord(api_url={self.api_url}, api_method={self.api_method}, request_dump={self.request_dump}, response={self.response})"


@dataclass
class ExecutionResult:
    success: bool
    calls: list[CallRecord] = field(default_factory=list)

    def __repr__(self):
        return (
            "ExecutionResult(success={self.success}, calls=\n"
            + "\n".join([str(c) for c in self.calls])
            + ")"
        )


class SequenceExecutor:

    req_mat: RequestMaterializer
    res_mat: ResponseMaterializer
    http: HTTPClient
    binding_applier: BindingApplier
    payload_generator: Optional["PayloadGenerator"]
    payload_factory_generator: Optional[PayloadFactoryGenerator]
    rule_payload_generator: Optional["PayloadGenerator"]
    payload_mode: str
    llm_runs_per_code: int
    llm_regen_rounds: int
    enable_payload_regen: bool
    # Diagnosis from the LLM failure classifier, when the runner has one. It used
    # to be logged and discarded: the parameter_error branch just re-ran the same
    # flow, so a correct diagnosis changed nothing. Feeding it into the payload
    # prompt is what makes that branch do work.
    failure_hint: Optional[str]
    ledger: Optional["RecoveryLedger"]
    multipart_handler: Optional["MultipartHandler"]
    form_handler: Optional["FormHandler"]
    max_attempts_per_api: int
    _attempt_budget: dict[tuple, int]
    _permanent_failures: set[tuple]

    def __init__(
        self,
        http: HTTPClient,
        req_mat: RequestMaterializer,
        res_mat: ResponseMaterializer,
        binding_applier: BindingApplier,
        payload_generator: Optional["PayloadGenerator"] = None,
        payload_factory_generator: Optional[PayloadFactoryGenerator] = None,
        rule_payload_generator: Optional["PayloadGenerator"] = None,
        payload_mode: str = "rule",
        llm_runs_per_code: int = 3,
        llm_regen_rounds: int = 2,
        enable_payload_regen: bool = True,
        multipart_handler: Optional["MultipartHandler"] = None,
        form_handler: Optional["FormHandler"] = None,
        max_attempts_per_api: int = 5,
    ):
        self.http = http
        self.req_mat = req_mat
        self.res_mat = res_mat
        self.binding_applier = binding_applier
        self.payload_generator = payload_generator
        self.payload_factory_generator = payload_factory_generator
        self.rule_payload_generator = rule_payload_generator
        self.payload_mode = payload_mode
        self.llm_runs_per_code = llm_runs_per_code
        self.llm_regen_rounds = llm_regen_rounds
        self.enable_payload_regen = enable_payload_regen
        self.failure_hint = None
        self.ledger = None
        self.multipart_handler = multipart_handler
        self.form_handler = form_handler
        self.max_attempts_per_api = max(1, int(max_attempts_per_api))
        self._attempt_budget = {}
        self._permanent_failures = set()
        # Render URLs the app returned in responses, fed to the XSS walker as extra seeds
        # so it can reach app-generated pages (e.g. token-gated draft previews).
        self.harvested_urls: set[str] = set()
        # Concrete path-parameter values seen while sending, so a resource we injected
        # into can later be re-addressed by its sibling read endpoints.
        self.resource_path_values: dict[str, Any] = {}
        # Resources being created, keyed by the collection endpoint that created
        # them. Each record keeps the parent path parameters alongside the new child
        # id, so the pair can later be replayed together.
        #
        # This exists because binding each field independently produces incoherent
        # tuples for a nested resource -- in the worst case the same id fills both a
        # parent and its child path parameter, or a child is addressed under a
        # parent it does not belong to. Field names cannot express "this child
        # belongs to that parent"; the path shape can.
        self.resource_records: dict[str, list[dict[str, Any]]] = {}
        # Bumped per plan so a record from the chain we just ran is preferred over
        # an older one left behind by a previous endpoint's plan.
        self._plan_generation = 0
        self._generation_held = 0

    def _api_key(self, api: APIModel) -> tuple:
        return (api.api_method, api.api_url)

    def _budget_remaining(self, api: APIModel) -> int:
        key = self._api_key(api)
        used = self._attempt_budget.get(key, 0)
        return max(0, self.max_attempts_per_api - used)

    def _consume_budget(self, api: APIModel) -> int:
        key = self._api_key(api)
        used = self._attempt_budget.get(key, 0) + 1
        self._attempt_budget[key] = used
        return used

    def reset_attempt_budget(self, api: APIModel) -> None:
        """Give one API a fresh attempt budget.

        The classifier-driven parameter retry runs after a full pass has already
        spent this API's budget; without clearing it the retry is skipped as
        "budget exhausted" and the branch silently does nothing.
        """
        self._attempt_budget.pop(self._api_key(api), None)
        self._permanent_failures.discard(self._api_key(api))

    def _make_skip_response(self, reason: str) -> HTTPResponse:
        return HTTPResponse(status_code=ERROR_STATUS_CODE, text=reason, headers={})

    @contextmanager
    def hold_plan_generation(self):
        """Keep one resource generation across a multi-step repair chain.

        run() bumps the generation per plan, so a chain that creates a resource
        in one step and activates it in the next saw the second step as a
        different generation and declined to reuse the first step's record.
        Observed on Appwrite: the repair chain created a tag on one function and
        then activated a tag on a function it had never touched, so
        POST /functions/{functionId}/executions kept answering
        "Tag not found. Deploy tag before trying to execute a function".
        """
        self._plan_generation += 1
        self._generation_held += 1
        try:
            yield self._plan_generation
        finally:
            self._generation_held -= 1

    def run(self, plan: SequencePlan) -> ExecutionResult:

        result = ExecutionResult(success=True)
        self._attempt_budget = {}
        self._permanent_failures = set()
        if not self._generation_held:
            self._plan_generation += 1
        edges_by_consumers: dict[APIModel, list[Binding]] = {}
        producers_by_consumer: dict[APIModel, set[APIModel]] = {}
        for e in plan.edges:
            edges_by_consumers.setdefault(e.consumer, []).extend(e.bindings)
            producers_by_consumer.setdefault(e.consumer, set()).add(e.producer)
        api_success: dict[APIModel, bool] = {}

        backup_open_required = self.req_mat.open_required
        for idx, api in enumerate(plan.ordered_apis):
            key = self._api_key(api)
            if key in self._permanent_failures:
                reason = f"SKIPPED: known failing endpoint {api.api_method.value} {api.api_url}"
                logger.info(reason)
                result.calls.append(
                    CallRecord(
                        api_url=api.api_url,
                        api_method=api.api_method,
                        request_dump={
                            "path": {},
                            "header": {},
                            "query": {},
                            "body": {},
                            "files": None,
                            "note": reason,
                        },
                        response=self._make_skip_response(reason),
                    )
                )
                api_success[api] = False
                if idx == len(plan.ordered_apis) - 1:
                    result.success = False
                continue
            failed_deps = self._failed_dependencies(
                api, producers_by_consumer, api_success
            )
            if failed_deps:
                logger.info(
                    "Dependencies failed for %s %s, continuing anyway: %s",
                    api.api_method,
                    api.api_url,
                    ", ".join(
                        f"{dep.api_method.value} {dep.api_url}"
                        for dep in failed_deps
                    ),
                )
            bindings = edges_by_consumers.get(api, [])
            if self.payload_mode == "mix":
                success = self._run_api_with_mix(api, bindings, result)
            elif self.payload_factory_generator and self.payload_generator:
                success = self._run_api_with_llm(api, bindings, result)
            else:
                success = self._run_api_with_rules(
                    api,
                    bindings,
                    result,
                    allow_regen=self.enable_payload_regen,
                )
            api_success[api] = success
            if not success:
                self._permanent_failures.add(key)
            if not success and idx == len(plan.ordered_apis) - 1:
                result.success = False

        self.req_mat.open_required = backup_open_required
        return result

    def _run_api_with_rules(
        self,
        api: APIModel,
        bindings: list[Binding],
        result: ExecutionResult,
        payload_generator: Optional["PayloadGenerator"] = None,
        allow_regen: bool = True,
        failures: Optional[list[dict[str, Any]]] = None,
    ) -> bool:
        success = False
        regen_attempted = False
        retry_count = 0
        max_rule_attempts = 5
        while not success and retry_count < max_rule_attempts:
            retry_count += 1
            api.reset_request_values()
            self.binding_applier.apply_to_consumer(bindings)

            open_required = (retry_count % 2 == 1)
            self.req_mat.open_required = open_required
            generator = payload_generator if payload_generator is not None else self.payload_generator
            if generator:
                request_payload = generator.generate(api)
            else:
                request_payload = self.req_mat.materialize(api)
                if api.api_method == APIMethod.GET and retry_count == 3:
                    request_payload = self.req_mat.materialize_get_empty(api)

            self._apply_dependency_overrides(api, request_payload)

            resp, files_summary = self._send_request(
                api,
                request_payload,
                attempt=retry_count,
                last_response=failures[-1]["response"] if failures else None,
            )
            result.calls.append(
                CallRecord(
                    api_url=api.api_url,
                    api_method=api.api_method,
                    request_dump={
                        "path": request_payload.path,
                        "header": request_payload.header,
                        "query": request_payload.query,
                        "body": request_payload.body,
                        "files": files_summary,
                    },
                    response=resp,
                )
            )
            # resp.ok, not the status code: with --custom_judge a 200 whose body
            # says the operation failed must not close a repair as successful.
            if self.ledger is not None:
                self.ledger.record_outcome(
                    f"{api.api_method.value} {api.api_url}", resp.ok, resp.status_code)
            if not resp.ok:
                if failures is not None:
                    failures.append(self._build_failure_record(resp, request_payload, retry_count))
                if (allow_regen and not regen_attempted and self._maybe_regenerate_payload(
                        api, resp, request_payload)):
                    regen_attempted = True
                    continue
                continue
            success = True
            self.res_mat.apply(api, resp)
        return success

    def _run_api_with_mix(self, api: APIModel, bindings: list[Binding],
                          result: ExecutionResult) -> bool:
        failures: list[dict[str, Any]] = []
        logger.info("Mix mode rule attempt for %s %s", api.api_method, api.api_url)
        success = self._run_api_with_rules(
            api,
            bindings,
            result,
            payload_generator=self.rule_payload_generator,
            allow_regen=False,
            failures=failures,
        )
        if success:
            return True
        if self._budget_remaining(api) == 0:
            logger.info(
                "Mix mode LLM budget exhausted for %s %s, skipping LLM",
                api.api_method,
                api.api_url,
            )
            return False
        if not self.payload_factory_generator or not self.payload_generator:
            return False
        attempts = [{"code": "<rule-based>", "failures": failures}]
        runtime_error = self._build_runtime_error_history(attempts)
        logger.info("Mix mode switching to LLM for %s %s", api.api_method, api.api_url)
        if self.ledger is not None:
            from runtime.recovery_ledger import SITE_MIX_ESCALATION
            self.ledger.record_repair(
                "param", SITE_MIX_ESCALATION, f"{api.api_method.value} {api.api_url}",
                {"rule_failures": len(failures)})
        result_obj, _usage = self.payload_factory_generator.generate(
            api, runtime_error=runtime_error, max_attempts=2
        )
        if result_obj is None:
            logger.info("Mix mode LLM generation failed for %s %s", api.api_method, api.api_url)
            return False
        return self._run_api_with_llm(api, bindings, result)

    def _run_api_with_llm(self, api: APIModel, bindings: list[Binding],
                          result: ExecutionResult) -> bool:
        attempts: list[dict[str, Any]] = []
        for code_round in range(self.llm_regen_rounds + 1):
            failures: list[dict[str, Any]] = []
            for run_idx in range(1, self.llm_runs_per_code + 1):
                if self._budget_remaining(api) == 0:
                    logger.info(
                        "LLM budget exhausted for %s %s",
                        api.api_method,
                        api.api_url,
                    )
                    return False
                api.reset_request_values()
                self.binding_applier.apply_to_consumer(bindings)
                request_payload = self.payload_generator.generate(api)
                # Whether the regenerated value or the bound value should win is
                # decided by what the last attempt failed with, not by the fact that
                # a regeneration happened. A conflict means the identifier must be
                # fresh, so the factory's value wins; anything else -- a 404 above
                # all -- means it must name something that exists, and the factory
                # will happily invent `default-basket`. Keying this off `code_round`
                # alone fixed POST /api/baskets/{name} and broke
                # DELETE /api/baskets/{name} and GET /baskets/{name}/responses/{method}
                # in the same run, which is how the distinction was found.
                self._apply_dependency_overrides(
                    api, request_payload,
                    keep_generated=self._last_failure_was_conflict(attempts),
                )

                resp, files_summary = self._send_request(
                    api,
                    request_payload,
                    attempt=run_idx,
                    last_response=failures[-1]["response"] if failures else None,
                    count_budget=True,
                )
                result.calls.append(
                    CallRecord(
                        api_url=api.api_url,
                        api_method=api.api_method,
                        request_dump={
                            "path": request_payload.path,
                            "header": request_payload.header,
                            "query": request_payload.query,
                            "body": request_payload.body,
                            "files": files_summary,
                        },
                        response=resp,
                    )
                )
                if self.ledger is not None:
                    self.ledger.record_outcome(
                        f"{api.api_method.value} {api.api_url}", resp.ok, resp.status_code)
                if resp.ok:
                    self.res_mat.apply(api, resp)
                    return True
                failures.append(
                    self._build_failure_record(resp, request_payload, run_idx)
                )

            attempts.append(
                {
                    "code": api.payload_factory_code,
                    "failures": failures,
                }
            )
            if code_round >= self.llm_regen_rounds:
                break
            if self._budget_remaining(api) == 0:
                logger.info(
                    "LLM budget exhausted during regen for %s %s",
                    api.api_method,
                    api.api_url,
                )
                break
            runtime_error = self._build_runtime_error_history(attempts)
            logger.info(
                "Runtime LLM regen for %s %s round=%d/%d",
                api.api_method,
                api.api_url,
                code_round + 1,
                self.llm_regen_rounds,
            )
            result_obj, _usage = self.payload_factory_generator.generate(
                api, runtime_error=runtime_error, max_attempts=2
            )
            if result_obj is None:
                logger.info("Runtime LLM regen failed for %s %s", api.api_method, api.api_url)
                break
            logger.info("Runtime LLM regen succeeded for %s %s", api.api_method, api.api_url)
        return False

    # A create rejected for reusing an identifier, as opposed to a request that
    # named something which does not exist. The strings are the ones these SUTs
    # actually answer with: Rbaskets says "bucket already exists", Gitea "already
    # exists", GitLab "has already been taken".
    _CONFLICT_MARKERS = (
        "already exist", "already been taken", "duplicate", "is taken",
        "in use", "conflict", "已存在", "重复",
    )

    @classmethod
    def _last_failure_was_conflict(cls, attempts: list[dict[str, Any]]) -> bool:
        """Did the most recent attempt fail because the identifier was taken?"""
        for attempt in reversed(attempts):
            failures = attempt.get("failures") or []
            if not failures:
                continue
            last = failures[-1]
            if last.get("status") == 409:
                return True
            text = str(last.get("response") or "").lower()
            return any(marker in text for marker in cls._CONFLICT_MARKERS)
        return False

    def _build_failure_record(self, response: HTTPResponse, request_payload,
                              run_idx: int) -> dict[str, Any]:
        payload = {
            "path": request_payload.path,
            "query": request_payload.query,
            "body": request_payload.body,
        }
        payload_json = self._safe_json(payload)
        return {
            "run": run_idx,
            "status": response.status_code,
            "response": self._truncate_text(response.text, 1000),
            "payload": self._truncate_text(payload_json, 2000),
        }

    def _build_runtime_error_history(self,
                                     attempts: list[dict[str, Any]]) -> str:
        lines: list[str] = []
        if self.failure_hint:
            lines.append(f"[DIAGNOSIS] {self.failure_hint}")
        for idx, attempt in enumerate(attempts, start=1):
            code = attempt.get("code") or "<none>"
            lines.append(f"[CODE ATTEMPT {idx}]")
            lines.append(self._truncate_text(code, 2000))
            failures = attempt.get("failures", [])
            for fail in failures:
                lines.append(
                    f"- Run {fail.get('run')}: HTTP {fail.get('status')}; "
                    f"Response: {fail.get('response')}; "
                    f"Payload: {fail.get('payload')}"
                )
        return "\n".join(lines)

    def _safe_json(self, payload: Any) -> str:
        try:
            return json.dumps(payload, ensure_ascii=False, default=self._json_fallback)
        except Exception:
            return "<unserializable payload>"

    def _json_fallback(self, obj: Any) -> str:
        if isinstance(obj, (bytes, bytearray, memoryview)):
            return f"<bytes length={len(obj)}>"
        return str(obj)

    def _failed_dependencies(
        self,
        api: APIModel,
        producers_by_consumer: dict[APIModel, set[APIModel]],
        api_success: dict[APIModel, bool],
    ) -> list[APIModel]:
        producers = producers_by_consumer.get(api)
        if not producers:
            return []
        return [p for p in producers if api_success.get(p) is False]

    def _apply_dependency_overrides(self, api: APIModel, request_payload,
                                    keep_generated: bool = False) -> None:
        """Write bound producer/consumer values into the materialized payload.

        `keep_generated` leaves alone any field the payload factory already
        supplied. It is set once a runtime regeneration has happened, because at
        that point the factory has seen the failing response and the binding has
        not. Measured on Rbaskets: POST /api/baskets/{name} is a create whose
        name the client chooses, but a binding pinned it to `test2`, the name a
        sibling create had already used, so the app answered
        409 `bucket already exists`. The LLM correctly regenerated a unique name
        -- and this method silently overwrote it with `test2` again, on every
        retry. The repair could not have worked no matter how good the payload
        was.
        """
        extractor = self.binding_applier.extractor
        for field in extractor.request_fields(api):
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
            target = self._section_for(field.location, request_payload)
            if target is None:
                continue
            segments = field.path.segments
            if keep_generated and segments and segments[0] in target:
                logger.info(
                    "Keeping regenerated %s.%s for %s %s over bound value %r",
                    field.location, ".".join(str(x) for x in segments),
                    api.api_method.value, api.api_url, param.value,
                )
                continue
            self._set_by_path(target, segments, param.value)

    @staticmethod
    def _extract_resource_id(body: Any) -> Optional[str]:
        """The id of the resource a create response describes, if it says one.

        Envelopes differ per application -- Appwrite answers with the object,
        Chat2DB wraps it in {"success":..,"data":..} and sometimes returns the
        bare id as data -- so descend one envelope before giving up.
        """
        for _ in range(2):
            if isinstance(body, dict):
                for key in ("$id", "id", "Id", "ID"):
                    v = body.get(key)
                    if isinstance(v, (str, int)) and str(v).strip():
                        return str(v)
                if "data" in body:
                    body = body["data"]
                    continue
            elif isinstance(body, (str, int)) and str(body).strip():
                return str(body)
            return None
        return None

    @staticmethod
    def _parent_keys(records: list[dict]) -> set[str]:
        """Parameter names any record under this collection has used as a parent."""
        out: set[str] = set()
        for r in records:
            out |= set(r.get("parent") or {})
        return out

    def _record_resource(self, api: APIModel, request_payload, resp) -> None:
        """Remember that this request created a child under these parent params."""
        if not getattr(resp, "ok", False):
            return
        path = {k: v for k, v in (getattr(request_payload, "path", None) or {}).items()}
        new_id = self._extract_resource_id(resp.json())
        child = None
        if new_id is None:
            # A create whose path ends in a placeholder lets the client choose the
            # identifier, so the created resource's id is the value we just sent --
            # the response need not repeat it. Without this, such a resource would
            # never enter the records and every later read would have to guess its
            # id.
            segs = [x for x in api.api_url.split("/") if x]
            if (api.api_method in (APIMethod.POST, APIMethod.PUT)
                    and segs and segs[-1].startswith("{") and segs[-1].endswith("}")):
                child = segs[-1][1:-1]
                value = path.get(child)
                if isinstance(value, (str, int)) and str(value).strip():
                    new_id = str(value)
        if new_id is None:
            return
        parent = {k: v for k, v in path.items() if k != child}
        # Records are looked up by COLLECTION path, which for an ordinary create is
        # its own url (POST /teams/{teamId}/memberships) but for a client-named one
        # is that url minus the trailing placeholder: consumers of
        # /baskets/{name} ask for /baskets.
        collection = api.api_url
        if child is not None:
            segs = [x for x in api.api_url.split("/") if x]
            collection = "/" + "/".join(segs[:-1])
        self.resource_records.setdefault(collection, []).append(
            {"parent": parent, "id": new_id, "gen": self._plan_generation}
        )

    def _warn_if_deleting_a_fixture(self, api: APIModel, request_payload) -> None:
        """Say so, loudly, before a DELETE removes a resource given as environment.

        --custom_param_file outranks discovered values by design, so a DELETE whose
        path is entirely pinned addresses the fixture itself, and every later
        request keeps addressing a resource that no longer exists. Measured on
        Gitea: DELETE /repos/root/voapi-fixture succeeded ten minutes into a run
        and took the success rate from 24/32 before it to 1/49 after, for the
        remaining hour and fifty minutes. The warning does not block the request --
        that is dang.json's job -- it makes the hazard visible in the first minutes
        instead of at the post-mortem.
        """
        if api.api_method != APIMethod.DELETE:
            return
        path = getattr(request_payload, "path", None) or {}
        if not path:
            return
        pins = getattr(self.req_mat, "overrides", {}) or {}
        pinned = [k for k, v in path.items() if k in pins and pins[k] == v]
        if pinned and len(pinned) == len(path):
            logger.warning(
                "DELETE %s targets a resource pinned entirely by --custom_param_file "
                "(%s). If this succeeds, every later endpoint under it addresses a "
                "resource that no longer exists; consider a dangerous-endpoints entry.",
                api.api_url,
                ", ".join(f"{k}={path[k]!r}" for k in pinned),
            )

    def _forget_deleted_resource(self, api: APIModel, request_payload, resp) -> None:
        """Drop records for a resource a successful DELETE just removed.

        Otherwise the tuple mechanism keeps handing out an id that no longer
        exists. Measured on Rbaskets: DELETE /baskets/{name} removed basket
        BFv0EV9p and GET /baskets/{name}, measured moments later, was given the
        same name and answered 404 -- the run destroyed the resource it then
        tried to read, and that alone cost an endpoint on a 20-endpoint
        application.
        """
        if api.api_method != APIMethod.DELETE or not getattr(resp, "ok", False):
            return
        path = getattr(request_payload, "path", None) or {}
        if not path:
            return
        # Only the value of the LAST placeholder is dropped. Taking every path value
        # would also forget the parents named in the path: a DELETE on a nested
        # resource would drop the parent record as well, and later steps that still
        # need that parent would lose it.
        segs = [x for x in api.api_url.split("/") if x]
        idx = next((i for i in range(len(segs) - 1, -1, -1)
                    if segs[i].startswith("{") and segs[i].endswith("}")), None)
        if idx is None:
            return
        child = segs[idx][1:-1]
        value = path.get(child)
        if not isinstance(value, (str, int)) or not str(value).strip():
            return
        gone = {str(value)}
        for collection, records in self.resource_records.items():
            kept = [r for r in records if str(r["id"]) not in gone]
            if len(kept) != len(records):
                logger.info(
                    "Forgetting %d resource record(s) under %s deleted by %s %s",
                    len(records) - len(kept), collection,
                    api.api_method.value, api.api_url,
                )
                self.resource_records[collection] = kept

    def _apply_resource_tuple(self, api: APIModel, request_payload) -> None:
        """Fill an item endpoint's path parameters from a single recorded resource.

        /teams/{teamId}/memberships/{membershipId} is addressed by dropping the
        last segment to reach its collection, /teams/{teamId}/memberships, which is
        the endpoint that created the child. Anything the user pinned through
        --custom_param_file is left alone: that is a deliberate fixture value and
        outranks a discovered one.
        """
        path = getattr(request_payload, "path", None)
        # `is None`, not falsy: an empty dict is exactly the retry this has to fix,
        # where the generator emitted no path fields at all.
        if path is None:
            return
        segs = [x for x in api.api_url.split("/") if x]
        if not segs:
            return
        # The child parameter is the last {placeholder}, which is not always the last
        # segment. /teams/{teamId}/memberships/{membershipId}/status ends in a literal
        # action, and requiring a trailing placeholder skipped it entirely -- it was
        # the endpoint behind most of the mismatched pairs, retried ten times with the
        # membership id in both parameters. Trailing actions (/status, /activate,
        # /start, /tag) are common enough that this shape cannot be the exception.
        idx = next((i for i in range(len(segs) - 1, -1, -1)
                    if segs[i].startswith("{") and segs[i].endswith("}")), None)
        if idx is None:
            return
        child = segs[idx][1:-1]
        overrides = getattr(self.req_mat, "overrides", {}) or {}
        if child in overrides:
            return
        collection = "/" + "/".join(segs[:idx])
        records = self.resource_records.get(collection)
        if not records:
            logger.debug("No resource record under %s for %s %s",
                         collection, api.api_method.value, api.api_url)
            return
        # Prefer a record from the plan currently executing: an id from a resource this
        # chain created is the one the application expects. A record from an earlier
        # plan is normally worse than what the per-field bindings produced, because a
        # stale-but-real id looks valid and fails deep inside the application.
        #
        # The exception is when the bindings are provably wrong, and there is one
        # signature for that: the same id filling a parent and its child. A stale
        # coherent pair beats a fresh incoherent one, so that case falls back.
        same_plan = [r for r in records if r["gen"] == self._plan_generation]
        if same_plan:
            rec = same_plan[-1]
        else:
            current_child = path.get(child)
            degenerate = current_child is not None and any(
                path.get(k) == current_child for k in self._parent_keys(records)
                if k != child and k in path
            )
            if not degenerate:
                logger.debug("No same-plan resource record under %s for %s %s",
                             collection, api.api_method.value, api.api_url)
                return
            rec = records[-1]
            logger.info(
                "Resource tuple falling back across plans for %s %s: path had %s in "
                "both parent and child", api.api_method.value, api.api_url, current_child)
        # Assign rather than patch-if-present. Every {param} in the template has to
        # be in the payload for the URL to resolve, and the generator does not always
        # emit them -- it alternates which optional fields it includes between
        # retries. Skipping absent keys is what let a retry keep a stale teamId while
        # the first attempt had been paired correctly.
        for key, value in rec["parent"].items():
            if key not in overrides:
                path[key] = value
        path[child] = rec["id"]
        logger.info(
            "Resource tuple for %s %s: %s",
            api.api_method.value, api.api_url,
            {k: path[k] for k in list(rec["parent"]) + [child]},
        )
        # A parent and a child holding the same id is the signature of the bug this
        # method exists to remove, so say so loudly rather than emitting the request.
        dupes = [k for k in rec["parent"] if k != child and path.get(k) == path[child]]
        if dupes:
            logger.warning(
                "Resource tuple degenerate for %s %s: %s share the child id %s",
                api.api_method.value, api.api_url, dupes, path[child],
            )

    def _apply_sibling_body_refs(self, api: APIModel, request_payload) -> None:
        """Fill a body field that names a sibling collection, consistently with the path.

        The path half of this is not enough. Appwrite activates a function tag with
        PATCH /functions/{functionId}/tag and a body of {"tag": "<tagId>"} -- the id
        lives in the body, not the URL, and it has to belong to the function named in
        the path. It did not: tags were activated against other functions, Appwrite
        answered 200 anyway, and POST /functions/{functionId}/executions then reported
        404 "Tag not found. Deploy tag before trying to execute a function" with every
        step of the four-call deployment chain having returned 2xx.

        A body field is treated as a sibling reference when the request's own path,
        plus the field name pluralised, names a collection we have a record for:
        /functions/{functionId} + "tag" -> /functions/{functionId}/tags. The record is
        then only used if its parent parameters match what the path already holds, so
        this cannot introduce the very mismatch it exists to remove.
        """
        body = getattr(request_payload, "body", None)
        path = getattr(request_payload, "path", None)
        if not isinstance(body, dict) or path is None:
            return
        overrides = getattr(self.req_mat, "overrides", {}) or {}
        segs = [x for x in api.api_url.rstrip("/").split("/") if x]
        for field in list(body):
            if field in overrides or not isinstance(body.get(field), (str, int)):
                continue
            # Drop a trailing segment that is the field itself: the collection sibling
            # of /functions/{functionId}/tag is /functions/{functionId}/tags, not
            # /functions/{functionId}/tag/tags.
            own = segs[:-1] if segs and segs[-1].rstrip("s") == field.rstrip("s") else segs
            base = "/" + "/".join(own)
            for candidate in (f"{base}/{field}s", f"{base}/{field}"):
                records = self.resource_records.get(candidate)
                if not records:
                    continue
                usable = [
                    r for r in records
                    if r["gen"] == self._plan_generation
                    # The record's parent must agree with the path we are about to
                    # send, or we would be pointing at a sibling of a different parent.
                    and all(path.get(k) == v for k, v in r["parent"].items() if k in path)
                ]
                if not usable:
                    continue
                body[field] = usable[-1]["id"]
                logger.info(
                    "Sibling body ref for %s %s: %s=%s (from %s)",
                    api.api_method.value, api.api_url, field, body[field], candidate,
                )
                break

    def _section_for(self, location: ParamLocation, request_payload):
        if location == ParamLocation.PATH:
            return request_payload.path
        if location == ParamLocation.HEADER:
            return request_payload.header
        if location == ParamLocation.QUERY:
            return request_payload.query
        if location == ParamLocation.BODY:
            return request_payload.body if isinstance(request_payload.body,
                                                      dict) else None
        return None

    def _set_by_path(self, target: dict, segments: tuple[str, ...],
                     value: Any) -> None:
        if not segments:
            return
        cur = target
        for seg in segments[:-1]:
            child = cur.get(seg)
            if not isinstance(child, dict):
                # The path does not resolve through nested dicts in the already
                # materialized body -- typically because it traverses a JSON array
                # (e.g. metas is [{...}]). Overwriting that array with {} to graft a
                # nested key would destroy a valid structure, so skip this override and
                # leave the materialized value intact.
                return
            cur = child
        cur[segments[-1]] = value

    def _maybe_regenerate_payload(self, api: APIModel, response: HTTPResponse,
                                  request_payload) -> bool:
        if not self.payload_factory_generator:
            return False
        if response.status_code < 400:
            return False
        # TODO need to remove
        if "No file sent" in response.text:
            return False
        prev_code = api.payload_factory_code
        logger.info(
            "Runtime LLM regen for %s %s status=%s",
            api.api_method,
            api.api_url,
            response.status_code,
        )
        if self.ledger is not None:
            from runtime.recovery_ledger import SITE_RUNTIME_REGEN
            self.ledger.record_repair(
                "param", SITE_RUNTIME_REGEN, f"{api.api_method.value} {api.api_url}",
                {"status": response.status_code,
                 "response": (response.text or "")[:200]})
        runtime_error = self._build_runtime_error(response, request_payload, prev_code)
        result, _usage = self.payload_factory_generator.generate(
            api, runtime_error=runtime_error, max_attempts=2)
        if result is None:
            logger.info("Runtime LLM regen failed for %s %s", api.api_method, api.api_url)
        else:
            logger.info("Runtime LLM regen succeeded for %s %s", api.api_method, api.api_url)
        return result is not None

    def _build_runtime_error(self, response: HTTPResponse,
                             request_payload, prev_code: Optional[str]) -> str:
        payload = {
            "path": request_payload.path,
            "query": request_payload.query,
            "body": request_payload.body,
        }
        prev_code_str = (
            self._truncate_text(prev_code, 2000) if prev_code else "<none>"
        )
        hint = f"[DIAGNOSIS] {self.failure_hint}\n" if self.failure_hint else ""
        return hint + (f"HTTP {response.status_code} error. "
                f"Response: {response.text}. "
                f"Request payload: {json.dumps(payload, ensure_ascii=False)}. "
                f"Previous code:\n{prev_code_str}")

    def _truncate_text(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "\n...<truncated>"

    def _send_request(
        self,
        api: APIModel,
        request_payload,
        attempt: int,
        last_response: Optional[str],
        count_budget: bool = False,
    ) -> tuple[HTTPResponse, Optional[list[str]]]:
        if count_budget:
            if self._budget_remaining(api) == 0:
                reason = f"SKIPPED: LLM budget exhausted for {api.api_method.value} {api.api_url}"
                logger.info(reason)
                return self._make_skip_response(reason), None
            self._consume_budget(api)
        files = None
        if self.multipart_handler and self.multipart_handler.is_multipart(
            api.api_method.value, api.api_url
        ):
            files = self.multipart_handler.prepare_files(
                api.api_method.value,
                api.api_url,
                attempt=attempt,
                last_response_text=last_response,
            )
            if files:
                try:
                    request_payload = replace(request_payload, files=files)
                    if isinstance(request_payload.body, dict):
                        body = {
                            k: v
                            for k, v in request_payload.body.items()
                            if k not in files
                        }
                        request_payload = replace(request_payload, body=body)
                except Exception:
                    pass
        if self.form_handler and files is None:
            try:
                request_payload = self.form_handler.prepare_payload(api, request_payload)
            except Exception as exc:
                logger.warning("Form handler failed: %s", exc)
        # Applied here rather than alongside the per-field overrides: this is the one
        # place every outgoing request passes through. Hooking it to the override step
        # meant any retry path that rebuilt the payload without calling that step sent
        # an incoherent tuple.
        self._apply_resource_tuple(api, request_payload)
        self._apply_sibling_body_refs(api, request_payload)
        self._warn_if_deleting_a_fixture(api, request_payload)
        resp = self.http.send(api.api_method, api.api_url, request_payload, files=files)
        self.harvested_urls |= harvest_urls(resp.text, self.http.baseurl)
        if getattr(request_payload, "path", None):
            self.resource_path_values.update(request_payload.path)
        self._record_resource(api, request_payload, resp)
        self._forget_deleted_resource(api, request_payload, resp)
        return resp, self._summarize_files(files)

    def _summarize_files(self, files) -> Optional[list[str]]:
        if not files:
            return None
        return [f"{k}:{v[0]}" for k, v in files.items()]
