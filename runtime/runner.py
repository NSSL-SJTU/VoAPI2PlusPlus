import asyncio
import logging
import json
from typing import Iterable, Optional
from pathlib import Path
from dataclasses import dataclass, field
import time
from vuln.candidate import CandidateAPI
from vuln.handler import VulnHandler
from vuln.types import VulnType
from models.api_model import APIModel
from models.types import APIMethod
from runtime.exec.executor import SequenceExecutor, ExecutionResult, CallRecord
from planning.graph import DependencyEdge, SequencePlan
from planning.sequence import SequencePlanner, OverrideResolver
from matching.llm_dependency import resolve_dependencies_llm
from runtime.llm_repair import plan_repairs, resolve_repair_apis
from runtime.llm_failure import classify_failure, FailureClassification
from runtime.vuln_dependencies import VulnDependencyPreparer
from utils.llm_client import LLMClient
from runtime.recovery_ledger import RecoveryLedger


logger = logging.getLogger(__name__)

# Order for endpoints the topology leaves unordered: create the state, read it,
# change it, destroy it last. Never used to change the topology itself. This keeps
# a run from reading or deleting a resource before the create that produces it, and
# from destroying a resource its later steps still depend on.
_METHOD_RISK = {
    APIMethod.POST: 0,
    APIMethod.GET: 1,
    APIMethod.HEAD: 1,
    APIMethod.OPTIONS: 1,
    APIMethod.PUT: 2,
    APIMethod.PATCH: 2,
    APIMethod.DELETE: 3,
}


@dataclass
class Runner:
    planner: SequencePlanner
    executor: SequenceExecutor
    all_api_list: list[APIModel]
    vuln_handler: VulnHandler
    coverage_mode: bool = False
    output_dir: Optional[Path] = None
    dep_llm_mode: str = "off"
    dep_llm_ablation: str = "off"
    dep_llm_max_tries: int = 1
    dep_llm_model: Optional[str] = None
    project_name: str = "Unknown"
    llm_client: Optional[LLMClient] = field(default=None, init=False, repr=False)
    full_vuln_scan: bool = False
    xss_config: Optional[dict] = None
    vuln_test_order: str = "api"
    _endpoint_failures: int = field(default=0, init=False, repr=False)
    ledger: RecoveryLedger = field(default_factory=RecoveryLedger, init=False, repr=False)

    def run(self, cand_api_list: list[CandidateAPI]):
        if self.coverage_mode:
            self._run_coverage_topo(cand_api_list)
            return

        if self.vuln_test_order == "xss_first":
            self._run_vuln_by_type(cand_api_list, allowed_types={VulnType.XSS})
            self._run_xss_walker_if_needed()
            self._run_render_probe_if_needed()
            self._run_vuln_by_type(
                cand_api_list,
                allowed_types={vt for vt in VulnType if vt != VulnType.XSS},
            )
            self._recheck_deferred_evidence()
            return

        if self.vuln_test_order == "type":
            self._run_vuln_by_type(cand_api_list)
        else:
            for cand in cand_api_list:
                self._guard_endpoint(
                    f"{cand.api.api_method.value} {cand.api.api_url}",
                    self.run_for_one,
                    cand,
                )

        self._run_xss_walker_if_needed()
        self._run_render_probe_if_needed()
        self._recheck_deferred_evidence()

    def _recheck_deferred_evidence(self) -> None:
        """Re-read out-of-band evidence once the scan is over.

        An endpoint may fetch the planted URL from a background worker --
        Alist's offline download answers with a task id and only then dials out
        -- so the callback lands after the strategy has already moved on. The
        evidence check is a file lookup, so a sweep at the end is nearly free.
        """
        total = 0
        for strategy in self.vuln_handler.strategy_map.values():
            recheck = getattr(strategy, "recheck_pending_evidence", None)
            if not callable(recheck):
                continue
            try:
                total += recheck()
            except Exception:
                logger.exception("Deferred evidence recheck failed for %s", strategy)
        if total:
            logger.info("Deferred evidence sweep confirmed %d finding(s)", total)

    # A dead LLM endpoint must not look like "every API is simply untestable",
    # so give up once this many endpoints in a row blow up.
    MAX_CONSECUTIVE_ENDPOINT_FAILURES = 10

    def _guard_endpoint(self, label: str, fn, *args, **kwargs):
        """Run one endpoint's work, absorbing anything it raises.

        Every LLM call in the pipeline can raise -- a provider hiccup reaches us
        as tenacity's RetryError wrapping InstructorRetryException -- and none of
        the ~23 call sites catches it, so a single bad response used to abort the
        whole scan. A 4h25m Jellyfin run died this way at endpoint 59 of 102,
        losing 9.3M tokens of work. Guarding here covers all of those sites at
        once, because they are all reached through one endpoint's processing.
        """
        try:
            result = fn(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except Exception:
            self._endpoint_failures += 1
            logger.exception(
                "Endpoint aborted (%d in a row): %s", self._endpoint_failures, label
            )
            if self._endpoint_failures >= self.MAX_CONSECUTIVE_ENDPOINT_FAILURES:
                raise RuntimeError(
                    f"{self._endpoint_failures} endpoints failed consecutively; "
                    "the LLM backend or the SUT is probably down"
                ) from None
            return None
        self._endpoint_failures = 0
        return result

    def _run_render_probe_if_needed(self) -> None:
        """Confirm stored XSS whose render is a client-side HTML sink (not a URL the crawler
        can reach) by re-rendering the read endpoint's reflection. See vuln.render_probe."""
        if not self.xss_config:
            return
        xss_strategy = self.vuln_handler.strategy_map.get(VulnType.XSS)
        registry = getattr(xss_strategy, "xss_registry", None)
        if registry is None or len(registry) == 0:
            return
        from runtime.resource_probe import read_endpoints
        from vuln.render_probe import RenderProbe

        templates = {
            rec.api_url
            for xid in registry.all_ids()
            if (rec := registry.lookup(xid)) is not None
        }
        reads = read_endpoints(templates, self.all_api_list)
        if not reads:
            return
        home = self.xss_config["home_url"]
        read_urls: list[str] = []
        for api in reads:
            try:
                payload = self.executor.req_mat.materialize(api)
                url = self._build_read_url(home, api.api_url, payload.path)
            except Exception:
                url = None
            if url and "{" not in url:
                read_urls.append(url)
        if not read_urls:
            return
        probe = RenderProbe(
            home_url=home,
            cookie_str=self.xss_config["cookie"],
            domain=self.xss_config["domain"],
            xss_registry=registry,
            vuln_recorder=xss_strategy.recorder,
            local_storage=self.xss_config.get("local_storage", {}),
            headless=self.xss_config.get("headless", True),
        )
        triggered = asyncio.run(probe.run(read_urls))
        logger.info(
            "XSS render-probe: %d read endpoint(s), %d confirmed",
            len(read_urls),
            len(triggered),
        )

    @staticmethod
    def _build_read_url(home: str, api_url: str, path: dict) -> str:
        from urllib.parse import urlencode

        filled = api_url
        for k, v in (path or {}).items():
            filled = filled.replace("{" + k + "}", str(v))
        url = home.rstrip("/") + "/" + filled.lstrip("/")
        # Fetch page one broadly, no materialized filters -- a materialized searchKey/status
        # would filter the list away from the record we just injected. Extra pagination keys
        # are ignored by frameworks that don't use them.
        pagination = {
            "pageNo": 1, "pageSize": 200, "page": 1, "size": 200, "current": 1,
        }
        return url + "?" + urlencode(pagination)

    def _poke_injected_resources(self, registry) -> None:
        """Call the GET siblings of each injected resource so the app returns their render
        URLs (e.g. a token-gated draft preview), which the executor then harvests. No
        endpoint is hardcoded -- see runtime.resource_probe."""
        from runtime.resource_probe import sibling_read_targets
        from runtime.materializers.request import RequestPayload

        templates = {
            rec.api_url
            for xid in registry.all_ids()
            if (rec := registry.lookup(xid)) is not None
        }
        resource_ids = getattr(self.executor, "resource_path_values", {})
        if not templates or not resource_ids:
            return
        targets = sibling_read_targets(templates, self.all_api_list, resource_ids)
        header = dict(getattr(self.executor.req_mat, "header_default", {}) or {})
        poked = 0
        for api, path in targets:
            payload = RequestPayload(path=path, header=header, query={}, body={})
            try:
                self.executor._send_request(api, payload, attempt=1, last_response=None)
                poked += 1
            except Exception as exc:  # a probe failure must never abort the walk
                logger.debug("resource poke failed for %s: %s", api.api_url, exc)
        if poked:
            logger.info(
                "XSS Walker: poked %d read endpoint(s) of injected resources", poked
            )

    def _run_xss_walker_if_needed(self) -> None:
        if not self.xss_config:
            # Say so. A missing walker config produces the same output as an
            # application with no stored XSS -- an empty xss/ directory -- so
            # without this warning the two cases are indistinguishable, and stored
            # payloads that were injected but never rendered read as no finding.
            logger.warning(
                "XSS Walker disabled: no --xss_config_file. Stored-XSS payloads "
                "will be injected but never confirmed; XSS findings will read as 0."
            )
            return
        xss_strategy = self.vuln_handler.strategy_map.get(VulnType.XSS)
        if xss_strategy is None:
            return
        registry = getattr(xss_strategy, "xss_registry", None)
        if registry is None or len(registry) == 0:
            logger.info("XSS Walker: no registered XSS IDs, skipping")
            return
        from vuln.xss_walker import XSSWalker

        recorder = xss_strategy.recorder
        # Poke the read endpoints of every resource we injected into, so the app returns
        # the render URLs (e.g. a token-gated draft preview) that get harvested below.
        self._poke_injected_resources(registry)
        # Seed the walker with the static config URLs plus every render URL the app itself
        # returned during the scan. That is what lets it reach app-generated pages -- e.g.
        # a token-gated draft preview -- without any app-specific crawl logic.
        config_seeds = list(self.xss_config.get("seed_urls", []))
        harvested = sorted(getattr(self.executor, "harvested_urls", set()))
        seed_urls = config_seeds + [u for u in harvested if u not in config_seeds]
        logger.info(
            "XSS Walker: %d config seed(s) + %d harvested URL(s)",
            len(config_seeds),
            len(harvested),
        )
        walker = XSSWalker(
            home_url=self.xss_config["home_url"],
            cookie_str=self.xss_config["cookie"],
            domain=self.xss_config["domain"],
            xss_registry=registry,
            vuln_recorder=recorder,
            max_steps=self.xss_config.get("max_steps", 500),
            max_actions_per_page=self.xss_config.get("max_actions_per_page", 12),
            headless=self.xss_config.get("headless", True),
            settle_ms=self.xss_config.get("settle_ms", 700),
            local_storage=self.xss_config.get("local_storage", {}),
            max_noop_clicks_per_page=self.xss_config.get(
                "max_noop_clicks_per_page", 8
            ),
            seed_urls=seed_urls,
            parallel_url_workers=self.xss_config.get("parallel_url_workers", 1),
            parallel_url_budget=self.xss_config.get("parallel_url_budget", 0),
            button_crawl_mode=self.xss_config.get("button_crawl_mode", "navigation"),
            max_stateful_pages=self.xss_config.get("max_stateful_pages", 50),
        )
        logger.info("XSS Walker: starting with %d registered IDs", len(registry))
        started = time.time()
        triggered = asyncio.run(walker.run())
        summary = walker.summary()
        summary["elapsed_seconds"] = round(time.time() - started, 3)
        if self.output_dir:
            (self.output_dir / "xss_walker_summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (self.output_dir / "xss_walker_confirmed_ids.txt").write_text(
                "\n".join(triggered) + ("\n" if triggered else ""),
                encoding="utf-8",
            )
        if triggered:
            logger.info(
                (
                    "XSS Walker: %d XSS vulnerabilities confirmed "
                    "(observed_unconfirmed=%d not_observed=%d)"
                ),
                len(triggered),
                summary.get("observed_unconfirmed", summary.get("rejected", 0)),
                summary.get("not_observed", summary.get("unreachable", 0)),
            )
        else:
            logger.info(
                "XSS Walker: no XSS triggered (observed_unconfirmed=%d not_observed=%d)",
                summary.get("observed_unconfirmed", summary.get("rejected", 0)),
                summary.get("not_observed", summary.get("unreachable", 0)),
            )

    def run_for_one(self, cand: CandidateAPI) -> Optional[bool]:
        target_api = cand.api
        if self.coverage_mode:
            seq = self.planner.build(target_api, self.all_api_list)
            # Reset producer parameters to avoid state pollution across runs.
            for api in seq.ordered_apis:
                api.reset_request_values()
            exec_result = self._run_with_failure_handling(seq, target_api, include_target=True)
            status = "Success" if exec_result.success else "Fail"
            msg = f"{target_api.api_method} {target_api.api_url} {status}\n"
            logger.info(f"Coverage: {msg.strip()}")
            if self.output_dir:
                with open(self.output_dir / "coverage.txt", "a", encoding="utf-8") as f:
                    f.write(msg)
            return exec_result.success

        seq = self._prepare_for_vuln(cand)
        if seq is None:
            return
        self.run_for_vuln(cand, seq.edges)

    def _prepare_for_vuln(self, cand: CandidateAPI) -> Optional[SequencePlan]:
        target_api = cand.api
        seq = self.planner.build(target_api, self.all_api_list)
        # Reset producer parameters to avoid state pollution across runs.
        for api in seq.ordered_apis:
            api.reset_request_values()

        prepared_seq = seq.remove_target_api()
        exec_result = self._run_with_failure_handling(prepared_seq, target_api, include_target=False)
        if not exec_result.success:
            return None
        return seq

    def _run_vuln_by_type(
        self,
        cand_api_list: list[CandidateAPI],
        allowed_types: Optional[set[VulnType]] = None,
    ) -> None:
        preparers_by_target: dict[APIModel, dict[tuple, VulnDependencyPreparer]] = {}
        for vuln_type in VulnType:
            if allowed_types is not None and vuln_type not in allowed_types:
                continue
            if vuln_type not in self.vuln_handler.strategy_map:
                continue
            candidates = [
                cand for cand in cand_api_list if vuln_type in cand.test_types
            ]
            if not candidates:
                continue
            logger.info(
                "Vuln type-ordered scan: starting %s for %d candidate(s)",
                vuln_type.name,
                len(candidates),
            )
            for cand in candidates:
                label = f"{vuln_type.name} {cand.api.api_method.value} {cand.api.api_url}"
                seq = self._guard_endpoint(label, self._prepare_for_vuln, cand)
                if seq is None:
                    continue
                preparers = preparers_by_target.setdefault(cand.api, {})
                self._guard_endpoint(
                    label,
                    self.run_for_vuln,
                    cand,
                    seq.edges,
                    only_vuln_type=vuln_type,
                    preparers=preparers,
                )
        

    def _resolve_dep_llm_safely(self, api, pool, *, purpose, history_text=None):
        """resolve_dependencies_llm, with a provider failure demoted to "no bindings".

        Every call into this path is three or four LLM round trips, and any of them
        can raise -- a 429 once killed a Jellyfin coverage run at 223 of 377
        endpoints after four hours, escaping through the one call site that
        _guard_endpoint did not cover. Dependency recovery is an optimisation: when
        it cannot run, the right outcome is to fall back to the rule-derived
        bindings, not to end the scan.
        """
        try:
            return resolve_dependencies_llm(
                api,
                pool,
                model=self.dep_llm_model,
                llm_client=self._get_llm_client(),
                project_name=self.project_name,
                purpose=purpose,
                **({"history_text": history_text} if history_text is not None else {}),
            )
        except Exception as exc:
            logger.warning(
                "LLM dependency resolution failed for %s %s (purpose=%s): %s -- "
                "continuing without LLM bindings",
                api.api_method, api.api_url, purpose, exc,
            )
            return None

    def _run_coverage_topo(self, cand_api_list: list[CandidateAPI]) -> None:
        apis = [cand.api for cand in cand_api_list]
        bindings_by_consumer, producers_by_consumer = self._build_dependency_index(apis)
        ordered_apis = self._topo_sort_apis(apis, producers_by_consumer)
        success_cache: dict[APIModel, bool] = {}
        success_count = 0
        fail_count = 0
        for api in ordered_apis:
            failed_producers = [
                p for p in producers_by_consumer.get(api, set())
                if success_cache.get(p) is False
            ]
            bindings = bindings_by_consumer.get(api, [])
            used_alt_bindings = False
            if failed_producers:
                if self.dep_llm_mode == "on_failure" and self._allow_dep_llm():
                    pool = [
                        p for p in self.all_api_list
                        if p not in failed_producers and p != api
                        and success_cache.get(p) is True
                    ]
                    llm_bindings = self._resolve_dep_llm_safely(
                        api, pool, purpose="dep_recovery_producer")
                    if llm_bindings:
                        bindings = llm_bindings
                        used_alt_bindings = True
                    else:
                        logger.info(
                            "Coverage skip %s %s: failed producers %s",
                            api.api_method,
                            api.api_url,
                            ", ".join(f"{p.api_method.value} {p.api_url}" for p in failed_producers),
                        )
                        self._record_coverage(api, False)
                        success_cache[api] = False
                        fail_count += 1
                        continue
                else:
                    logger.info(
                        "Coverage skip %s %s: failed producers %s",
                        api.api_method,
                        api.api_url,
                        ", ".join(f"{p.api_method.value} {p.api_url}" for p in failed_producers),
                    )
                    self._record_coverage(api, False)
                    success_cache[api] = False
                    fail_count += 1
                    continue
            label = f"{api.api_method.value} {api.api_url}"
            u = LLMClient.global_usage()
            self.ledger.begin_episode(label, LLMClient.global_call_count(),
                                      u.get("total_tokens", 0))
            plan = self._guard_endpoint(label, self._build_plan_for_api, api, bindings)
            exec_result = None
            if plan is not None:
                if used_alt_bindings:
                    exec_result = self._guard_endpoint(label, self.executor.run, plan)
                else:
                    exec_result = self._guard_endpoint(
                        label, self._run_with_failure_handling, plan, api,
                        include_target=True,
                    )
            if exec_result is None:
                success_cache[api] = False
                fail_count += 1
                self._record_coverage(api, False)
                continue
            success_cache[api] = exec_result.success
            if exec_result.success:
                success_count += 1
            else:
                fail_count += 1
            self._record_coverage(api, exec_result.success)
        summary = f"Total: {len(ordered_apis)} Success: {success_count} Fail: {fail_count}\n"
        logger.info(f"Coverage Summary: {summary.strip()}")
        if self.output_dir:
            with open(self.output_dir / "coverage.txt", "a", encoding="utf-8") as f:
                f.write(f"\n{summary}")

    def _build_dependency_index(
        self,
        apis: list[APIModel],
    ) -> tuple[dict[APIModel, list], dict[APIModel, set[APIModel]]]:
        bindings_by_consumer: dict[APIModel, list] = {}
        producers_by_consumer: dict[APIModel, set[APIModel]] = {}
        pool = list(self.all_api_list)
        for api in apis:
            candidates = [p for p in pool if p != api]
            bindings = self.planner.resolver.resolve(api, candidates)
            bindings_by_consumer[api] = bindings
            for b in bindings:
                producers_by_consumer.setdefault(api, set()).add(b.producer.api)
        return bindings_by_consumer, producers_by_consumer

    def _topo_sort_apis(
        self,
        apis: list[APIModel],
        producers_by_consumer: dict[APIModel, set[APIModel]],
    ) -> list[APIModel]:
        api_set = set(apis)
        indegree = {api: 0 for api in apis}
        adj: dict[APIModel, set[APIModel]] = {api: set() for api in apis}
        for consumer, producers in producers_by_consumer.items():
            for producer in producers:
                if producer not in api_set:
                    continue
                adj.setdefault(producer, set()).add(consumer)
                indegree[consumer] = indegree.get(consumer, 0) + 1
        # Ties -- endpoints with no dependency ordering between them -- are otherwise
        # broken by input order, which is arbitrary and can run a DELETE immediately
        # before a GET bound to the same resource, so the read answers 404 on what
        # was just deleted. Ordering ties by how destructive the method is costs
        # nothing (the topological constraints are untouched) and stops a run from
        # destroying the subject of its next request.
        rank = {api: (_METHOD_RISK.get(api.api_method, 2), i)
                for i, api in enumerate(apis)}
        queue = sorted((api for api in apis if indegree.get(api, 0) == 0),
                       key=lambda a: rank[a])
        ordered: list[APIModel] = []
        while queue:
            api = queue.pop(0)
            ordered.append(api)
            newly_ready = []
            for nxt in adj.get(api, set()):
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    newly_ready.append(nxt)
            if newly_ready:
                queue = sorted(queue + newly_ready, key=lambda a: rank[a])
        if len(ordered) < len(apis):
            remaining = [api for api in apis if api not in ordered]
            ordered.extend(remaining)
        return ordered

    def _build_plan_for_api(self, api: APIModel, bindings: list):
        from planning.graph import SequencePlan

        if not bindings:
            return SequencePlan((api,), tuple())

        resolver = OverrideResolver(self.planner.resolver, {api: bindings})
        planner = SequencePlanner(resolver=resolver)
        return planner.build(api, self.all_api_list)

    def _record_coverage(self, api: APIModel, success: bool) -> None:
        status = "Success" if success else "Fail"
        u = LLMClient.global_usage()
        self.ledger.end_episode(status, LLMClient.global_call_count(),
                                u.get("total_tokens", 0))
        msg = f"{api.api_method} {api.api_url} {status}\n"
        logger.info(f"Coverage: {msg.strip()}")
        if self.output_dir:
            with open(self.output_dir / "coverage.txt", "a", encoding="utf-8") as f:
                f.write(msg)

    def run_for_vuln(
        self,
        cand: CandidateAPI,
        edges: Iterable[DependencyEdge],
        only_vuln_type: Optional[VulnType] = None,
        preparers: Optional[dict[tuple, VulnDependencyPreparer]] = None,
    ):
        preparers = preparers if preparers is not None else {}
        for vuln_type in cand.test_types:
            if only_vuln_type is not None and vuln_type != only_vuln_type:
                continue
            if vuln_type not in self.vuln_handler.strategy_map:
                continue
            strategy = self.vuln_handler.get_strategy(vuln_type)
            dependency_preparer = self._get_vuln_dependency_preparer(
                strategy,
                preparers,
            )
            strategy.execute(
                cand.api,
                cand.test_types[vuln_type],
                edges,
                self.all_api_list,
                dependency_preparer=dependency_preparer,
            )
            self._record_vuln_progress(cand.api, vuln_type.value)

    def _get_vuln_dependency_preparer(
        self,
        strategy,
        preparers: dict[tuple, VulnDependencyPreparer],
    ) -> Optional[VulnDependencyPreparer]:
        enabled = getattr(strategy, "_llm_enabled", None)
        if not callable(enabled) or not enabled():
            return None
        llm_client = getattr(strategy, "llm_client", None)
        if llm_client is None:
            return None
        key = (
            id(llm_client),
            getattr(strategy, "llm_model", None),
            getattr(strategy, "project_name", self.project_name),
            max(1, int(getattr(strategy, "llm_max_tries", 1))),
        )
        preparer = preparers.get(key)
        if preparer is None:
            preparer = VulnDependencyPreparer(
                planner=self.planner,
                executor=self.executor,
                all_api_list=self.all_api_list,
                llm_client=llm_client,
                llm_model=getattr(strategy, "llm_model", None),
                project_name=getattr(strategy, "project_name", self.project_name),
                max_tries=key[3],
                execute_plan=lambda plan: self._run_plan(
                    plan,
                    allow_payload_regen=False,
                ),
            )
            preparers[key] = preparer
        return preparer

    def _record_vuln_progress(self, api: APIModel, vuln_type: str) -> None:
        now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        msg = f"VULN_DONE {self.full_vuln_scan} {now_time} {vuln_type} {api.api_method} {api.api_url}\n"
        logger.info(msg.strip())
        if self.output_dir:
            with open(self.output_dir / "vuln_coverage.txt", "a", encoding="utf-8") as f:
                f.write(msg)

    def _run_with_failure_handling(
        self,
        plan,
        target_api: APIModel,
        include_target: bool,
    ) -> ExecutionResult:
        if self.dep_llm_mode != "on_failure" or self.dep_llm_ablation == "off":
            return self.executor.run(plan)

        exec_result = self._run_plan(plan, allow_payload_regen=False)
        if exec_result.success:
            return exec_result

        classification = self._classify_failure(exec_result, target_api)
        if self._is_rate_limited(exec_result, classification):
            sleep_sec = 3
            logger.info(
                "Rate limited; sleeping %ds then retrying %s %s",
                sleep_sec,
                target_api.api_method,
                target_api.api_url,
            )
            time.sleep(sleep_sec)
            exec_result = self._run_plan(plan, allow_payload_regen=False)
            if exec_result.success:
                return exec_result
            classification = self._classify_failure(exec_result, target_api)
        if classification.error_type == "dependency_error" and self._allow_dep_llm():
            exec_result = self._retry_with_llm_dependencies(
                plan,
                target_api,
                include_target=include_target,
                fallback_result=exec_result,
            )
            if exec_result.success:
                return exec_result
            exec_result = self._retry_with_llm_repairs(
                plan,
                target_api,
                include_target=include_target,
                fallback_result=exec_result,
            )
            if exec_result.success:
                return exec_result

        if classification.error_type == "parameter_error" and self._allow_param_llm():
            # Re-running the plan alone changes nothing in mix mode: the executor's
            # mix path escalates rule -> LLM on its own and ignores
            # enable_payload_regen, so this branch used to repeat pass one and the
            # classifier's diagnosis was thrown away (it was only ever logged).
            # Hand the diagnosis to the payload prompt, and clear the per-API
            # attempt budget so the retry is actually allowed to run.
            exec_result = self._retry_with_param_hint(plan, target_api, classification)
        return exec_result

    def _retry_with_param_hint(
        self,
        plan,
        target_api: APIModel,
        classification: FailureClassification,
    ) -> ExecutionResult:
        hint = (classification.reason or "").strip()
        if classification.missing_fields:
            hint = (hint + " Missing or invalid fields: "
                    + ", ".join(classification.missing_fields)).strip()
        if not hint:
            return self._run_plan(plan, allow_payload_regen=True)

        logger.info(
            "LLM parameter retry for %s %s: %s",
            target_api.api_method,
            target_api.api_url,
            hint[:200],
        )
        from runtime.recovery_ledger import SITE_PARAM_HINT
        self.ledger.record_repair(
            "param", SITE_PARAM_HINT, f"{target_api.api_method.value} {target_api.api_url}",
            {"hint": hint[:300], "missing_fields": list(classification.missing_fields or [])})
        executor = self.executor
        previous_hint = getattr(executor, "failure_hint", None)
        executor.failure_hint = hint
        # The first pass already consumed this API's attempt budget; without
        # resetting it the retry is skipped as "budget exhausted".
        reset = getattr(executor, "reset_attempt_budget", None)
        if callable(reset):
            reset(target_api)
        try:
            return self._run_plan(plan, allow_payload_regen=True)
        finally:
            executor.failure_hint = previous_hint

    def _is_rate_limited(
        self,
        exec_result: ExecutionResult,
        classification: FailureClassification,
    ) -> bool:
        call = self._pick_failure_call(exec_result)
        return bool(call and call.response.status_code == 429)

    def _run_plan(
        self,
        plan,
        allow_payload_regen: bool,
    ) -> ExecutionResult:
        previous = self.executor.enable_payload_regen
        if self.executor.ledger is None:
            self.executor.ledger = self.ledger
        self.executor.enable_payload_regen = allow_payload_regen
        try:
            return self.executor.run(plan)
        finally:
            self.executor.enable_payload_regen = previous

    def _retry_with_llm_dependencies(
        self,
        plan,
        target_api: APIModel,
        include_target: bool,
        fallback_result: ExecutionResult,
    ) -> ExecutionResult:
        max_tries = max(1, int(self.dep_llm_max_tries))
        last_result = fallback_result
        history_entries: list[str] = []
        for attempt in range(1, max_tries + 1):
            logger.info("LLM dependency retry %d/%d for %s %s", attempt, max_tries, target_api.api_method, target_api.api_url)
            self.ledger.record_repair(
                "dep", "dep_replan", f"{target_api.api_method.value} {target_api.api_url}",
                {"attempt": attempt, "max_tries": max_tries})
            history_text = "\n\n".join(history_entries) if history_entries else None
            llm_bindings = self._resolve_dep_llm_safely(
                target_api, self.all_api_list, purpose="dep_recovery",
                history_text=history_text or "")
            if not llm_bindings:
                logger.info("LLM dependency retry: no bindings returned")
                break
            merged_bindings = self._merge_bindings(target_api, llm_bindings)
            resolver = OverrideResolver(self.planner.resolver, {target_api: merged_bindings})
            llm_planner = SequencePlanner(resolver=resolver)
            new_plan = llm_planner.build(target_api, self.all_api_list)
            if not include_target:
                new_plan = new_plan.remove_target_api()
            exec_result = self._run_plan(new_plan, allow_payload_regen=False)
            last_result = exec_result
            if exec_result.success:
                return exec_result
            history_entries.append(
                self._format_dep_history_entry(
                    attempt=attempt,
                    target_api=target_api,
                    llm_bindings=llm_bindings,
                    exec_result=exec_result,
                )
            )
        return last_result

    def _merge_bindings(
        self,
        target_api: APIModel,
        llm_bindings: list,
    ) -> list:
        pool = [api for api in self.all_api_list if api != target_api]
        rule_bindings = self.planner.resolver.resolve(target_api, pool)
        merged = list(rule_bindings)
        seen = {self._binding_key(b) for b in merged}
        for b in llm_bindings:
            key = self._binding_key(b)
            if key in seen:
                continue
            merged.append(b)
            seen.add(key)
        return merged

    def _format_dep_history_entry(
        self,
        attempt: int,
        target_api: APIModel,
        llm_bindings: list,
        exec_result: ExecutionResult,
    ) -> str:
        lines: list[str] = [f"Attempt {attempt}:"]
        lines.append("Mappings:")
        if llm_bindings:
            for b in llm_bindings:
                try:
                    producer = b.producer.api
                    lines.append(
                        f"- {producer.api_method.value} {producer.api_url} "
                        f"{b.producer.location.value}.{b.producer.path.dotted()} -> "
                        f"{b.consumer.location.value}.{b.consumer.path.dotted()}"
                    )
                except Exception:
                    lines.append(f"- {b}")
        else:
            lines.append("- <none>")

        producer_calls, target_call = self._extract_dep_calls(exec_result, target_api)
        if producer_calls:
            lines.append("Producer calls (A):")
            for call in producer_calls:
                lines.append(self._format_call_record(call))
        if target_call:
            lines.append("Consumer failure call (B):")
            lines.append(self._format_call_record(target_call))
        return "\n".join(lines)

    def _extract_dep_calls(
        self,
        exec_result: ExecutionResult,
        target_api: APIModel,
    ) -> tuple[list[CallRecord], Optional[CallRecord]]:
        producer_by_key: dict[tuple[str, str], CallRecord] = {}
        target_calls: list[CallRecord] = []
        for call in exec_result.calls:
            if (
                call.api_method == target_api.api_method
                and call.api_url == target_api.api_url
            ):
                target_calls.append(call)
                continue
            key = (call.api_method.value, call.api_url)
            producer_by_key[key] = call
        target_call = target_calls[-1] if target_calls else self._pick_failure_call(exec_result)
        return list(producer_by_key.values()), target_call

    def _format_call_record(self, call: CallRecord) -> str:
        request_dump = call.request_dump or {}
        redacted = dict(request_dump)
        headers = redacted.get("header")
        if isinstance(headers, dict):
            redacted["header"] = self._redact_headers(headers)
        request_text = json.dumps(redacted, ensure_ascii=True, default=str)
        response_text = call.response.text or ""
        response_text = self._truncate_text(response_text, limit=800)
        return (
            f"- {call.api_method.value} {call.api_url}\n"
            f"  request: {request_text}\n"
            f"  response: status={call.response.status_code} body={response_text}"
        )

    def _redact_headers(self, headers: dict) -> dict:
        redacted = {}
        for k, v in headers.items():
            if k.lower() in {"authorization", "cookie"}:
                redacted[k] = "******"
            else:
                redacted[k] = v
        return redacted

    def _truncate_text(self, text: str, limit: int = 800) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + f"...(truncated {len(text) - limit} chars)"

    def _binding_key(self, binding) -> tuple:
        return (
            binding.consumer.api,
            binding.consumer.location.value,
            binding.consumer.path.dotted(),
            binding.producer.api,
            binding.producer.location.value,
            binding.producer.path.dotted(),
        )

    def _retry_with_llm_repairs(
        self,
        plan,
        target_api: APIModel,
        include_target: bool,
        fallback_result: ExecutionResult,
    ) -> ExecutionResult:
        call = self._pick_failure_call(fallback_result)
        if call:
            failed_method = call.api_method.value
            failed_path = call.api_url
            status_code = str(call.response.status_code)
            response_text = call.response.text
        else:
            failed_method = target_api.api_method.value
            failed_path = target_api.api_url
            status_code = "UNKNOWN"
            response_text = "No HTTP call recorded."

        repair_apis = plan_repairs(
            self._get_llm_client(),
            failed_method=failed_method,
            failed_path=failed_path,
            status_code=status_code,
            response_text=response_text,
            api_models=self.all_api_list,
            model=self.dep_llm_model,
            project_name=self.project_name,
        )
        if not repair_apis:
            logger.info("LLM repair plan: no repair APIs returned")
            return fallback_result

        repair_models, missing = resolve_repair_apis(repair_apis, self.all_api_list)
        if missing:
            logger.info("LLM repair plan: missing APIs %s", missing)
        repair_models = [
            api for api in repair_models
            if not (api.api_method.value == failed_method and api.api_url == failed_path)
        ]
        if not repair_models:
            logger.info("LLM repair plan: no valid repair APIs resolved")
            return fallback_result

        # One held generation for the whole chain, so a step that creates a
        # resource and a later step that activates it agree on which resource
        # they mean. Without it each plan was its own generation and the reuse
        # rules declined to carry the first step's record into the second.
        with self.executor.hold_plan_generation():
            for index, repair_api in enumerate(repair_models):
                logger.info(
                    "LLM repair step %d/%d: %s %s",
                    index + 1,
                    len(repair_models),
                    repair_api.api_method,
                    repair_api.api_url,
                )
                self.ledger.record_repair(
                    "repair_step", "repair_plan",
                    f"{repair_api.api_method.value} {repair_api.api_url}",
                    {"for_target": f"{target_api.api_method.value} {target_api.api_url}"})
                if index == 0:
                    repair_plan = self.planner.build(repair_api, self.all_api_list)
                    if self._allow_dep_llm():
                        llm_bindings = self._resolve_dep_llm_safely(
                            repair_api, self.all_api_list, purpose="dep_repair")
                        if llm_bindings:
                            merged_bindings = self._merge_bindings(repair_api, llm_bindings)
                            resolver = OverrideResolver(
                                self.planner.resolver, {repair_api: merged_bindings}
                            )
                            llm_planner = SequencePlanner(resolver=resolver)
                            repair_plan = llm_planner.build(repair_api, self.all_api_list)
                else:
                    # Later steps act on what the first step built, so they get a
                    # target-only plan. Giving each step its full plan re-runs the
                    # producers and builds a second, unrelated resource.
                    repair_plan = self._build_target_only_plan(repair_api)
                repair_result = self._run_plan(repair_plan, allow_payload_regen=True)
                if not repair_result.success:
                    logger.info(
                        "LLM repair step failed: %s %s",
                        repair_api.api_method,
                        repair_api.api_url,
                    )
                    return fallback_result

            if include_target:
                retry_plan = self._build_target_only_plan(target_api)
                return self._run_plan(retry_plan, allow_payload_regen=False)
            return self._run_plan(plan, allow_payload_regen=False)

    def _classify_failure(
        self,
        exec_result: ExecutionResult,
        target_api: APIModel,
    ) -> FailureClassification:
        call = self._pick_failure_call(exec_result)
        if call:
            failed_method = call.api_method.value
            failed_path = call.api_url
            status_code = str(call.response.status_code)
            response_text = call.response.text
            request_payload = call.request_dump
        else:
            failed_method = target_api.api_method.value
            failed_path = target_api.api_url
            status_code = "SKIPPED"
            response_text = "No HTTP call recorded; likely skipped due to failed dependencies."
            request_payload = {}

        result, usage = classify_failure(
            self._get_llm_client(),
            consumer_method=target_api.api_method.value,
            consumer_path=target_api.api_url,
            failed_method=failed_method,
            failed_path=failed_path,
            status_code=status_code,
            response_text=response_text,
            request_payload=request_payload,
            model=self.dep_llm_model,
            project_name=self.project_name,
        )
        logger.info(
            "LLM failure classification: %s reason=%s missing=%s usage=%s",
            result.error_type,
            result.reason,
            result.missing_fields,
            usage,
        )
        self.ledger.record_classification(
            target=f"{target_api.api_method.value} {target_api.api_url}",
            failed_api=f"{failed_method} {failed_path}",
            status=status_code, predicted=result.error_type,
            reason=result.reason, missing_fields=result.missing_fields,
            response=response_text)
        return result

    def _pick_failure_call(
        self, exec_result: ExecutionResult
    ) -> Optional[CallRecord]:
        for call in reversed(exec_result.calls):
            if not call.response.ok:
                return call
        return exec_result.calls[-1] if exec_result.calls else None

    def _get_llm_client(self) -> LLMClient:
        if self.llm_client is None:
            self.llm_client = LLMClient()
        return self.llm_client

    def _allow_dep_llm(self) -> bool:
        return self.dep_llm_ablation in ("dep_only", "both")

    def _allow_param_llm(self) -> bool:
        return self.dep_llm_ablation in ("param_only", "both")

    def _build_target_only_plan(self, target_api: APIModel):
        pool = [api for api in self.all_api_list if api != target_api]
        bindings = self.planner.resolver.resolve(target_api, pool)
        by_pair: dict[tuple[APIModel, APIModel], list] = {}
        for b in bindings:
            key = (b.producer.api, b.consumer.api)
            by_pair.setdefault(key, []).append(b)
        edges = [
            DependencyEdge(prod, cons, tuple(bs)) for (prod, cons), bs in by_pair.items()
        ]
        from planning.graph import SequencePlan

        return SequencePlan((target_api,), tuple(edges))
