from dataclasses import dataclass
from functools import cached_property
from typing import Iterable, ClassVar, Dict, Tuple, Set, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import logging
import time
from vuln.strategy import VulnStrategy
from vuln.types import VulnType
from vuln.recorder import VulnCase
from runtime.http.client import HTTPResponse
from runtime.materializers.request import RequestPayload
from models.api_model import APIModel
from models.ref import FieldRef
from models.parameter import Parameter, BasicParameter, ArrayParameter, PropertyParameter
from models.types import ParamType, ParamLocation
from planning.graph import DependencyEdge
from runtime.vuln_dependencies import VulnDependencyPreparer
import subprocess
from urllib.parse import urlencode


logger = logging.getLogger(__name__)


@dataclass
class SQLiStrategy(VulnStrategy):
    vuln_type: ClassVar[VulnType] = VulnType.SQLi

    need_trigger: bool = False

    def has_vuln(self, vuln_case: VulnCase) -> bool:
        return False

    # ---- helpers: parameter traversal ----
    def _iter_basic_params(
        self, part: Dict[str, Parameter], location: ParamLocation
    ) -> Iterable[Tuple[str, BasicParameter, ParamLocation]]:
        for name, p in (part or {}).items():
            yield from self._walk_param(name, p, location)

    def _walk_param(
        self, name: str, p: Parameter, location: ParamLocation
    ) -> Iterable[Tuple[str, BasicParameter, ParamLocation]]:
        if isinstance(p, BasicParameter):
            yield (name, p, location)
            return
        if isinstance(p, ArrayParameter):
            return
        if isinstance(p, PropertyParameter):
            for k, child in p.properties.items():
                yield from self._walk_param(k, child, location)

    def _collect_candidates(
        self, target: APIModel, test_field_refs: Iterable[FieldRef]
    ) -> List[Tuple[str, ParamLocation]]:
        refs = list(test_field_refs or [])
        candidates: list[Tuple[str, ParamLocation]] = []
        seen: set[Tuple[str, ParamLocation]] = set()

        for r in refs:
            if isinstance(r.param, BasicParameter):
                key = (r.name, r.location)
                if key not in seen:
                    seen.add(key)
                    candidates.append(key)

        for name, p, loc in self._iter_basic_params(
            target.request_structure.query, ParamLocation.QUERY
        ):
            key = (name, loc)
            if key not in seen and p.param_type == ParamType.STRING:
                seen.add(key)
                candidates.append(key)
        for name, p, loc in self._iter_basic_params(
            target.request_structure.body, ParamLocation.BODY
        ):
            key = (name, loc)
            if key not in seen and p.param_type == ParamType.STRING:
                seen.add(key)
                candidates.append(key)
        return candidates

    def _mark_selected_required(
        self, target: APIModel, selected: Set[Tuple[str, ParamLocation]]
    ) -> list[Tuple[BasicParameter, bool]]:
        original: list[Tuple[BasicParameter, bool]] = []

        def mark(part: Dict[str, Parameter], location: ParamLocation):
            for name, p in (part or {}).items():
                for leaf_name, leaf, leaf_loc in self._walk_param(name, p, location):
                    if (leaf_name, leaf_loc) in selected:
                        original.append((leaf, leaf.is_required))
                        leaf.is_required = True

        mark(target.request_structure.query, ParamLocation.QUERY)
        mark(target.request_structure.body, ParamLocation.BODY)
        mark(target.request_structure.header, ParamLocation.HEADER)
        mark(target.request_structure.path, ParamLocation.PATH)
        return original

    def _restore_required_flags(self, originals: list[Tuple[BasicParameter, bool]]):
        for leaf, flag in originals:
            leaf.is_required = flag

    def _send_with_selected(
        self, target: APIModel, selected: Set[Tuple[str, ParamLocation]]
    ) -> HTTPResponse:
        originals = self._mark_selected_required(target, selected)
        prev = self.req_materializer.open_required
        self.req_materializer.open_required = True
        try:
            payload = self.req_materializer.materialize(target)
            return self.http.send(target.api_method, target.api_url, request_payload=payload)
        finally:
            self._restore_required_flags(originals)
            self.req_materializer.open_required = prev

    def _materialize_with_selected(
        self, target: APIModel, selected: Set[Tuple[str, ParamLocation]]
    ):
        originals = self._mark_selected_required(target, selected)
        prev = self.req_materializer.open_required
        self.req_materializer.open_required = True
        try:
            return self.req_materializer.materialize(target)
        finally:
            self._restore_required_flags(originals)
            self.req_materializer.open_required = prev

    # ---- sqlmap runner (self-contained) ----
    @cached_property
    def _sqlmap_path(self) -> str:
        logger.info("Getting sqlmap path")
        sqlmap_path = ""
        p = subprocess.Popen(
            ["pip", "show", "sqlmap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, _ = p.communicate()
        if out:
            out = out.decode()
            location = out[out.find("Location:") + 10 :]
            sqlmap_path = location[
                : location.find(os.linesep)
            ] + "{0}sqlmap{0}sqlmap.py".format(os.path.sep)
        logger.info("Sqlmap path: %s", sqlmap_path)
        return sqlmap_path
        

    def _build_sqlmap_cmd(
        self,
        full_url: str,
        api_method: str,
        headers_str: str,
        body_str: str,
        test_params: list[str],
    ) -> list[str]:
        cmd: list[str] = ["python", self._sqlmap_path, "-u", full_url, f"--method={api_method}"]
        if headers_str:
            cmd += [f"--headers={headers_str}"]
        if body_str:
            cmd += [f"--data={body_str}", "--param-del=;"]
        if test_params:
            cmd += ["-p", ",".join(test_params)]
        cmd += [
            "--batch",
            "--technique=T",
            "--time-sec=3",
            "--level=3",
            "--fresh-queries",
        ]
        return cmd

    def _headers_to_str(self, headers: dict[str, str]) -> str:
        if not headers:
            return ""
        return "\n".join(f"{k}:{v}" for k, v in headers.items())

    def _body_to_semicolon(self, body: dict[str, object]) -> str:
        if not body:
            return ""
        return ";".join(f"{k}={body[k]}" for k in body)

    def _format_url(
        self, baseurl: str, api_url: str, path: dict[str, object], query: dict[str, object]
    ) -> str:
        url = api_url
        for k, v in (path or {}).items():
            url = url.replace(f"{{{k}}}", str(v))
        if query:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urlencode(query, doseq=True)}"
        if baseurl.endswith("/"):
            baseurl = baseurl[:-1]
        return baseurl + url

    def _parse_sqlmap_output_line(self, line: str, out: List[str]):
        if "might be injectable" in line:
            parts = line.split("'") if "'" in line else []
            cand = parts[1] if len(parts) >= 3 else line.strip().split()[-1]
            if cand and cand not in out:
                out.append(cand)
            return
        if "Parameter:" in line:
            part = line.split("Parameter:", 1)[1]
            cand = part.strip().split()[0] if part else ""
            if cand and cand not in out:
                out.append(cand)

    def _is_order_clause_param(self, param_name: str) -> bool:
        normalized = param_name.lower()
        return any(term in normalized for term in ("sort", "order", "orderby"))

    def _time_payloads(self, original_value: object, delay_seconds: int) -> list[str]:
        base = str(original_value or "id").strip() or "id"
        return [
            f"{base} AND (SELECT 9860 FROM (SELECT(!SLEEP({delay_seconds})))qlVw)",
            f"{base},(SELECT SLEEP({delay_seconds}))",
        ]

    def _payload_with_value(
        self,
        payload: RequestPayload,
        cand: Tuple[str, ParamLocation],
        value: object,
    ) -> RequestPayload:
        path = dict(payload.path or {})
        header = dict(payload.header or {})
        query = dict(payload.query or {})
        body = dict(payload.body or {}) if isinstance(payload.body, dict) else payload.body
        param_name, location = cand
        if location == ParamLocation.QUERY:
            query[param_name] = value
        elif location == ParamLocation.BODY and isinstance(body, dict):
            body[param_name] = value
        return RequestPayload(path=path, header=header, query=query, body=body)

    def _payload_value(
        self,
        payload: RequestPayload,
        cand: Tuple[str, ParamLocation],
    ) -> object:
        param_name, location = cand
        if location == ParamLocation.QUERY:
            return (payload.query or {}).get(param_name, "id")
        if location == ParamLocation.BODY and isinstance(payload.body, dict):
            return payload.body.get(param_name, "id")
        return "id"

    def _measure_payload(
        self,
        target: APIModel,
        payload: RequestPayload,
    ) -> tuple[float, HTTPResponse]:
        started = time.monotonic()
        response = self.http.send(target.api_method, target.api_url, request_payload=payload)
        return time.monotonic() - started, response

    def _verify_order_time_blind(
        self,
        target: APIModel,
        cand: Tuple[str, ParamLocation],
        payload: RequestPayload,
    ) -> bool:
        param_name, location = cand
        if location not in (ParamLocation.QUERY, ParamLocation.BODY):
            return False
        if not self._is_order_clause_param(param_name):
            return False

        delay_seconds = 3
        baseline_times: list[float] = []
        for _ in range(2):
            elapsed, response = self._measure_payload(target, payload)
            if not response.ok:
                return False
            baseline_times.append(elapsed)

        original_value = self._payload_value(payload, cand)
        threshold = max(1.5, delay_seconds * 0.6)
        baseline_max = max(baseline_times)
        for attack_value in self._time_payloads(original_value, delay_seconds):
            delayed_times: list[float] = []
            attack_payload = self._payload_with_value(payload, cand, attack_value)
            for _ in range(2):
                elapsed, response = self._measure_payload(target, attack_payload)
                if not response.ok:
                    break
                delayed_times.append(elapsed)
            if len(delayed_times) < 2:
                continue
            delta = min(delayed_times) - baseline_max
            logger.info(
                (
                    "SQLi time-blind fallback param=%s baseline=%s delayed=%s "
                    "delta=%.3fs threshold=%.3fs"
                ),
                param_name,
                [round(v, 3) for v in baseline_times],
                [round(v, 3) for v in delayed_times],
                delta,
                threshold,
            )
            if delta >= threshold:
                return True
        return False

    def _run_sqlmap(
        self,
        baseurl: str,
        api_url: str,
        api_method: str,
        payload_path: dict[str, object],
        payload_header: dict[str, object],
        payload_query: dict[str, object],
        payload_body: dict[str, object] | list[object],
        test_params: list[str],
    ) -> list[str]:
        logger.info("Running sqlmap for {} with test params {}".format(api_url, test_params))
        full_url = self._format_url(baseurl, api_url, payload_path or {}, payload_query or {})
        headers_str = self._headers_to_str({k: str(v) for k, v in (payload_header or {}).items()})
        body_str = (
            self._body_to_semicolon(payload_body)
            if isinstance(payload_body, dict) and payload_body
            else ""
        )
        cmd = self._build_sqlmap_cmd(full_url, api_method, headers_str, body_str, test_params)

        injectable: list[str] = []
        try:
            logger.info("Running sqlmap command: {}".format(cmd))
            with subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            ) as proc:
                for line in proc.stdout or []:
                    logger.info("Sqlmap output: {}".format(line))
                    self._parse_sqlmap_output_line(line, injectable)
            return injectable
        except (OSError, subprocess.SubprocessError):
            return injectable

    def execute(
        self,
        target: APIModel,
        test_field_refs: Iterable[FieldRef],
        edges: Iterable[DependencyEdge],
        all_api_list: Optional[list[APIModel]] = None,
        dependency_preparer: Optional[VulnDependencyPreparer] = None,
    ):
        logger.info("Executing SQLiStrategy for %s", target.api_url)
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

        refs = list(test_field_refs or [])
        candidates = self._collect_candidates(target, refs)
        logger.info("Candidates: %s", candidates)

        MAX_SUPPORTERS = 10
        baseurl = self.http.baseurl
        api_url = target.api_url
        api_method = target.api_method.value

        tasks: list[tuple[Tuple[str, ParamLocation], RequestPayload, list[str], HTTPResponse]] = []
        for cand in candidates:
            selected: set[Tuple[str, ParamLocation]] = {cand}
            logger.info("Trying param %s with selected %s", cand, selected)
            resp = self._send_with_selected(target, selected)
            if not resp.ok:
                supporters = [c for c in candidates if c != cand]
                for sup in supporters[:MAX_SUPPORTERS]:
                    selected.add(sup)
                    logger.info("Try add supporter %s, selected %s", sup, selected)
                    resp = self._send_with_selected(target, selected)
                    if resp.ok:
                        logger.info("OK with selected %s", selected)
                        break
            if not resp.ok:
                logger.info("Skip param %s due to non-2xx", cand)
                continue

            payload = self._materialize_with_selected(target, selected)
            if cand[1] not in (ParamLocation.QUERY, ParamLocation.BODY):
                logger.info("Param {} not in QUERY/BODY, skip sqlmap".format(cand))
                continue
            test_params = [cand[0]]
            tasks.append((cand, payload, test_params, resp))

        if not tasks:
            return

        max_workers = min(4, len(tasks))
        sqlmap_results: list[
            tuple[Tuple[str, ParamLocation], RequestPayload, HTTPResponse, list[str]]
        ] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            for cand, payload, test_params, resp in tasks:
                future = executor.submit(
                    self._run_sqlmap,
                    baseurl,
                    api_url,
                    api_method,
                    payload.path,
                    payload.header,
                    payload.query,
                    payload.body if isinstance(payload.body, dict) else {},
                    test_params,
                )
                future_map[future] = (cand, payload, resp)

            for future in as_completed(future_map):
                cand, payload, resp = future_map[future]
                try:
                    injectable = future.result()
                except Exception:
                    logger.exception("Sqlmap task failed for %s", cand)
                    continue
                sqlmap_results.append((cand, payload, resp, injectable))

        for cand, payload, resp, injectable in sqlmap_results:
            if not injectable and self._verify_order_time_blind(target, cand, payload):
                injectable = [cand[0]]

            for pname in injectable:
                ref = next((r for r in refs if r.name == pname), None)
                if not ref:
                    for nm, p, _ in self._iter_basic_params(
                        target.request_structure.query, ParamLocation.QUERY
                    ):
                        if nm == pname and isinstance(p, BasicParameter):
                            ref = FieldRef(target, ParamLocation.QUERY, pname, p.param_type, None, p)  # type: ignore[arg-type]
                            break
                    if not ref:
                        for nm, p, _ in self._iter_basic_params(
                            target.request_structure.body, ParamLocation.BODY
                        ):
                            if nm == pname and isinstance(p, BasicParameter):
                                ref = FieldRef(target, ParamLocation.BODY, pname, p.param_type, None, p)  # type: ignore[arg-type]
                                break
                if ref:
                    case = VulnCase(ref, self.vuln_type, "sqlmap_time_blind", resp)
                    self.recorder.record(case)
