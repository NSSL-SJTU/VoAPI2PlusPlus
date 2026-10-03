import json
import logging
from pathlib import Path

import tyro

from config import VoAPIConfig
from matching.extractor import FieldExtractor
from runtime.runner import Runner
from runtime.exec.executor import SequenceExecutor
from runtime.materializers.request import RequestMaterializer
from runtime.materializers.response import ResponseMaterializer
from runtime.materializers.policy import ResponsePolicy
from runtime.bindings.applier import BindingApplier
from runtime.http.client import HTTPClient
from runtime.payload_generator import DependencyManager
from runtime.multipart import (
    MultipartSpecIndex,
    MultipartHandler,
    inject_multipart_form_params,
)
from runtime.form import FormSpecIndex, FormHandler
from utils.llm_client import LLMClient
from vuln.candidate import CandidateAPI, CandidateExtractor, filter_candidate_vuln_types
from vuln.keyword import APIKeywordConfig
from vuln.types import parse_vuln_type_filter
from matching.llm_dependency import run_dependency_poc
from runtime.bootstrap import (
    _configure_logging,
    _load_api_models,
    _load_dangerous_keys,
    _write_api_model_list,
    _load_headers,
    _load_custom_params,
    _apply_custom_judge,
    _build_sequence_planner,
    _setup_llm_payloads,
    _build_payload_generators,
    _build_vuln_handler,
    filter_api_models_by_file,
    exclude_api_models_by_file,
)


def main() -> None:
    args = tyro.cli(VoAPIConfig)
    logger = _configure_logging(args)
    LLMClient.reset_global_usage()
    HTTPClient.reset_global_count()

    api_model_list = _load_api_models(args)
    logger.info("Total APIs loaded: %d", len(api_model_list))

    # Drop endpoints the loader produced twice: a project can ship two modules that
    # declare the same controller and paths, so the source extractor emits the same
    # path more than once. Only one module is packaged, so the second copy is not a
    # distinct endpoint, it is the same endpoint counted again.
    seen: set[tuple[str, str]] = set()
    deduped = []
    for api in api_model_list:
        key = (api.api_method.value, api.api_url)
        if key in seen:
            logger.info("Dropping duplicate endpoint %s %s", key[0], key[1])
            continue
        seen.add(key)
        deduped.append(api)
    if len(deduped) != len(api_model_list):
        logger.info("Deduplicated APIs: %d -> %d", len(api_model_list), len(deduped))
        api_model_list = deduped

    # Built here, not in the multipart block below: with payload_mode=llm,
    # _setup_llm_payloads generates a payload for every API up front, so a body
    # parameter injected after that point would never reach the generator.
    multipart_spec_index = None
    if args.spec_path and Path(args.spec_path).exists():
        try:
            multipart_spec_index = MultipartSpecIndex(args.spec_path)
            injected = inject_multipart_form_params(api_model_list, multipart_spec_index)
            if injected:
                logger.info(
                    "Injected %d multipart form parameter(s) missing from the model: %s",
                    len(injected),
                    "; ".join(injected),
                )
        except Exception as exc:
            logger.warning("Failed to index multipart spec: %s", exc)
    consumer_api_list = None
    if args.dep_llm_poc:
        consumer_list = api_model_list
        if args.only_apis_file:
            consumer_list = filter_api_models_by_file(
                api_model_list, args.only_apis_file, logger
            )
        if args.exclude_apis_file:
            consumer_list = exclude_api_models_by_file(
                consumer_list, args.exclude_apis_file, logger
            )
        run_dependency_poc(
            api_model_list,
            args.output_dir,
            model=args.payload_model,
            consumer_models=consumer_list,
            project_name=args.project_name,
        )
        return
    if args.only_apis_file:
        consumer_api_list = filter_api_models_by_file(
            api_model_list, args.only_apis_file, logger
        )
    if args.exclude_apis_file and consumer_api_list is not None:
        consumer_api_list = exclude_api_models_by_file(
            consumer_api_list, args.exclude_apis_file, logger
        )

    dangerous_keys = _load_dangerous_keys(args)
    safe_api_list = [
        api for api in api_model_list if (api.api_method.value, api.api_url) not in dangerous_keys
    ]
    field_extractor = FieldExtractor()
    candidate_extractor = CandidateExtractor(field_extractor, APIKeywordConfig)
    candidate_pool = safe_api_list
    if args.exclude_apis_file:
        candidate_pool = exclude_api_models_by_file(
            candidate_pool, args.exclude_apis_file, logger
        )
    if consumer_api_list is not None:
        allowed = set(consumer_api_list)
        candidate_pool = [api for api in candidate_pool if api in allowed]
    if args.coverage_count:
        cand_api_list = [CandidateAPI(api, {}) for api in candidate_pool]
    elif args.vuln_full_scan:
        logger.info("Vuln full scan enabled: using all APIs without keyword filtering")
        cand_api_list = candidate_extractor.extract_full(candidate_pool)
    else:
        cand_api_list = candidate_extractor.extract(candidate_pool)
    vuln_type_filter = parse_vuln_type_filter(args.vuln_types)
    if vuln_type_filter is not None:
        if args.coverage_count:
            logger.info("Ignoring --vuln_types in coverage mode")
        else:
            before = len(cand_api_list)
            cand_api_list = filter_candidate_vuln_types(cand_api_list, vuln_type_filter)
            logger.info(
                "Filtered vulnerability types by %s: %d -> %d candidate APIs",
                args.vuln_types,
                before,
                len(cand_api_list),
            )

    sequence_planner = _build_sequence_planner(args, field_extractor)
    http_client = HTTPClient(args.baseurl)
    _write_api_model_list(api_model_list)

    header_dict = _load_headers(args.header_file)
    custom_param_dict = _load_custom_params(args.custom_param_file)
    _apply_custom_judge(args)

    req_mat = RequestMaterializer(header_dict, custom_param_dict)
    dep_manager = DependencyManager()
    policy = ResponsePolicy()
    res_mat = ResponseMaterializer(policy, dep_manager=dep_manager)
    binding_applier = BindingApplier(field_extractor)

    generator, safe_api_list, cand_api_list = _setup_llm_payloads(
        args,
        api_model_list,
        safe_api_list,
        cand_api_list,
        logger,
    )
    payload_generator, rule_payload_generator = _build_payload_generators(
        args, req_mat, header_dict, dep_manager=dep_manager
    )

    multipart_handler = None
    form_handler = None
    if args.spec_path:
        sample_dir = Path("APIUploadPayloads") / "normal"
        if sample_dir.exists():
            try:
                spec_index = multipart_spec_index or MultipartSpecIndex(args.spec_path)
                multipart_handler = MultipartHandler(
                    spec_index=spec_index,
                    sample_dir=sample_dir,
                    llm_client=LLMClient(),
                    model=args.payload_model,
                    project_name=args.project_name,
                )
                logger.info(
                    "Multipart handler enabled: %d endpoints",
                    len(spec_index.multipart),
                )
            except Exception as exc:
                logger.warning("Failed to init multipart handler: %s", exc)
        else:
            logger.warning("Multipart sample dir not found: %s", sample_dir)
        try:
            form_spec_index = FormSpecIndex(args.spec_path)
            if form_spec_index.form:
                form_handler = FormHandler(spec_index=form_spec_index)
                logger.info(
                    "Form handler enabled: %d endpoints",
                    len(form_spec_index.form),
                )
        except Exception as exc:
            logger.warning("Failed to init form handler: %s", exc)

    executor = SequenceExecutor(
        http_client,
        req_mat,
        res_mat,
        binding_applier,
        payload_generator=payload_generator,
        payload_factory_generator=generator if args.payload_mode in ("llm", "mix") else None,
        rule_payload_generator=rule_payload_generator,
        payload_mode=args.payload_mode,
        multipart_handler=multipart_handler,
        form_handler=form_handler,
    )
    vuln_handler = _build_vuln_handler(
        http_client,
        req_mat,
        binding_applier,
        args,
        payload_factory_generator=generator if args.payload_mode in ("llm", "mix") else None,
        dep_manager=dep_manager,
        form_handler=form_handler,
    )
    xss_config = None
    if args.xss_config_file:
        with open(args.xss_config_file, "r", encoding="utf-8") as f:
            xss_config = json.load(f)
        logger.info("XSS Walker config loaded from %s", args.xss_config_file)
    elif not args.coverage_count:
        # Warn up front, not only when the walker is reached at the end of a
        # multi-hour scan: without it, stored XSS can be injected but never
        # confirmed, which looks exactly like finding none.
        logger.warning(
            "Dynamic XSS verification is OFF (no --xss_config_file); "
            "stored-XSS candidates can only be reported as unconfirmed"
        )

    runner = Runner(
        sequence_planner,
        executor,
        safe_api_list,
        vuln_handler,
        coverage_mode=args.coverage_count,
        output_dir=Path(args.output_dir),
        dep_llm_mode=args.dep_llm_mode,
        dep_llm_ablation=args.dep_llm_ablation,
        dep_llm_max_tries=args.dep_llm_max_tries,
        dep_llm_model=args.payload_model,
        project_name=args.project_name,
        full_vuln_scan=args.vuln_full_scan,
        xss_config=xss_config,
        vuln_test_order=args.vuln_test_order,
    )
    runner.run(cand_api_list)
    usage = LLMClient.global_usage()
    logger.info(
        "LLM token usage (run total): prompt=%d completion=%d total=%d",
        usage.get("prompt_tokens", 0),
        usage.get("completion_tokens", 0),
        usage.get("total_tokens", 0),
    )
    LLMClient.log_usage_breakdown()
    if args.output_dir:
        ledger_path = Path(args.output_dir) / "recovery_ledger.json"
        runner.ledger.dump(ledger_path)
        s = runner.ledger.summary()
        logger.info(
            "Recovery ledger: %d episodes, %d repairs, rescued %d endpoint(s) -> %s",
            s["episodes"], s["repairs"], len(s["rescued_endpoints"]), ledger_path)
        for k, v in s["by_mechanism_and_site"].items():
            logger.info("  %s: %d triggered, %d ok (%.1f%%)",
                        k, v["triggered"], v["ok"], v["rate"] * 100)
    logger.info("HTTP request count (run total): %d", HTTPClient.global_count())
    logger.info("HTTP 500 count (unique APIs): %d", HTTPClient.global_500_count())


if __name__ == "__main__":
    main()
