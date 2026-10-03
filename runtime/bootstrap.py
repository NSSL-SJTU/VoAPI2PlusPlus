import json
import logging
import os
from typing import Optional
from datetime import datetime
from pathlib import Path

from config import VoAPIConfig

from prepare import get_api_list
from code_analyzer.extractor import build_api_extractor, build_code_context_provider
from matching.extractor import FieldExtractor
from matching.finder import ProducerFinder
from matching.rules import ProducerRules
from matching.matcher import NameMatcher
from models.types import ProducerMethodPriority, ProducerMethods, ProducerMethodsNoGet
from planning.sequence import (
    SequencePlanner,
    RuleBasedResolver,
    LLMResolver,
    UnionResolver,
)
from runtime.materializers.request import RequestMaterializer
from runtime.http.client import HTTPResponse, HTTPClient
from runtime.payload_generator import RuleBasedPayloadGenerator, CodeBasedPayloadGenerator
from code_analyzer.payload_agent import PayloadFactoryGenerator
from utils.doc_loader import APIDocLoader
from utils.llm_client import LLMClient
from vuln.candidate import CandidateAPI
from vuln.handler import VulnHandler
from vuln.strategies.path import PathStrategy
from vuln.strategies.cmdi import CommandiStrategy
from vuln.strategies.sqli import SQLiStrategy
from vuln.strategies.ssrf import SSRFStrategy
from vuln.strategies.xss import XSSStrategy
from vuln.strategies.upload import UploadStrategy
from vuln.types import VulnType
from vuln.recorder import VulnRecorder
from vuln.xss_registry import XSSRegistry
from vuln.payloads import APIVulnPayloads, adapt_api_vul_payloads
from log_config import config_log


def _parse_api_filter_file(filter_file: str) -> tuple[set[tuple[str, str]], set[str]]:
    allow_pairs, allow_paths = set(), set()
    with open(filter_file, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) == 1:
                path = parts[0]
                allow_paths.add(path if path.startswith("/") else "/" + path)
            else:
                method = parts[0].upper()
                path = " ".join(parts[1:])
                path = path if path.startswith("/") else "/" + path
                allow_pairs.add((method, path))
    return allow_pairs, allow_paths


def filter_api_models_by_file(
    api_model_list: list,
    only_apis_file: str,
    logger: logging.Logger,
):
    allow_pairs, allow_paths = _parse_api_filter_file(only_apis_file)
    before = len(api_model_list)
    filtered = [
        api
        for api in api_model_list
        if (api.api_method.value, api.api_url) in allow_pairs
        or api.api_url in allow_paths
    ]
    logger.info(
        "Filtered APIs by %s: %d -> %d",
        only_apis_file,
        before,
        len(filtered),
    )
    return filtered


def exclude_api_models_by_file(
    api_model_list: list,
    exclude_apis_file: str,
    logger: logging.Logger,
):
    exclude_pairs, exclude_paths = _parse_api_filter_file(exclude_apis_file)
    before = len(api_model_list)
    filtered = [
        api
        for api in api_model_list
        if (api.api_method.value, api.api_url) not in exclude_pairs
        and api.api_url not in exclude_paths
    ]
    logger.info(
        "Excluded APIs by %s: %d -> %d",
        exclude_apis_file,
        before,
        len(filtered),
    )
    return filtered


def _stamp_log_file(log_file: str) -> str:
    base, dot, ext = log_file.rpartition(".")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if dot:
        return f"{base}_{ts}.{ext}"
    return f"{log_file}_{ts}"


def _configure_logging(args: VoAPIConfig) -> logging.Logger:
    if args.log_file:
        args.log_file = _stamp_log_file(args.log_file)
    config_log(args.log_file, args.debug)
    logger = logging.getLogger(__name__)
    logger.info("Args: %s", vars(args))
    return logger


def _load_api_models(args: VoAPIConfig) -> list:
    project_path = args.spring_project or args.code_project_path
    if project_path:
        return build_api_extractor(project_path, args.code_lang).scan_project()
    assert args.api_info_file, "Either --spring_project/--code_project_path or --api_info_file must be provided"
    return get_api_list(args.api_info_file)


def _load_dangerous_keys(args: VoAPIConfig) -> set[tuple[str, str]]:
    dangerous_keys: set[tuple[str, str]] = set()
    if args.dangerous_endpoints_file and os.path.exists(
        args.dangerous_endpoints_file
    ):
        with open(args.dangerous_endpoints_file, "r", encoding="utf-8") as f:
            dang_conf = json.load(f)
        for item in dang_conf.get("dangerous_endpoints", []):
            path = item.get("path")
            method = item.get("method")
            if not path or not method:
                continue
            clean_path = path if path.startswith("/") else "/" + path
            dangerous_keys.add((method.upper(), clean_path))
    return dangerous_keys


def _write_api_model_list(api_model_list: list) -> None:
    with open("api_model_list.txt", "w", encoding="utf-8") as f:
        for api in api_model_list:
            f.write(api.to_txt())


def _load_headers(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_custom_params(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _apply_custom_judge(args: VoAPIConfig) -> None:
    if not args.custom_judge:
        return
    HTTPResponse.custom_judge = True
    with open(args.custom_judge_file, "r", encoding="utf-8") as f:
        custom_judge_dict = json.load(f)
    HTTPResponse.fail_str = custom_judge_dict["fail_str"]
    HTTPResponse.success_str = custom_judge_dict["success_str"]


def _build_sequence_planner(args: VoAPIConfig,
                            field_extractor: FieldExtractor) -> SequencePlanner:
    producer_methods = ProducerMethods if not args.no_get_producer else ProducerMethodsNoGet
    producer_rules = ProducerRules(producer_methods, ProducerMethodPriority)
    finder = ProducerFinder(field_extractor, producer_rules)
    name_matcher = NameMatcher()
    rule_resolver = RuleBasedResolver(field_extractor, finder, name_matcher)

    mode = getattr(args, "dep_resolver", "rule")
    if mode == "rule":
        return SequencePlanner(resolver=rule_resolver)

    llm_resolver = LLMResolver(
        llm_client=LLMClient(),
        model=args.payload_model,
        project_name=args.project_name,
    )
    if mode == "llm":
        return SequencePlanner(resolver=llm_resolver)
    return SequencePlanner(resolver=UnionResolver(rule_resolver, llm_resolver))


def _setup_llm_payloads(
    args: VoAPIConfig,
    api_model_list: list,
    safe_api_list: list,
    cand_api_list: list[CandidateAPI],
    logger: logging.Logger,
) -> tuple[PayloadFactoryGenerator | None, list, list]:
    if args.payload_mode not in ("llm", "mix"):
        return None, safe_api_list, cand_api_list
    payload_context_source = args.payload_context_source
    code_project_path = args.code_project_path or args.spring_project
    if payload_context_source == "spec" and not args.spec_path:
        raise ValueError("--spec_path is required when payload_context_source=spec")
    if payload_context_source in ("code", "auto") and not (args.spec_path or code_project_path):
        raise ValueError(
            "--spec_path or --code_project_path/--spring_project is required for payload_context_source=code/auto"
        )
    loader = None
    if args.spec_path and os.path.exists(args.spec_path):
        loader = APIDocLoader(args.spec_path)
    elif payload_context_source == "spec":
        raise ValueError(f"--spec_path not found: {args.spec_path}")
    elif args.spec_path:
        logger.warning("Spec not found (%s); falling back to code context", args.spec_path)
    llm = LLMClient()
    code_context_provider = None
    if payload_context_source in ("code", "auto") and code_project_path:
        code_context_provider = build_code_context_provider(
            code_project_path, args.code_lang
        )
    generator = PayloadFactoryGenerator(
        loader,
        llm,
        project_name=args.project_name,
        default_model=args.payload_model,
        code_context_provider=code_context_provider,
        payload_context_source=payload_context_source,
    )
    if args.payload_mode == "llm":
        token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        for api in api_model_list:
            _, usage = generator.generate(api, model=args.payload_model)
            token_usage["prompt_tokens"] += usage["prompt_tokens"]
            token_usage["completion_tokens"] += usage["completion_tokens"]
            token_usage["total_tokens"] += usage["total_tokens"]
        logger.info(
            "Payload codegen tokens: prompt=%d completion=%d total=%d",
            token_usage["prompt_tokens"],
            token_usage["completion_tokens"],
            token_usage["total_tokens"],
        )
        if safe_api_list:
            ok_set = {api for api in safe_api_list if api.payload_factory_code}
            if len(ok_set) < len(safe_api_list):
                logger.warning(
                    "Skipping %d APIs due to payload_factory_code generation failure",
                    len(safe_api_list) - len(ok_set),
                )
            safe_api_list = [api for api in safe_api_list if api in ok_set]
            cand_api_list = [cand for cand in cand_api_list if cand.api in ok_set]
    return generator, safe_api_list, cand_api_list


def _build_payload_generators(
    args: VoAPIConfig,
    req_mat: RequestMaterializer,
    header_dict: dict,
    dep_manager=None,
) -> tuple[RuleBasedPayloadGenerator | CodeBasedPayloadGenerator | None,
           RuleBasedPayloadGenerator | None]:
    if args.payload_mode == "rule":
        return RuleBasedPayloadGenerator(req_mat), None
    if args.payload_mode == "llm":
        return (
            CodeBasedPayloadGenerator(
                header_default=header_dict, dep_manager=dep_manager
            ),
            None,
        )
    if args.payload_mode == "mix":
        return (
            CodeBasedPayloadGenerator(header_default=header_dict, dep_manager=dep_manager),
            RuleBasedPayloadGenerator(req_mat),
        )
    return None, None


def _build_vuln_handler(
    http_client: HTTPClient,
    req_mat: RequestMaterializer,
    binding_applier,
    args: VoAPIConfig,
    payload_factory_generator: Optional[PayloadFactoryGenerator] = None,
    dep_manager=None,
    form_handler=None,
) -> VulnHandler:
    vuln_recorder = VulnRecorder(Path(args.output_dir))
    strategy_args = (http_client, req_mat, binding_applier, vuln_recorder)
    # TODO We should add a upload strategy
    strategy_classes = {
        VulnType.PATH_TRAVERSAL: PathStrategy,
        VulnType.COMMAND_INJECTION: CommandiStrategy,
        VulnType.SQLi: SQLiStrategy,
        VulnType.SSRF: SSRFStrategy,
        VulnType.XSS: XSSStrategy,
        VulnType.UNRESTRICTED_UPLOAD: UploadStrategy,
    }
    adapt_api_vul_payloads(APIVulnPayloads, args.http_ip, args.http_port, args.https_port)
    enable_llm = payload_factory_generator is not None
    llm_payload_generator = (
        CodeBasedPayloadGenerator(
            header_default=req_mat.header_default,
            dep_manager=dep_manager,
        )
        if enable_llm
        else None
    )
    llm_client = payload_factory_generator.llm_client if payload_factory_generator else None
    xss_registry = XSSRegistry()
    extra_kwargs: dict[VulnType, dict] = {
        VulnType.XSS: {"xss_registry": xss_registry},
    }
    vuln_strategy_map = {
        vuln_type: strategy_class(
            *strategy_args,
            APIVulnPayloads[vuln_type],
            payload_factory_generator=payload_factory_generator,
            llm_payload_generator=llm_payload_generator,
            llm_client=llm_client,
            llm_model=args.payload_model,
            skip_retry_on_payload_error=args.vuln_skip_payload_retry,
            llm_max_tries=2,
            enable_llm=enable_llm,
            project_name=args.project_name,
            form_handler=form_handler,
            **extra_kwargs.get(vuln_type, {}),
        )
        for vuln_type, strategy_class in strategy_classes.items()
    }
    return VulnHandler(vuln_strategy_map)
