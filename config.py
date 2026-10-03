from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class VoAPIConfig:
    """VoAPI2 vulnerability-oriented API fuzzing configuration."""

    # --- Input sources ---
    output_dir: str
    """Output Directory"""
    baseurl: str
    """Base URL"""
    header_file: str
    """Header File"""
    custom_param_file: str
    """Custom Param File"""
    log_file: str
    """Log File"""
    http_ip: str
    """HTTP IP for SSRF"""

    spec_file: Optional[str] = None
    """Spec File Path"""
    api_info_file: Optional[str] = None
    """API Info File"""
    spring_project: Optional[str] = None
    """Path to Spring project root"""
    code_lang: Optional[Literal["java", "go"]] = None
    """Source language of the analyzed project (default: detect from build files)"""
    no_get_producer: bool = False
    """Get Method Can not be Producer"""

    # --- SSRF callback ---
    http_port: int = 4444
    """HTTP Port for SSRF"""
    https_port: int = 4445
    """HTTPS Port for SSRF"""

    # --- Flags ---
    custom_judge_file: Optional[str] = None
    """Custom Judge File"""
    custom_judge: bool = False
    """Custom Judge for API Response"""
    coverage_count: bool = False
    """Coverage Count"""
    debug: bool = False
    """Debug Mode"""

    # --- Payload ---
    payload_mode: Literal["rule", "llm", "mix"] = "rule"
    """Payload generation mode: rule (default), llm, or mix"""
    spec_path: Optional[str] = None
    """OpenAPI spec path for LLM payload code generation"""
    payload_model: str = "gpt-4o"
    """LLM model for payload code generation"""
    payload_context_source: Literal["spec", "code", "auto"] = "auto"
    """Payload context source: spec, code, or auto (default)"""
    code_project_path: Optional[str] = None
    """Project path for code-based payload context (defaults to --spring-project)"""
    project_name: str = "Appwrite"
    """Project name used in LLM prompts"""

    # --- API filtering ---
    only_apis_file: Optional[str] = None
    """File listing APIs to test (one per line: METHOD /path)"""
    exclude_apis_file: Optional[str] = None
    """File listing APIs to skip (same format as --only-apis-file)"""
    dangerous_endpoints_file: Optional[str] = None
    """JSON file listing dangerous endpoints to always exercise"""

    # --- XSS Walker ---
    xss_config_file: Optional[str] = None
    """JSON config file for XSS Walker (home_url, cookie, domain, max_steps)"""

    # --- LLM dependency ---
    dep_llm_poc: bool = False
    """Run LLM-assisted dependency selection PoC and exit"""
    dep_llm_mode: Literal["off", "on_failure"] = "off"
    """LLM dependency mode: off or on_failure"""
    dep_llm_ablation: Literal["off", "dep_only", "param_only", "both"] = "off"
    """LLM ablation: off, dep_only, param_only, both"""
    dep_llm_max_tries: int = 1
    """Max LLM dependency retries on failure"""
    dep_resolver: Literal["rule", "llm", "union"] = "rule"
    """Dependency inference source: rule (default), llm (LLM replaces the rule matcher), or union (both)"""

    # --- Vuln ---
    vuln_skip_payload_retry: bool = False
    """Skip LLM retries in vuln testing when failure is classified as parameter_error"""
    vuln_full_scan: bool = False
    """Test all APIs for all vuln types (skip keyword filtering)"""
    vuln_test_order: Literal["api", "type", "xss_first"] = "api"
    """Vulnerability test scheduling order: api (default), type, or xss_first
    (test XSS first, run the XSS walker, then test the remaining types)"""
    vuln_types: Optional[str] = None
    """Comma-separated vulnerability types to test, e.g. sqli,xss,ssrf"""
