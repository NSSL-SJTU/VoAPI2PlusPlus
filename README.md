# VoAPI²++

VoAPI²++ (voapi2++) is a vulnerability-oriented API fuzzing framework. It builds
stateful request sequences, binds parameters across endpoints by dependency, and
generates payloads with a hybrid strategy (deterministic rules plus LLM-generated
code-as-policy), falling back to LLM repair on failed requests.

It is an improved version of VoAPI² (USENIX Security '24, see
[Citation](#citation)), extending the original with source-code-driven endpoint
extraction (Spring/Java and Go), LLM-assisted dependency resolution and failure
repair, and a headless-browser XSS walker.

## How it works

1. **Model the API.** Load endpoints from RESTler-style `APIInfo.txt`, an OpenAPI
   spec, or directly from a Spring (Java) or Go project source tree.
2. **Plan sequences.** Order endpoints by producer/consumer dependencies so a
   resource is created before it is read, updated, or deleted.
3. **Generate payloads.** `rule` builds values from metadata; `llm` generates a
   Python payload factory from the spec/source; `mix` uses rules first and falls
   back to the LLM on failure.
4. **Execute and repair.** Send requests, capture responses, update bindings, and
   on a 4xx/5xx ask the LLM to classify the failure and regenerate.
5. **Test for vulnerabilities.** Keyword-filter endpoints per class and run the
   strategies for SSRF, SQLi, path traversal, command injection, unrestricted
   upload, and stored/reflected XSS (the XSS walker confirms rendering in a
   headless browser).

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) for dependency management
- An OpenAI-compatible API key (only for `llm` / `mix` modes and LLM repair)

## Setup

```bash
uv sync                              # runtime dependencies
uv run playwright install chromium   # once, for XSS browser confirmation
```

Create a `.env` file with your LLM credentials (only needed for `llm` / `mix`
modes and LLM repair):

- `API_KEY` — your OpenAI-compatible API key (required)
- `BASE_URL` — API endpoint; leave unset to use the OpenAI default, or point it at
  any OpenAI-compatible endpoint (optional)
- `MODEL_NAME` — default model (optional)

## Inputs

Provide these per target:

- `APIInfo.txt` — RESTler-style endpoint metadata (or an OpenAPI `spec.json`, or a
  project source tree via `--spring_project` / `--code_project_path`)
- `spec.json` — OpenAPI spec (required for `llm` / `mix`)
- `Header.json` — authentication headers
- `Param.json` — custom parameter values

## Running

Entry point is `main.py`.

```bash
uv run python main.py \
  --output_dir ./output \
  --api_info_file ./APIInfo.txt \
  --spec_path ./spec.json \
  --baseurl http://127.0.0.1:8080 \
  --header_file ./Header.json \
  --custom_param_file ./Param.json \
  --log_file ./output/log.txt \
  --http_ip <your-callback-ip> \
  --payload_mode mix \
  --project_name <target-name>
```

Common options:

- `--payload_mode [rule|llm|mix]`
- `--spec_path` (required for `llm` / `mix`)
- `--coverage_count` — record endpoint coverage
- `--vuln_types sqli,xss,ssrf` — limit which vulnerability classes are tested
- `--vuln_test_order [api|type|xss_first]`
- `--only_apis_file` / `--exclude_apis_file` — limit the endpoints under test

Run `uv run python main.py --help` for the full list.

## Output

- Logs are written to `--log_file` (with a timestamp suffix).
- LLM responses are cached as JSONL (`LLM_CACHE_FILE`, default `./.llm_cache.jsonl`);
  set it empty to disable the cache.
- The XSS walker writes `xss_walker_summary.json` and `xss_walker_confirmed_ids.txt`
  to the output directory.

## Citation

VoAPI²++ builds on VoAPI². If you use this work, please cite the original paper:

```bibtex
@inproceedings {294607,
author = {Wenlong Du and Jian Li and Yanhao Wang and Libo Chen and Ruijie Zhao and Junmin Zhu and Zhengguang Han and Yijun Wang and Zhi Xue},
title = {Vulnerability-oriented Testing for {RESTful} {APIs}},
booktitle = {33rd USENIX Security Symposium (USENIX Security 24)},
year = {2024},
isbn = {978-1-939133-44-1},
address = {Philadelphia, PA},
pages = {739--755},
url = {https://www.usenix.org/conference/usenixsecurity24/presentation/du},
publisher = {USENIX Association},
month = aug
}
```
