# The generated snippets only ever see `ctx`, so the prompts have to name what
# is actually on it. Describing ctx.random as "random module" led models to
# invent attributes such as ctx.random.hex that do not exist and abort the payload.
CTX_TOOLS = """Context Available (variable name `ctx`), and nothing else:
- `ctx.fake`: Faker instance -- fake.name(), fake.email(), fake.uuid4(), fake.url(),
  fake.word(), fake.pystr(), fake.date_time(); plus fake.hexify(n) for n hex digits.
- `ctx.dep`: Dependency manager -- ctx.dep.get("tag", default) to read a value
  produced by an earlier request.
- `ctx.random`: the stdlib random module (randint, choice, choices, sample,
  uniform, shuffle) EXTENDED with two helpers:
    - ctx.random.string(length, alphabet=None) -> random alphanumeric token
    - ctx.random.hexstring(length) -> random hex digits
  There is no ctx.random.hex; use ctx.random.hexstring or fake.hexify."""


def build_payload_factory_prompt(project_name: str, method: str, url: str, doc_json: str) -> str:
    return f"""
You are an expert Python QA Engineer.

Task: Write a Python code snippet to generate a VALID request payload for the provided API spec.

Input Spec From {project_name} API Spec:
Method: {method}
Path: {url}
Spec (JSON):
{doc_json}

{CTX_TOOLS}

CRITICAL RULES FOR CODE GENERATION:
1. The code MUST end with: return {{'path': {{...}}, 'query': {{...}}, 'body': {{...}}}}.
2. Do NOT import modules. Use only the provided `ctx` tools.
3. The code should be a function body only (no def/class, no code fences).
4. Only use request parameters and requestBody from the spec. Do NOT include response fields.
5. If there is no requestBody for GET/DELETE, leave body empty.
6. You don’t need to make each parameter cover every possible case. You just need to make it as likely as possible to pass the tests. For each parameter, the candidates should be the ones you’re most confident in. The example values in the spec may not be the best choice.
Output Format: JSON matching the CodeGenerationOutput model.
""".strip()

def build_payload_factory_prompt_from_code(
    project_name: str,
    method: str,
    url: str,
    code_blob: str,
) -> str:
    return f"""
You are an expert Python QA Engineer.

Task: Write a Python code snippet to generate a VALID request payload for the provided API,
using the Java code context below (no OpenAPI spec available).

Input Context From {project_name} Code:
Method: {method}
Path: {url}
Code (snippets):
{code_blob}

{CTX_TOOLS}

CRITICAL RULES FOR CODE GENERATION:
1. The code MUST end with: return {{'path': {{...}}, 'query': {{...}}, 'body': {{...}}}}.
2. Do NOT import modules. Use only the provided `ctx` tools.
3. The code should be a function body only (no def/class, no code fences).
4. Only use request parameters and requestBody inferred from the code context. Do NOT include response fields.
5. If there is no request body for GET/DELETE, leave body empty.
6. Keep payload minimal and likely to pass validation.
Output Format: JSON matching the CodeGenerationOutput model.
""".strip()

def build_payload_factory_prompt_with_parse_error_from_base(
    base_prompt: str,
    parse_error: str,
) -> str:
    return f"""
{base_prompt}

Issue:
Your previous code failed to parse.

Parse error:
{parse_error}

Please fix the syntax and return a corrected version.
""".strip()


def build_payload_factory_prompt_with_runtime_error_from_base(
    base_prompt: str,
    runtime_error: str,
) -> str:
    return f"""
{base_prompt}

----------------------------------------------------------------------
!!! RUNTIME DIAGNOSTIC REPORT !!!
----------------------------------------------------------------------
Your previous code ran, but the API request FAILED.
Below is the full execution log containing the HTTP Status, Server Response, Payload Sent, and the Code used.

[EXECUTION LOG]
{runtime_error}

[RECOVERY INSTRUCTIONS]
1. **Analyze the Log**: 
   - Look at the **HTTP Response**: What is the server complaining about?
   - Compare the **Payload Sent** vs **Previous Code**: Did the code generate what you expected?
   - Check the **Previous Code**: Locate the logic error based on the server's complaint.
   - Please imagine the logic of server, think why this playload cause error.

2. **Heuristic Strategy: The "KISS" Principle**:
   - **Reduce Complexity**: If the error suggests validation failure on a complex field (like `rules` or `config`), do NOT try to "fix" the complex values inside it. Instead, **fallback to the SIMPLEST valid form**.
   - **Minimal Viable Payload**: 
     - If a list/dict is optional or can be empty, try sending it empty.
     - If it requires items, send the bare minimum required fields only.
   - **ID Format**: If "Invalid ID/UID", check if you are using a standard UUID where a short string was expected (or vice versa).

3. **Action**:
   - Rewrite the code based on the analysis above.
   - **Explain your fix** in the explanation field (e.g., "Simplified 'rules' parameter to an empty list to avoid validation errors").

Please return the **CORRECTED** Python code.
""".strip()

def build_payload_factory_prompt_with_parse_error(
    project_name: str,
    method: str,
    url: str,
    doc_json: str,
    parse_error: str,
) -> str:
    base_prompt = build_payload_factory_prompt(project_name, method, url, doc_json)
    return f"""
{base_prompt}

Issue:
Your previous code failed to parse.

Parse error:
{parse_error}

Please fix the syntax and return a corrected version.
""".strip()


def build_payload_factory_prompt_with_runtime_error(
    project_name: str,
    method: str,
    url: str,
    doc_json: str,
    runtime_error: str,
) -> str:
    base_prompt = build_payload_factory_prompt(project_name, method, url, doc_json)
    return f"""
{base_prompt}

----------------------------------------------------------------------
!!! RUNTIME DIAGNOSTIC REPORT !!!
----------------------------------------------------------------------
Your previous code ran, but the API request FAILED.
Below is the full execution log containing the HTTP Status, Server Response, Payload Sent, and the Code used.

[EXECUTION LOG]
{runtime_error}

[RECOVERY INSTRUCTIONS]
1. **Analyze the Log**: 
   - Look at the **HTTP Response**: What is the server complaining about?
   - Compare the **Payload Sent** vs **Previous Code**: Did the code generate what you expected?
   - Check the **Previous Code**: Locate the logic error based on the server's complaint.
   - Please imagine the logic of server, think why this playload cause error.

2. **Heuristic Strategy: The "KISS" Principle**:
   - **Reduce Complexity**: If the error suggests validation failure on a complex field (like `rules` or `config`), do NOT try to "fix" the complex values inside it. Instead, **fallback to the SIMPLEST valid form**.
   - **Minimal Viable Payload**: 
     - If a list/dict is optional or can be empty, try sending it empty.
     - If it requires items, send the bare minimum required fields only.
   - **ID Format**: If "Invalid ID/UID", check if you are using a standard UUID where a short string was expected (or vice versa).

3. **Action**:
   - Rewrite the code based on the analysis above.
   - **Explain your fix** in the explanation field (e.g., "Simplified 'rules' parameter to an empty list to avoid validation errors").

Please return the **CORRECTED** Python code.
""".strip()


def build_dep_key_fields_prompt(
    method: str,
    path: str,
    request_fields: str,
    project_name: str,
) -> str:
    return f"""
You are an expert API dependency analyst.
Project: {project_name}

Task: From the request fields listed below, select the fields that most likely require values
produced by other APIs (ids, tokens, foreign keys, parent references). Only choose from the
provided fields; do NOT invent new fields. The list can be empty.
Use `location` as one of: path, header, query, body. Use `name` as the dotted field path
shown after the location prefix in the request fields list.

API:
Method: {method}
Path: {path}

Request fields:
{request_fields}

Output Format: JSON matching the KeyFieldSelection model.
""".strip()


def build_dep_candidate_prompt(
    method: str,
    path: str,
    key_fields: str,
    api_catalog: str,
    project_name: str,
) -> str:
    return f"""
You are an expert API dependency analyst.
Project: {project_name}

Task: Choose up to 5 producer APIs that can provide values for the key fields below.
Only choose from the API catalog. Return fewer than 5 if uncertain.
Prefer POST producers over GET, and GET over PATCH when choosing candidates.
For `id`-like key fields, strongly prefer APIs whose resource in path matches the consumer resource.
Avoid relying on nested identity fields (such as owner.id / namespace.id / user.id) unless the consumer field explicitly targets those entities.

Consumer:
Method: {method}
Path: {path}

Key fields:
{key_fields}

API catalog (method path | resource | request keys | response keys | id-like response keys):
{api_catalog}

Output Format: JSON matching the CandidateSelection model.
""".strip()


def build_dep_mapping_prompt(
    method: str,
    path: str,
    consumer_request_fields: str,
    producer_response_details: str,
    history_text: str | None = None,
    project_name: str = "Unknown",
) -> str:
    history_block = ""
    if history_text:
        history_block = f"\nPrevious attempts and failures:\n{history_text}\n"
    return f"""
You are an expert API dependency analyst.
Project: {project_name}

Task: Map producer response fields to consumer request fields for dependency binding.
Only use the fields listed below. If unsure, return an empty mappings list.
Use field names in `producer_field` and `consumer_field` as location-prefixed dotted paths,
exactly as shown in the field lists (e.g., body.user.id, path.collectionId).
Each producer API provides at most one response field candidate per key field.
Prefer POST producers over GET, and GET over PATCH when selecting mappings.
If a POST would register or create a user, prefer GET unless the GET user's data does not satisfy the required conditions.
For `path.id` or `*id` consumer fields, prioritize same-resource IDs and avoid cross-resource IDs.
Do not map non-ID semantic fields (such as name/path/title) to ID fields unless there is explicit evidence in the field names.
{history_block}


Consumer:
Method: {method}
Path: {path}

Consumer request fields:
{consumer_request_fields}

Producer response fields (top candidates):
{producer_response_details}

Output Format: JSON matching the FieldMappingResult model.
""".strip()


def build_failure_classification_prompt(
    consumer_method: str,
    consumer_path: str,
    failed_method: str,
    failed_path: str,
    status_code: str,
    response_text: str,
    request_payload: str,
    project_name: str,
) -> str:
    return f"""
You are an expert API testing analyst.
Project: {project_name}

Task: Classify the failure as one of:
- dependency_error: missing/invalid identifiers, foreign keys, or values that should be produced by other APIs.
- parameter_error: wrong format/type/value/constraints for parameters (input validation).
- unknown: not enough information.

Consumer:
Method: {consumer_method}
Path: {consumer_path}

Failed API:
Method: {failed_method}
Path: {failed_path}
Status: {status_code}

Request payload:
{request_payload}

Response text:
{response_text}

Output Format: JSON matching the FailureClassification model.
""".strip()


def build_vuln_payload_plan_prompt(
    project_name: str,
    vuln_type: str,
    method: str,
    path: str,
    failures_json: str,
    code_blob: str | None = None,
) -> str:
    code_block = ""
    if code_blob:
        code_block = f"\nCode context (snippets):\n{code_blob}\n"
    return f"""
You are an expert API security tester.
Project: {project_name}
Vulnerability type: {vuln_type}

Task: All attack payloads for the same target field failed. Diagnose the failure reason and propose the next step.

Rules:
- Choose error_type: dependency_error, parameter_error, unknown.
- If dependency_error: payloads must be [] and code must be "".
- If parameter_error: provide 1-4 payload strings and Python code that builds the request using `payload`.
- Keep testing the exact API shown below. Do NOT switch to a different path or method.
- If failures are 404/Not Found and the request path contains random values or unresolved placeholders for path parameters, choose dependency_error because the path value likely needs to be produced by another API.
- The code MUST be a function body only (no def/class) and MUST end with:
  return {{'path': {{...}}, 'query': {{...}}, 'body': {{...}}}}
- Do NOT import modules. Use only the ctx tools listed below.

{CTX_TOOLS}

- Do not include Markdown or code fences.
- You MAY transform payloads, but the core MUST NOT change.
  - For SSRF: core = scheme + host + port must remain unchanged; only path/query may change.
  - For XSS: the original payload string must appear verbatim as a substring (you may wrap/prefix/suffix it).

Failures (JSON list):
{failures_json}
{code_block}

Example output (parameter_error):
{{"error_type":"parameter_error","reason":"example","payloads":["1","2"],"code":"return {{'path': {{}}, 'query': {{}}, 'body': {{'name': payload}}}}"}}

Output Format: JSON matching the VulnPayloadPlan model.
""".strip()


def build_upload_file_type_prompt(
    method: str,
    path: str,
    file_fields: list[str],
    file_field_descs: dict[str, str],
    content_types: list[str],
    last_response_text: str,
    allowed_types: list[str],
    project_name: str,
) -> str:
    allowed = ", ".join(allowed_types)
    fields = ", ".join(file_fields)
    content = ", ".join(content_types) if content_types else "<none>"
    desc_lines = []
    for name in file_fields:
        desc = file_field_descs.get(name, "")
        if desc:
            desc_lines.append(f"- {name}: {desc}")
        else:
            desc_lines.append(f"- {name}: <none>")
    desc_block = "\n".join(desc_lines)
    return f"""
You are an expert API testing analyst.
Project: {project_name}

Task: Choose the most appropriate file type for a multipart upload request.
Only choose from the allowed types list.
Also choose which of the multipart file fields should be uploaded as files.
Only choose from the provided multipart file fields list.
If you think a field should be sent as a normal text field, omit it from use_file_fields.
If the field description mentions tar.gz or gzip, prefer a gzip-compatible type.

API:
Method: {method}
Path: {path}

Multipart file fields: {fields}
Field descriptions:
{desc_block}
Spec content types: {content}

Last response (if any):
{last_response_text}

Allowed types: {allowed}

Output Format: JSON matching the FileTypeChoice model.
""".strip()


def build_upload_file_gen_prompt(
    method: str,
    path: str,
    file_fields: list[str],
    file_field_descs: dict[str, str],
    content_types: list[str],
    last_response_text: str,
    output_path: str,
    project_name: str,
) -> str:
    fields = ", ".join(file_fields)
    content = ", ".join(content_types) if content_types else "<none>"
    desc_lines = []
    for name in file_fields:
        desc = file_field_descs.get(name, "")
        if desc:
            desc_lines.append(f"- {name}: {desc}")
        else:
            desc_lines.append(f"- {name}: <none>")
    desc_block = "\n".join(desc_lines)
    return f"""
You are an expert API testing analyst.
Project: {project_name}

Task: Generate Python code that writes a small, valid file to the given output_path.
The code MUST write the file to output_path and should be minimal. Do NOT import modules.
You may use only: open, bytes, str, len, range, json, base64, os.

API:
Method: {method}
Path: {path}

Multipart file fields: {fields}
Field descriptions:
{desc_block}
Spec content types: {content}

Last response (if any):
{last_response_text}

Output path:
{output_path}

Output Format: JSON matching the FileGenCode model.
""".strip()


def build_repair_plan_prompt(
    failed_method: str,
    failed_path: str,
    status_code: str,
    response_text: str,
    api_catalog: str,
    project_name: str,
) -> str:
    return f"""
You are an expert API testing analyst.
Project: {project_name}

Task: Propose up to 3 repair APIs that should be called BEFORE the failed API
to resolve the failure. Only choose from the API catalog. Return an empty list
if no repair is needed or you are unsure.

The list is executed in the order you give, so it may be a chain rather than a
single call. Creating a resource is often not enough on its own: when the
response says a resource is missing, not deployed, not active, not enabled, or
not attached, include BOTH the endpoint that creates it AND the endpoint that
activates or attaches it, in that order. Read the response text for the verb it
asks for -- "deploy tag before trying to execute" means a create step followed
by the endpoint that sets the tag, not the create step alone. A chain that stops
one step short repairs nothing, so prefer the complete chain over the shortest
one.

Failed API:
Method: {failed_method}
Path: {failed_path}
Status: {status_code}
Response: {response_text}

API catalog (method path | request keys | response keys):
{api_catalog}

Output Format: JSON matching the RepairPlan model.
""".strip()
