import base64
import json
import logging
import os
import random
import re
import uuid
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Optional, Literal

import jsonref
from pydantic import BaseModel, Field

from models.parameter import (
    ArrayParameter,
    BasicParameter,
    Parameter,
    PropertyParameter,
)
from models.types import ParamType
from utils.llm_client import LLMClient
from utils.prompts import build_upload_file_gen_prompt, build_upload_file_type_prompt


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MultipartEndpoint:
    file_fields: list[str]
    content_types: list[str]
    file_field_descs: dict[str, str]
    # The non-file half of a multipart body. RESTler's compiler emits no body
    # parameters for multipart/form-data at all, so without this the model never
    # sees them and a required non-file field is left unset.
    form_fields: dict[str, dict] = dataclass_field(default_factory=dict)


class MultipartSpecIndex:
    def __init__(self, spec_path: str):
        self.spec = self._load_and_deref(spec_path)
        self.multipart: dict[str, MultipartEndpoint] = {}
        self._build_index()

    def _load_and_deref(self, path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith((".yaml", ".yml")):
                import yaml

                base = yaml.safe_load(f)
            else:
                base = json.load(f)
        return jsonref.replace_refs(base, base_uri=path, proxies=False)

    def _build_index(self) -> None:
        paths = self.spec.get("paths", {})
        for url, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                req = details.get("requestBody") or {}
                content = req.get("content") or {}
                if "multipart/form-data" not in content:
                    continue
                schema = content.get("multipart/form-data", {}).get("schema") or {}
                file_fields = _extract_file_fields(schema)
                if not file_fields:
                    continue
                file_field_descs = _extract_file_field_descs(schema, file_fields)
                key = f"{method.upper()} {url}"
                self.multipart[key] = MultipartEndpoint(
                    file_fields=file_fields,
                    content_types=list(content.keys()),
                    file_field_descs=file_field_descs,
                    form_fields=_extract_form_fields(schema, file_fields),
                )

    def get(self, method: str, path: str) -> Optional[MultipartEndpoint]:
        key = f"{method.upper()} {path}"
        return self.multipart.get(key)


_FILE_NAME_KEYWORDS = ("file", "upload", "image", "avatar", "photo", "document", "attachment")
_FILE_DESC_KEYWORDS = (" file", "binary", "upload")


def _extract_file_fields(schema: dict) -> list[str]:
    file_fields: list[str] = []
    if schema.get("type") == "string" and schema.get("format") in ("binary", "byte"):
        return ["file"]
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    for name, prop in props.items():
        if not isinstance(prop, dict):
            continue
        if prop.get("format") in ("binary", "byte"):
            file_fields.append(name)
            continue
        name_lower = str(name).lower()
        desc = str(prop.get("description") or "").lower()
        if any(keyword in name_lower for keyword in _FILE_NAME_KEYWORDS):
            file_fields.append(name)
            continue
        if any(keyword in desc for keyword in _FILE_DESC_KEYWORDS):
            file_fields.append(name)
            continue
    if not file_fields and "file" in required:
        if "file" in props:
            return ["file"]
    return file_fields


def _extract_file_field_descs(schema: dict, file_fields: list[str]) -> dict[str, str]:
    props = schema.get("properties") or {}
    descs: dict[str, str] = {}
    for name in file_fields:
        prop = props.get(name)
        if isinstance(prop, dict):
            descs[name] = str(prop.get("description") or "")
        else:
            descs[name] = ""
    return descs


def _extract_form_fields(schema: dict, file_fields: list[str]) -> dict[str, dict]:
    """The multipart properties that are not files, keyed by name.

    Values keep the raw sub-schema plus a `required` flag so callers can rebuild
    a parameter without re-reading the spec.
    """
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    fields: dict[str, dict] = {}
    for name, prop in props.items():
        if name in file_fields or not isinstance(prop, dict):
            continue
        fields[name] = {"schema": prop, "required": name in required}
    return fields


def inject_multipart_form_params(
    api_model_list: list, spec_index: "MultipartSpecIndex"
) -> list[str]:
    """Add a multipart endpoint's non-file form fields to its request body model.

    Returns one description per injected field, for logging. Existing body
    parameters are never overwritten: if a body model already has the field
    (from a spec variant that does declare it), that definition wins.
    """
    injected: list[str] = []
    for api in api_model_list:
        info = spec_index.get(api.api_method.value, api.api_url)
        if not info or not info.form_fields:
            continue
        body = api.request_structure.body
        for name, meta in info.form_fields.items():
            if name in body:
                continue
            body[name] = _param_from_schema(name, meta["schema"], meta["required"])
            injected.append(
                f"{api.api_method.value} {api.api_url}: {name}"
                f"{'*' if meta['required'] else ''}"
            )
    return injected


_OPENAPI_TYPE_MAP = {
    "string": ParamType.STRING,
    "integer": ParamType.INTEGER,
    "number": ParamType.NUMBER,
    "boolean": ParamType.BOOLEAN,
}

_OPENAPI_FORMAT_MAP = {
    "date-time": ParamType.DATETIME,
    "date": ParamType.DATE,
    "uuid": ParamType.UUID,
}


def _param_from_schema(name: str, schema: dict, is_required: bool) -> Parameter:
    """Build a Parameter from an OpenAPI property sub-schema.

    Arrays and objects get the dedicated classes rather than a BasicParameter:
    RandomValueDict has no ARRAY entry, so a BasicParameter of that type raises
    from get_random_value the first time the generator reaches for a value.
    """
    stype = schema.get("type")
    if stype == "array":
        item_schema = schema.get("items") or {}
        return ArrayParameter(
            name, item=_param_from_schema(name, item_schema, False), is_required=is_required
        )
    if stype == "object":
        props = schema.get("properties") or {}
        return PropertyParameter(
            name,
            properties={
                k: _param_from_schema(k, v, k in set(schema.get("required") or []))
                for k, v in props.items()
                if isinstance(v, dict)
            },
            is_required=is_required,
        )
    param_type = _OPENAPI_FORMAT_MAP.get(str(schema.get("format") or ""))
    if param_type is None:
        param_type = _OPENAPI_TYPE_MAP.get(str(stype), ParamType.STRING)
    example = schema.get("example")
    default = schema.get("default")
    enum = schema.get("enum") or []
    return BasicParameter(
        name,
        param_type,
        example=[example] if example is not None else list(enum),
        default=[default] if default is not None else [],
        is_required=is_required,
    )


class FileTypeChoice(BaseModel):
    file_type: Literal[
        "text/plain",
        "application/json",
        "image/png",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/octet-stream",
        "application/pdf",
        "audio/wav",
    ]
    use_file_fields: list[str]
    reason: str = ""


class FileGenCode(BaseModel):
    filename: str
    mime_type: str
    code: str = Field(..., description="Python code to write file to output_path")


@dataclass
class MultipartHandler:
    spec_index: MultipartSpecIndex
    sample_dir: Path
    llm_client: LLMClient
    model: Optional[str] = None
    output_dir: Path = Path("/tmp/voapi_uploads")
    project_name: str = "Unknown"

    def __post_init__(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sample_map = _build_sample_map(self.sample_dir)
        if not self._sample_map:
            logger.warning("Multipart sample dir is empty: %s", self.sample_dir)

    def is_multipart(self, method: str, path: str) -> bool:
        return self.spec_index.get(method, path) is not None

    def prepare_files(
        self,
        method: str,
        path: str,
        attempt: int,
        last_response_text: Optional[str],
    ) -> Optional[dict]:
        info = self.spec_index.get(method, path)
        if not info:
            return None
        file_fields = info.file_fields
        if not file_fields:
            return None
        file_field_descs = info.file_field_descs

        candidate = None
        use_fields = file_fields
        if attempt <= 2:
            candidate, use_fields = self._pick_by_llm(
                method,
                path,
                file_fields,
                file_field_descs,
                info.content_types,
                last_response_text,
            )
            if not use_fields:
                return None
            if candidate is None and attempt == 1:
                candidate = _pick_random_sample(self._sample_map)
            if candidate is None and attempt == 2:
                candidate = self._generate_by_llm(
                    method,
                    path,
                    use_fields,
                    file_field_descs,
                    info.content_types,
                    last_response_text,
                )
        else:
            candidate = self._generate_by_llm(
                method,
                path,
                use_fields,
                file_field_descs,
                info.content_types,
                last_response_text,
            )

        if candidate is None:
            return None
        files = {}
        for field in use_fields:
            files[field] = (candidate.filename, candidate.data, candidate.mime_type)
        return files

    def _pick_by_llm(
        self,
        method: str,
        path: str,
        file_fields: list[str],
        file_field_descs: dict[str, str],
        content_types: list[str],
        last_response_text: Optional[str],
    ):
        allowed = sorted(self._sample_map.keys())
        if "application/gzip" in allowed and "application/x-gzip" not in allowed:
            allowed.append("application/x-gzip")
        if "application/x-gzip" in allowed and "application/gzip" not in allowed:
            allowed.append("application/gzip")
        if not allowed:
            return None
        prompt = build_upload_file_type_prompt(
            method,
            path,
            file_fields,
            file_field_descs,
            content_types,
            last_response_text or "",
            allowed,
            self.project_name,
        )
        result, _usage = self.llm_client.ask_with_usage(
            prompt, FileTypeChoice, model=self.model
        )
        return _pick_sample_by_type(self._sample_map, result.file_type), result.use_file_fields

    def _generate_by_llm(
        self,
        method: str,
        path: str,
        file_fields: list[str],
        file_field_descs: dict[str, str],
        content_types: list[str],
        last_response_text: Optional[str],
    ):
        output_name = f"llm_{uuid.uuid4().hex}.bin"
        output_path = self.output_dir / output_name
        prompt = build_upload_file_gen_prompt(
            method,
            path,
            file_fields,
            file_field_descs,
            content_types,
            last_response_text or "",
            str(output_path),
            self.project_name,
        )
        result, _usage = self.llm_client.ask_with_usage(
            prompt, FileGenCode, model=self.model
        )
        # The snippet is LLM-authored, so it fails in arbitrary ways (truncated
        # base64, bad imports, ...). A broken upload payload must not abort the
        # whole run; fall back to the sample files instead.
        try:
            _execute_file_gen_code(result.code, output_path)
            data = output_path.read_bytes()
        except Exception as exc:
            logger.warning(
                "Multipart LLM file generation failed for %s %s: %s",
                method,
                path,
                exc,
            )
            return None
        return _FileCandidate(
            filename=result.filename or output_name,
            mime_type=result.mime_type or "application/octet-stream",
            data=data,
        )


@dataclass(frozen=True)
class _FileCandidate:
    filename: str
    mime_type: str
    data: bytes


def _build_sample_map(sample_dir: Path) -> dict[str, list[_FileCandidate]]:
    mapping: dict[str, list[_FileCandidate]] = {}
    for path in sample_dir.glob("*"):
        if not path.is_file():
            continue
        mime = _guess_mime(path)
        data = path.read_bytes()
        mapping.setdefault(mime, []).append(
            _FileCandidate(filename=path.name, mime_type=mime, data=data)
        )
    return mapping


def _guess_mime(path: Path) -> str:
    ext = path.suffix.lower()
    suffixes = [s.lower() for s in path.suffixes]
    if ext == ".txt":
        return "text/plain"
    if ext == ".json":
        return "application/json"
    if ext == ".png":
        return "image/png"
    if ext == ".zip":
        return "application/zip"
    if suffixes[-2:] == [".tar", ".gz"] or ext in (".tgz", ".gz"):
        return "application/gzip"
    if ext == ".pdf":
        return "application/pdf"
    if ext == ".wav":
        return "audio/wav"
    return "application/octet-stream"


def _pick_random_sample(
    sample_map: dict[str, list[_FileCandidate]]
) -> Optional[_FileCandidate]:
    all_samples = [s for group in sample_map.values() for s in group]
    if not all_samples:
        return None
    return random.choice(all_samples)


def _pick_sample_by_type(
    sample_map: dict[str, list[_FileCandidate]], mime_type: str
) -> Optional[_FileCandidate]:
    normalized = _normalize_mime(mime_type)
    group = sample_map.get(normalized)
    if not group and normalized == "application/gzip":
        group = sample_map.get("application/x-gzip")
    if not group:
        return None
    return random.choice(group)


def _normalize_mime(mime_type: str) -> str:
    if mime_type == "application/x-gzip":
        return "application/gzip"
    return mime_type


def _execute_file_gen_code(code: str, output_path: Path) -> None:
    safe_builtins = {
        "__import__": __import__,
        "open": open,
        "bytes": bytes,
        "str": str,
        "len": len,
        "range": range,
    }
    globals_dict = {
        "__builtins__": safe_builtins,
        "base64": base64,
        "json": json,
        "os": os,
        "output_path": str(output_path),
    }
    locals_dict: dict = {}
    exec(code, globals_dict, locals_dict)
