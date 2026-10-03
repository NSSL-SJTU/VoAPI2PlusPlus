import json
from dataclasses import dataclass
from typing import Optional

import jsonref

from models.api_model import APIModel


@dataclass(frozen=True)
class FormEndpoint:
    content_types: list[str]


class FormSpecIndex:
    def __init__(self, spec_path: str):
        self.spec = self._load_and_deref(spec_path)
        self.form: dict[str, FormEndpoint] = {}
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
                if "application/x-www-form-urlencoded" not in content:
                    continue
                key = f"{method.upper()} {url}"
                self.form[key] = FormEndpoint(content_types=list(content.keys()))

    def get(self, method: str, path: str) -> Optional[FormEndpoint]:
        key = f"{method.upper()} {path}"
        return self.form.get(key)


@dataclass
class FormHandler:
    spec_index: FormSpecIndex

    def is_form(self, method: str, path: str) -> bool:
        return self.spec_index.get(method, path) is not None

    def prepare_payload(self, api: APIModel, request_payload):
        endpoint = self.spec_index.get(api.api_method.value, api.api_url)
        if not endpoint:
            return request_payload
        header = dict(request_payload.header or {})
        header["Content-Type"] = "application/x-www-form-urlencoded"
        return request_payload.__class__(
            path=request_payload.path,
            header=header,
            query=request_payload.query,
            body=request_payload.body,
            files=getattr(request_payload, "files", None),
        )
