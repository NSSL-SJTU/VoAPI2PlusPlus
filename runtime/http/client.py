# runtime/http/client.py

from dataclasses import dataclass
from typing import Any, ClassVar
import json
import logging
import requests
from runtime.materializers.request import RequestPayload
from models.types import APIMethod
from requests_toolbelt.utils import dump

logger = logging.getLogger(__name__)
ERROR_STATUS_CODE = 599


@dataclass
class HTTPResponse:
    status_code: int
    text: str
    headers: dict[str, str]
    custom_judge: ClassVar[bool] = False
    fail_str: ClassVar[list[str]]
    success_str: ClassVar[str]

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except Exception:
            return None

    @property
    def ok(self) -> bool:
        if self.custom_judge:
            logging.info(f"success_str: {self.success_str}")
            logging.info(f"fail_str: {self.fail_str}")
            logging.info(f"text: {self.text}")
            return (
                str(self.status_code).startswith("2")
                and self.success_str in self.text
                and all(fail_str not in self.text for fail_str in self.fail_str)
            )
        return str(self.status_code).startswith("2")


@dataclass(frozen=True)
class HTTPClient:
    baseurl: str
    timeout: float = 4.0
    _global_request_count: ClassVar[int] = 0
    _global_500_apis: ClassVar[set[str]] = set()

    @classmethod
    def reset_global_count(cls) -> None:
        cls._global_request_count = 0
        cls._global_500_apis = set()

    @classmethod
    def global_count(cls) -> int:
        return int(cls._global_request_count)

    @classmethod
    def global_500_count(cls) -> int:
        return len(cls._global_500_apis)

    def __post_init__(self):
        if self.baseurl.endswith("/"):
            object.__setattr__(self, "baseurl", self.baseurl.rstrip("/"))

    def _format_url(self, api_url: str, path: dict[str, Any]) -> str:
        url = api_url
        for k, v in (path or {}).items():
            url = url.replace(f"{{{k}}}", str(v))
        return self.baseurl + url

    def _remove_cookie_from_headers(self, headers: dict[str, str]) -> dict[str, str]:
        return {"Cookie": "******"} | {k: v for k, v in headers.items() if k != "Cookie"}

    def _log_split_line(self):
        logger.info("-" * 30 + "send request" + "-" * 30)

    def _log_request(
        self,
        method: APIMethod,
        url: str,
        headers: dict[str, str],
        query: dict[str, Any],
        body: Any,
        json_body: Any,
    ):
        logger.info("send request: %s %s", method.value.lower(), url)
        logger.info("api_header_dict: %s", self._remove_cookie_from_headers(headers))
        logger.info("api_query_dict: %s", query)
        logger.info("request_data: %s", body)
        logger.info("request_json: %s", json_body)

    def _log_response(self, response: HTTPResponse):
        try:
            logger.info("response: %s", response.text)
            logger.info("status_code: %s", response.status_code)
        except Exception as e:
            logger.error("error: %s", e)

    def normalize_query(self, raw_query: dict[str, Any]) -> dict[str, Any]:
        return {
            k: str(v).lower() if isinstance(v, bool) else v 
                for k, v in raw_query.items()
        }

    def send(
        self,
        method: APIMethod,
        api_url: str,
        request_payload: RequestPayload,
        files=None,
    ) -> HTTPResponse:
        HTTPClient._global_request_count += 1
        path = request_payload.path
        headers = request_payload.header
        query = request_payload.query
        body = request_payload.body
        if files is None and getattr(request_payload, "files", None):
            files = request_payload.files
        url = self._format_url(api_url, path)
        hdrs = {k: str(v) for k, v in headers.items()}

        data = None
        json_body = None

        if files is not None:
            if isinstance(body, dict):
                data = body
            else:
                data = None
            json_body = None
            if "Content-Type" in hdrs:
                hdrs.pop("Content-Type", None)
        elif isinstance(body, (dict, list)):
            if body:
                json_body = body
            elif method in (APIMethod.GET, APIMethod.DELETE, APIMethod.HEAD):
                json_body = None
        elif isinstance(body, (bytes, str)):
            data = body
        elif body is None:
            pass
        else:
            pass

        query = self.normalize_query(query)

        content_type = hdrs.get("Content-Type", "")
        if (
            "application/x-www-form-urlencoded" in content_type.lower()
            and json_body is not None
            and data is None
            and files is None
        ):
            data = json_body
            json_body = None

        # if json_body is not None and "Content-Type" not in hdrs:
        #     hdrs["Content-Type"] = "application/json"
        self._log_split_line()
        self._log_request(method, url, hdrs, query, data, json_body)
        try:
            r = requests.request(
                method=method.value.lower(),
                url=url,
                headers=hdrs,
                params=query or {},
                json=json_body,
                data=data,
                files=files,
                timeout=self.timeout,
            )
            logger.info("request")
            logger.info(dump.dump_all(r).decode("utf-8", errors="replace"))
            logger.info("-" * 30 + "send request" + "-" * 30)
            resp = HTTPResponse(status_code=r.status_code, text=r.text, headers=dict(r.headers))
            if r.status_code == 500:
                HTTPClient._global_500_apis.add(f"{method.value} {api_url}")
            self._log_response(resp)
            return resp
        except Exception as e:

            logger.error("error: %s", e)
            return HTTPResponse(status_code=ERROR_STATUS_CODE, text=str(e), headers={})
