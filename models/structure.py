from dataclasses import dataclass, field
from typing import Dict, Any
from models.parameter import Parameter, build_parameter


@dataclass
class RequestStructure:
    """Request structure representation."""
    path:dict[str, Parameter] = field(default_factory=dict)
    header:dict[str, Parameter] = field(default_factory=dict)
    query:dict[str, Parameter] = field(default_factory=dict)
    body:dict[str, Parameter] = field(default_factory=dict)


@dataclass
class ResponseStructure:
    """Response structure representation."""
    body:dict[str, Parameter] = field(default_factory=dict)
    header:dict[str, Parameter] = field(default_factory=dict)


def build_request_structure(api_request:dict[str, Any]) -> RequestStructure:
    assert isinstance(api_request, dict), "api_request must be a dict"
    assert "path" in api_request, "path must be in api_request"
    assert "header" in api_request, "header must be in api_request"
    assert "query" in api_request, "query must be in api_request"
    assert "body" in api_request, "body must be in api_request"
    return RequestStructure(
        path={k: build_parameter(v, k) for k, v in api_request["path"].items()},
        header={k: build_parameter(v, k) for k, v in api_request["header"].items()},
        query={k: build_parameter(v, k) for k, v in api_request["query"].items()},
        body={k: build_parameter(v, k) for k, v in api_request["body"].items()}
    )

def build_response_structure(api_response:dict[str, Any]) -> ResponseStructure:
    assert isinstance(api_response, dict), "api_response must be a dict"
    assert "bodyResponse" in api_response, "bodyResponse must be in api_response"
    assert "headerResponse" in api_response, "headerResponse must be in api_response"
    return ResponseStructure(
        body={k: build_parameter(v, k) for k, v in api_response["bodyResponse"].items()},
        header={k: build_parameter(v, k) for k, v in api_response["headerResponse"].items()}
    )