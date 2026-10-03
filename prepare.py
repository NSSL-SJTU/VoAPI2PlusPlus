# TODO: need to refactor
from models.api_model import APIModel
from RESTlerCompileParser import parse_restler_compile
from models.structure import build_request_structure, build_response_structure


def get_api_list(api_info_file: str) -> list[APIModel]:
    api_template_list = parse_restler_compile(api_info_file)
    return [
        APIModel(
            api_template.api_url,
            api_template.api_method,
            build_request_structure(api_template.api_request),
            build_response_structure(api_template.api_response),
        )
        for api_template in api_template_list
    ]
