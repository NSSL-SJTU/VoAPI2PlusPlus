import random
from typing import Optional, Tuple, Any

from .structure import RequestStructure, ResponseStructure
from .parameter import Parameter, BasicParameter, ArrayParameter, PropertyParameter
from .types import (
    ParamType,
    ValueSource,
    RandomValueDict,
    ParamFormatDict,
    ParamValuePriority,
    APIMethod,
)


class APIModel:
    api_url: str
    api_method: APIMethod
    request_structure: RequestStructure
    response_structure: ResponseStructure
    payload_factory_code: Optional[str]
    code_explanation: Optional[str]

    def __init__(
        self,
        api_url: str,
        api_method: str,
        request_structure: RequestStructure,
        response_structure: ResponseStructure,
        payload_factory_code: Optional[str] = None,
        code_explanation: Optional[str] = None,
    ):
        self.api_url = self.clean_url(api_url)

        self.api_method = APIMethod(api_method.upper())
        self.request_structure = request_structure
        self.response_structure = response_structure
        self.payload_factory_code = payload_factory_code
        self.code_explanation = code_explanation

        self.init_request_values()
        self.init_response_values()

    def __repr__(self):
        return f"APIModel(api_url={self.api_url}, api_method={self.api_method}, request_structure={self.request_structure}, response_structure={self.response_structure})"

    def simple_repr(self):
        return f"APIModel(api_url={self.api_url}, api_method={self.api_method})"

    def clean_url(self, url: str) -> str:
        if url.startswith("/"):
            return url
        else:
            return "/" + url

    def generate_random_value(self, param_type: ParamType):
        assert param_type in RandomValueDict, "Invalid parameter type"
        values_to_choose = RandomValueDict[param_type]
        return random.choice(values_to_choose)

    def get_param_format(self, param_name: str) -> Optional[tuple[str, ValueSource]]:
        """get formatted value by parameter name"""
        for format_str in ParamFormatDict:
            if format_str in param_name:
                func = ParamFormatDict[format_str]
                return func(), ValueSource.VoAPI_FORMAT
        return None

    def value_type_conversion(self, value_list, param_type: ParamType):
        result_list = []
        if param_type == ParamType.NUMBER:
            for value in value_list:
                try:
                    result_list.append(float(value))
                except:
                    continue
        elif param_type == ParamType.INTEGER:
            for value in value_list:
                try:
                    result_list.append(int(value))
                except:
                    continue
        elif param_type == ParamType.BOOLEAN:
            for value in value_list:
                if str(value).lower() == "true":
                    result_list.append(True)
                elif str(value).lower() == "false":
                    result_list.append(False)
                else:
                    continue
        else:
            result_list = value_list
        return result_list

    def assign_parameter_value(self, param: Parameter, param_name: str = ""):
        if isinstance(param, BasicParameter):
            final_value = None
            final_source = None

            if param.default:
                if "RESTler" not in str(param.default):
                    converted_values = self.value_type_conversion(param.default, param.param_type)
                    if converted_values:
                        final_value = converted_values[0]
                        final_source = ValueSource.VoAPI_SPEC
                else:
                    final_value = self.generate_random_value(param.param_type)
                    final_source = ValueSource.VoAPI_RANDOM

            if param.example:
                converted_values = self.value_type_conversion(param.example, param.param_type)
                if converted_values:
                    # Sample across the examples instead of always taking the first, so
                    # multi-valued examples (enum constants like editorType's
                    # MARKDOWN/RICHTEXT) actually get exercised. Trade-off: value
                    # selection is no longer deterministic across runs.
                    final_value = random.choice(converted_values)
                    final_source = ValueSource.VoAPI_SPEC

            format_result = self.get_param_format(param_name)
            if format_result:
                format_value, format_source = format_result
                format_priority = ParamValuePriority.get(format_source, 0)
                final_priority = (
                    ParamValuePriority.get(final_source, 0) if final_source is not None else 0
                )
                if final_source is None or format_priority > final_priority:
                    final_value = format_value
                    final_source = format_source

            if final_value is None:
                final_value = self.generate_random_value(param.param_type)
                final_source = ValueSource.VoAPI_RANDOM

            param.value = final_value
            param.value_source = (
                final_source if final_source is not None else ValueSource.VoAPI_RANDOM
            )

        elif isinstance(param, ArrayParameter):
            if param.item:
                self.assign_parameter_value(param.item, param_name)

        elif isinstance(param, PropertyParameter):
            for prop_name, prop_param in param.properties.items():
                self.assign_parameter_value(prop_param, prop_name)

    def reset_request_values(self):
        """reset request parameter values (force re-generate random values)"""
        self.init_request_values()

    def init_request_values(self):
        """initialize request parameter values, directly modify Parameter object"""
        # handle path parameters
        for param_name, param in self.request_structure.path.items():
            self.assign_parameter_value(param, param_name)

        # handle header parameters
        for param_name, param in self.request_structure.header.items():
            self.assign_parameter_value(param, param_name)

        # handle query parameters
        for param_name, param in self.request_structure.query.items():
            self.assign_parameter_value(param, param_name)

        # handle body parameters
        for param_name, param in self.request_structure.body.items():
            self.assign_parameter_value(param, param_name)

    def assign_response_value_sepc(self, param: Parameter):
        if isinstance(param, BasicParameter):
            param_name_value = []

            # only use specification value for response
            if param.default:
                assert isinstance(param.default, list), "default must be a list"
                if "RESTler" not in str(param.default[0]):
                    default_list = self.value_type_conversion(param.default, param.param_type)
                    if default_list:
                        param_name_value = [default_list[0], ValueSource.VoAPI_SPEC]

            if param.example:
                assert isinstance(param.example, list), "example must be a list"
                example_list = self.value_type_conversion(param.example, param.param_type)
                if example_list:
                    param_name_value = [example_list[0], ValueSource.VoAPI_SPEC]

            # set value for Parameter object
            if param_name_value:
                param.value = param_name_value[0]
                param.value_source = param_name_value[1]

        elif isinstance(param, ArrayParameter):
            if param.item:
                self.assign_response_value_sepc(param.item)

        elif isinstance(param, PropertyParameter):
            for prop_param in param.properties.values():
                self.assign_response_value_sepc(prop_param)

    def init_response_values(self):
        """
        initialize response parameter values,
        directly modify Parameter object
        only use *specification* value for response
        """

        for param in self.response_structure.body.values():
            self.assign_response_value_sepc(param)

        for param in self.response_structure.header.values():
            self.assign_response_value_sepc(param)

    def show(self):
        """show API model info"""
        print("api_url: ", self.api_url)
        print("api_method: ", self.api_method)
        print("request_structure: ", self.request_structure)
        print("response_structure: ", self.response_structure)

    def show_txt(self, file_name: str = "api_model.txt"):
        """save API model info to text file"""
        show_str = self.to_txt()
        with open(file_name, "a+") as f:
            f.write(show_str)

    def to_txt(self):
        """convert API model to text representation"""
        show_str = "api_url: " + self.api_url + "\n"
        show_str += "api_method: " + self.api_method + "\n"
        show_str += "request_structure: " + str(self.request_structure) + "\n"
        show_str += "response_structure: " + str(self.response_structure) + "\n"
        show_str += "##################" + "\n"
        return show_str
