from enum import Enum
from typing import Dict, List, Any, Callable
import numpy
import random
import string


class ParamType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    NUMBER = "number"
    ARRAY = "array"
    OBJECT = "object"
    UUID = "uuid"
    DATETIME = "datetime"
    DATE = "date"
    FILE = "file"


RandomValueDict: dict[ParamType, list[Any]] = {
    ParamType.STRING: ["test" + str(i) for i in range(44)],
    ParamType.UUID: ["566048da-ed19-4cd3-8e0a-b7e0e1ec4d" + str(i) for i in range(10, 54)],
    ParamType.DATETIME: [str(i) + "-04-04T20:20:39+00:00" for i in range(1994, 2038)],
    ParamType.DATE: [str(i) + "-04-04" for i in range(1994, 2038)],
    ParamType.NUMBER: [round(x, 2) for x in list(numpy.arange(4.40, 4.84, 0.01))],
    ParamType.INTEGER: list(range(44)),
    ParamType.BOOLEAN: [True, False] * 22,
    ParamType.OBJECT: [{"VoAPI" + str(i): False} for i in range(11)]
    + [{"VoAPI" + str(i): i} for i in range(11, 22)]
    + [{"VoAPI" + str(i): "VoAPI" + str(i - 11)} for i in range(22, 33)]
    + [
        {"VoAPI" + str(i): [round(x, 2) for x in list(numpy.arange(4.40, 4.84, 0.01))][i]}
        for i in range(33, 44)
    ],
    ParamType.FILE: ["binary_file_content"],
}


def generate_email() -> str:
    username_length = random.randint(4, 10)
    username = "".join(random.choices(string.ascii_lowercase, k=username_length))
    domain_length = random.randint(4, 10)
    domain = "".join(random.choices(string.ascii_lowercase, k=domain_length))
    extension = random.choice(["com", "net", "org"])
    email = f"{username}@{domain}.{extension}"
    return email


def generate_password() -> str:
    chars = ""
    chars += string.ascii_uppercase
    chars += string.ascii_lowercase
    chars += string.digits
    chars += string.punctuation
    password = "".join(random.choices(chars, k=14))
    return password


ParamFormatDict: dict[str, Callable[[], Any]] = {
    "email": generate_email,
    "pass": generate_password,
}


class ValueSource(str, Enum):
    VoAPI_TEST = "VoAPI_TEST"
    VoAPI_CONSUMER = "VoAPI_CONSUMER"
    VoAPI_PRODUCER = "VoAPI_PRODUCER"
    VoAPI_CUSTOM = "VoAPI_CUSTOM"
    VoAPI_SPEC = "VoAPI_SPEC"
    VoAPI_FORMAT = "VoAPI_FORMAT"
    VoAPI_SUCCESS = "VoAPI_SUCCESS"
    VoAPI_RANDOM = "VoAPI_RANDOM"
    NONE = "NONE"


ParamValuePriority: dict[ValueSource, int] = {
    ValueSource.VoAPI_TEST: 7,
    ValueSource.VoAPI_CONSUMER: 6,
    ValueSource.VoAPI_PRODUCER: 6,
    ValueSource.VoAPI_CUSTOM: 5,
    ValueSource.VoAPI_SPEC: 4,
    ValueSource.VoAPI_FORMAT: 3,
    ValueSource.VoAPI_SUCCESS: 2,
    ValueSource.VoAPI_RANDOM: 1,
    ValueSource.NONE: 0,
}


class APIMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    TRACE = "TRACE"
    CONNECT = "CONNECT"
    OPTIONS = "OPTIONS"


ProducerMethodPriority = {
    APIMethod.POST: 4,
    APIMethod.PUT: 3,
    APIMethod.GET: 2,
    APIMethod.PATCH: 1,
    APIMethod.HEAD: 0,
    APIMethod.DELETE: 0,
    APIMethod.OPTIONS: 0,
    APIMethod.TRACE: 0,
    APIMethod.CONNECT: 0,
}


ProducerMethods = set([APIMethod.POST, APIMethod.PUT, APIMethod.PATCH, APIMethod.GET])
ProducerMethodsNoGet = set([APIMethod.POST, APIMethod.PUT, APIMethod.PATCH])

class ParamLocation(str, Enum):
    PATH = "path"
    HEADER = "header"
    QUERY = "query"
    BODY = "body"
