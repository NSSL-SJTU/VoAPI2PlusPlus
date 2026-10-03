from dataclasses import dataclass, field
from typing import Optional, Any
from models.types import ParamType, ValueSource, RandomValueDict, ParamFormatDict
import random
import logging


logger = logging.getLogger(__name__)


@dataclass
class Parameter:
    """Basic parameter representation."""

    param_name: str
    param_type: ParamType
    is_required: bool = False


@dataclass
class BasicParameter(Parameter):
    example: list[Any] = field(default_factory=list)
    default: list[Any] = field(default_factory=list)
    value: Any = None
    value_source: ValueSource = ValueSource.NONE
    # we will backup the value when testing
    backup_value: Any = None
    backup_value_source: ValueSource = ValueSource.NONE

    def __init__(
        self,
        param_name: str,
        param_type: ParamType,
        example: list[Any] = [],
        default: list[Any] = [],
        is_required: bool = False,
    ):
        super().__init__(param_name, param_type, is_required)
        self.example = example
        self.default = default

    def backup(self):
        self.backup_value = self.value
        self.backup_value_source = self.value_source

    def restore(self):
        self.value = self.backup_value
        self.value_source = self.backup_value_source

    def get_random_value(self) -> str:
        assert self.param_type in RandomValueDict, "Invalid parameter type"
        return random.choice(RandomValueDict[self.param_type])

    def get_format_value(self) -> Optional[str]:
        logger.debug("Getting format value for %s", self.param_name)
        for format_str, func in ParamFormatDict.items():
            if format_str in self.param_name:
                return func()
        logger.warning("No format value found for %s", self.param_name)
        return None


@dataclass
class ArrayParameter(Parameter):
    """Parameter representing an array of other parameters."""

    item: Optional[Parameter] = None

    def __init__(
        self, param_name: str, item: Optional[Parameter] = None, is_required: bool = False
    ):
        super().__init__(param_name=param_name, param_type=ParamType.ARRAY, is_required=is_required)
        self.item = item or None


@dataclass
class PropertyParameter(Parameter):
    """Parameter representing an object with named properties."""

    properties: dict[str, Parameter] = field(default_factory=dict)

    def __init__(
        self,
        param_name: str,
        properties: dict[str, Parameter] | None = None,
        is_required: bool = False,
    ):
        super().__init__(
            param_name=param_name, param_type=ParamType.OBJECT, is_required=is_required
        )
        self.properties = properties or {}


# ===== Parameter Builder =====
_TYPE_MAP = {
    "String": ParamType.STRING,
    "Int": ParamType.INTEGER,
    "Number": ParamType.NUMBER,
    "Uuid": ParamType.UUID,
    "DateTime": ParamType.DATETIME,
    "Date": ParamType.DATE,
    "Bool": ParamType.BOOLEAN,
    "Object": ParamType.OBJECT,
}


def build_parameter_array(struct: Any, param_name: str = "") -> ArrayParameter:
    assert len(struct) >= 2, "Array parameter must have at least 2 elements"
    item = None
    is_required = False
    if len(struct) == 3 and isinstance(struct[2], bool):
        item = struct[1]
        is_required = struct[2]
    else:
        # tolerate legacy forms like ["Array", item1, item2, ...] or ["Array", ..., is_required]
        if isinstance(struct[-1], bool):
            is_required = struct[-1]
            items = struct[1:-1]
        else:
            items = struct[1:]
        if len(items) == 1:
            item = items[0]
        else:
            item = _merge_array_items(items)
    array_item: Optional[Parameter] = None
    if isinstance(item, dict):
        array_item = PropertyParameter(
            param_name, {k: build_parameter(v, k) for k, v in item.items()}
        )
    else:
        array_item = build_parameter(item, param_name)
    assert array_item is not None, "Array item is None"
    return ArrayParameter(param_name, item=array_item, is_required=is_required)


def _merge_array_items(items: list[Any]) -> Any:
    if not items:
        return ["String", [], [], False]
    if len(items) == 1:
        return items[0]
    first = items[0]
    if isinstance(first, dict):
        merged: dict[str, Any] = {}
        for item in items:
            if isinstance(item, dict):
                merged.update(item)
        return merged or first
    if isinstance(first, list) and first:
        item_type = first[0]
        if item_type in ("Array", "Property"):
            return first
        examples: list[Any] = []
        defaults: list[Any] = []
        item_required = False
        for item in items:
            if not (isinstance(item, list) and item and item[0] == item_type):
                continue
            example = item[1] if len(item) > 1 else []
            default = item[2] if len(item) > 2 else []
            if not isinstance(example, list):
                example = [example]
            if not isinstance(default, list):
                default = [default]
            examples.extend(example)
            defaults.extend(default)
            if len(item) > 3 and isinstance(item[3], bool):
                item_required = item_required or item[3]
        return [
            item_type,
            _dedupe(examples),
            _dedupe(defaults),
            item_required,
        ]
    return first


def _dedupe(values: list[Any]) -> list[Any]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def build_parameter_object(struct: Any, param_name: str = "") -> PropertyParameter:
    assert len(struct) == 3, "Object parameter must have 3 elements"
    assert isinstance(struct[2], bool), "Object parameter must have a boolean is_required"
    is_required = struct[2]
    content = struct[1] if len(struct) > 1 else {}
    assert isinstance(content, dict), "Content is not a dict"
    return PropertyParameter(
        param_name,
        properties={k: build_parameter(v, k) for k, v in content.items()},
        is_required=is_required,
    )


def build_parameter(struct: Any, param_name: str = "") -> Parameter:
    """Recursively convert a legacy parameter structure into Parameter objects."""
    # if isinstance(struct, list):
    assert isinstance(struct, list), "Parameter must be a list"
    if not struct:
        return BasicParameter(param_name, ParamType.STRING, [], [])
    param_type = struct[0]
    if param_type == "Array":
        return build_parameter_array(struct, param_name)
    if param_type == "Property":
        print(f"Building property parameter: {struct}")
        return build_parameter_object(struct, param_name)

    example = struct[1] if len(struct) > 1 else []
    default = struct[2] if len(struct) > 2 else []
    is_required = struct[3] if len(struct) > 3 else False

    mapped_type = _TYPE_MAP.get(param_type)
    assert mapped_type is not None, "Invalid parameter type"

    if not isinstance(example, list):
        example = [example]
    if not isinstance(default, list):
        default = [default]
    return BasicParameter(param_name, mapped_type, example, default, is_required)
