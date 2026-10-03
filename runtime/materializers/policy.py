# runtime/materializers/policy.py

from dataclasses import dataclass
from typing import Optional, Any
from models.parameter import Parameter, BasicParameter, ArrayParameter, PropertyParameter
from models.types import ValueSource, ParamValuePriority


@dataclass(frozen=True)
class RequestPolicy:
    open_isrequired: bool = False

    def should_emit(self, name: str, param: Parameter) -> bool:
        # not required and open_isrequired=True → skip
        return True if not self.open_isrequired else bool(param.is_required)

    def finalize_value(self, name: str, param: Parameter) -> Any:
        if isinstance(param, BasicParameter):
            return param.value
        if isinstance(param, ArrayParameter):
            return None
        if isinstance(param, PropertyParameter):
            return None
        return None


@dataclass(frozen=True)
class ResponsePolicy:
    # prioritize_by_source_rank: bool = False

    def should_write(self,
                     existing_source: Optional[ValueSource],
                     new_source: Optional[ValueSource]) -> bool:
        if existing_source is None:
            return True
        if new_source is None:
            return False

        # if not self.prioritize_by_source_rank:
        #     return existing_source != new_source

        return ParamValuePriority.get(new_source, 0) >= ParamValuePriority.get(existing_source, 0)
