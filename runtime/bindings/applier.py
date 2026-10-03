# runtime/bindings/applier.py

from dataclasses import dataclass
from typing import Iterable
from models.types import ValueSource, ParamValuePriority
from models.parameter import BasicParameter, ArrayParameter
from matching.binding import Binding
from matching.extractor import FieldExtractor
import logging

logger = logging.getLogger(__name__)

@dataclass
class BindingApplier:
    extractor: FieldExtractor

    def apply_to_consumer(self, bindings: Iterable[Binding]) -> None:
        for b in bindings:
            target_param = b.consumer.param
            if not isinstance(target_param, BasicParameter):
                logger.warning(f"Invalid target parameter: {b.consumer}, {type(target_param)}")
                continue

            cur_src = target_param.value_source
            new_src = ValueSource.VoAPI_PRODUCER
            if ParamValuePriority.get(new_src, 0) >= ParamValuePriority.get(cur_src, 0):
                producer_param = b.producer.param
                if isinstance(producer_param, BasicParameter):
                    if producer_param.value is None or producer_param.value == "":
                        logger.warning(f"Producer parameter value is None or empty: {b.producer.name}")
                        continue
                    target_param.value = producer_param.value
                    target_param.value_source = ValueSource.VoAPI_CONSUMER
                elif isinstance(producer_param, ArrayParameter):
                    item = producer_param.item
                    if not isinstance(item, BasicParameter) or not item.value:
                        logger.warning(f"Array item is not BasicParameter or value is None: {b.producer}")
                        continue
                    target_param.value = item.value
                    target_param.value_source = ValueSource.VoAPI_CONSUMER
                else:
                    logger.warning(f"Producer parameter is not BasicParameter: {b.producer}")
                    continue
