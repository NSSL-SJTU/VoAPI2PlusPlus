# matching/binding.py

from dataclasses import dataclass
from enum import Enum
from models.ref import FieldRef

class MatchKind(str, Enum):
    EXACT = "exact"
    VARIANT = "variant"

@dataclass(frozen=True)
class ProducerHit:
    producer_field: FieldRef
    kind: MatchKind
    rule_passed: bool
    method_priority: int
    url_length: int
    
@dataclass(frozen=True)
class Binding:
    consumer: FieldRef
    producer: FieldRef
    kind: MatchKind
    
    def __repr__(self):
        return f"Binding({self.producer} → {self.consumer}, {self.kind.value})"