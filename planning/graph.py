# planning/graph.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from models.api_model import APIModel
from matching.binding import Binding

@dataclass(frozen=True)
class DependencyEdge:
    producer: APIModel
    consumer: APIModel
    bindings: tuple[Binding, ...]

    
    def __repr__(self):
        bindings_str = f"[{len(self.bindings)} bindings]" if self.bindings else "[no bindings]"
        return f"DependencyEdge({self.producer.simple_repr()} → {self.consumer.simple_repr()}, {bindings_str})"
    
    def detailed_repr(self):
        lines = [
            f"DependencyEdge:",
            f"  Producer: {self.producer.simple_repr()}",
            f"  Consumer: {self.consumer.simple_repr()}",
            f"  Bindings ({len(self.bindings)}):"
        ]
        
        if self.bindings:
            for i, binding in enumerate(self.bindings, 1):
                lines.append(f"    {i}. {binding}")
        else:
            lines.append("    (no bindings)")
        
        return "\n".join(lines)
    
    def compact_repr(self):
        producer_short = f"{self.producer.api_method.value} {self.producer.api_url}"
        consumer_short = f"{self.consumer.api_method.value} {self.consumer.api_url}"
        return f"{producer_short} → {consumer_short} ({len(self.bindings)})"

@dataclass(frozen=True)
class SequencePlan:
    ordered_apis: tuple[APIModel, ...]
    edges: tuple[DependencyEdge, ...]
    
    def __repr__(self):
        return f"SequencePlan({len(self.ordered_apis)} APIs, {len(self.edges)} edges)"
    
    def detailed_repr(self):
        lines = [
            f"SequencePlan:",
            f"  APIs ({len(self.ordered_apis)}):"
        ]
        
        for i, api in enumerate(self.ordered_apis, 1):
            lines.append(f"    {i}. {api.simple_repr()}")
        
        lines.append(f"  Dependencies ({len(self.edges)}):")
        if self.edges:
            for i, edge in enumerate(self.edges, 1):
                lines.append(f"    {i}. {edge.compact_repr()}")
        else:
            lines.append("    (no dependencies)")
        
        return "\n".join(lines)

    def remove_target_api(self) -> SequencePlan:
        assert len(self.ordered_apis) >= 1
        target_api = self.ordered_apis[-1]
        assert not any(target_api == e.producer for e in self.edges)
        return SequencePlan(
            ordered_apis=self.ordered_apis[:-1],
            edges=self.edges
        )
