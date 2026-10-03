# matching/rules.py
from dataclasses import dataclass
from typing import Dict, Set
from models.api_model import APIModel
from models.types import APIMethod


@dataclass(frozen=True)
class ProducerRules:
    # We can set no_get_producer to True to exclude GET producers
    allowed_methods: set[APIMethod]  # {"POST","PUT","GET"...}
    method_priority: dict[APIMethod, int]  # {"POST":4,"PUT":3,"GET":2,...}

    def is_valid(self, consumer: APIModel, producer: APIModel) -> bool:
        if producer.api_method not in self.allowed_methods:
            return False
        if not self._resource_included(consumer.api_url, producer.api_url):
            return False
        if consumer.api_url == producer.api_url:
            producer_method_priority = self.method_priority.get(producer.api_method, -1)
            consumer_method_priority = self.method_priority.get(consumer.api_method, -1)
            if producer_method_priority < consumer_method_priority:
                return False
        return True

    # ---- helpers ----
    def _segments(self, url: str) -> list[str]:
        # Ignore common base prefixes so they don't block producer matching
        ignore = {"api", "v1"}
        segments = [s.lower() for s in url.split("/") if s]
        return [s for s in segments if s not in ignore]

    def _resource_included(self, consumer_url: str, producer_url: str) -> bool:
        c = set(self._segments(consumer_url))
        return all(seg in c for seg in self._segments(producer_url))
