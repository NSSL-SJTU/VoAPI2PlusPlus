
from dataclasses import dataclass
from typing import Dict, List
from models.api_model import APIModel

@dataclass(frozen=True)
class ApiComparator:
    method_priority:dict[str, int]

    def sort(self, apis: list[APIModel]) -> list[APIModel]:
        return sorted(apis, key=self._key)

    def _key(self, api: APIModel):
        return (len(api.api_url), self.method_priority.get(api.api_method, -1))