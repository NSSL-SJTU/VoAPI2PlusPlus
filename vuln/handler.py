from dataclasses import dataclass
from vuln.types import VulnType
from vuln.strategy import VulnStrategy
from typing import Mapping


@dataclass
class VulnHandler:
    strategy_map: Mapping[VulnType, VulnStrategy]

    def get_strategy(self, vuln_type: VulnType) -> VulnStrategy:
        return self.strategy_map[vuln_type]