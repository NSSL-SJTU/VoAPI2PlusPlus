from dataclasses import dataclass
from typing import ClassVar

from vuln.strategy import VulnStrategy
from vuln.types import VulnType
from vuln.recorder import VulnCase

@dataclass
class CommandiStrategy(VulnStrategy):

    vuln_type: ClassVar[VulnType] = VulnType.COMMAND_INJECTION
    need_trigger: bool = False
    # The callback can arrive after the request returns.
    defers_evidence: ClassVar[bool] = True
    
    def has_vuln(self, vuln_case: VulnCase) -> bool:
        vuln_path = self.recorder.get_vuln_path(vuln_case)
        if vuln_path.exists():
            return True
        return False