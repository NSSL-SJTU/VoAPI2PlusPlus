from dataclasses import dataclass
from models.ref import FieldRef
from vuln.strategy import VulnStrategy
from vuln.types import VulnType
from vuln.recorder import VulnCase
from typing import ClassVar

@dataclass
class SSRFStrategy(VulnStrategy):
    vuln_type: ClassVar[VulnType] = VulnType.SSRF
    need_trigger: bool = False
    # The callback can arrive after the request returns.
    defers_evidence: ClassVar[bool] = True
    
    def has_vuln(self, vuln_case: VulnCase) -> bool:
        return self.recorder.has_evidence(vuln_case)

    def format_attack_payload(self, attack_payload: str, test_field_ref: FieldRef) -> str:
        api = test_field_ref.api
        api_url = api.api_url
        if not api_url.endswith("/"):
            api_url += "/"
        param_name = test_field_ref.name
        if "{" in attack_payload and "}" in attack_payload:
            try:
                return attack_payload.format(api_url + param_name)
            except Exception:
                return attack_payload
        return attack_payload
