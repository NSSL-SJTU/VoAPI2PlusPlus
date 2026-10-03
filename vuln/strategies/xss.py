import logging
from dataclasses import dataclass, field
from typing import ClassVar, Optional
from models.ref import FieldRef
from models.types import APIMethod
from vuln.strategy import VulnStrategy
from vuln.types import VulnType
from vuln.recorder import VulnCase
from vuln.xss_registry import XSSRegistry


logger = logging.getLogger(__name__)

XSS_ID_PLACEHOLDER = "{xss_id}"


@dataclass
class XSSStrategy(VulnStrategy):
    vuln_type: ClassVar[VulnType] = VulnType.XSS
    need_trigger: bool = False
    xss_registry: Optional[XSSRegistry] = None

    def has_vuln(self, vuln_case: VulnCase) -> bool:
        vuln_path = self.recorder.get_vuln_path(vuln_case)
        if vuln_path.exists():
            return True
        return False

    def format_attack_payload(self, attack_payload: str, test_field_ref: FieldRef) -> str:
        api = test_field_ref.api
        api_url = api.api_url
        if not api_url.endswith("/"):
            api_url += "/"
        param_name = test_field_ref.name

        if XSS_ID_PLACEHOLDER in attack_payload and self.xss_registry is not None:
            xss_id = self.xss_registry.register(
                api_method=api.api_method.value,
                api_url=api.api_url,
                param_name=param_name,
                attack_payload=attack_payload,
            )
            attack_payload = attack_payload.replace(XSS_ID_PLACEHOLDER, xss_id)
            logger.debug("XSS payload with ID %s for %s %s param=%s",
                         xss_id, api.api_method.value, api.api_url, param_name)

        if "{" in attack_payload and "}" in attack_payload:
            try:
                return attack_payload.format(api_url + param_name)
            except Exception:
                return attack_payload
        return attack_payload
