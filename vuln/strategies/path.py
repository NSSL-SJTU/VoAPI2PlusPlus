from dataclasses import dataclass
from vuln.strategy import VulnStrategy
from vuln.types import VulnType
from runtime.http.client import HTTPResponse
from vuln.recorder import VulnCase
from typing import ClassVar


UNIX_PASSWD_CHARS = "root:"
WINI_INI_CHARS = "; for 16-bit"

@dataclass
class PathStrategy(VulnStrategy):
    vuln_type: ClassVar[VulnType] = VulnType.PATH_TRAVERSAL
    
    def has_sensitive_info(self, response: HTTPResponse) -> bool:
        return WINI_INI_CHARS in response.text or UNIX_PASSWD_CHARS in response.text

    def has_vuln(self, vuln_case: VulnCase) -> bool:
        response = vuln_case.response
        return response.ok and self.has_sensitive_info(response)

    