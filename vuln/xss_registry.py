import secrets
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class XSSTestRecord:
    xss_id: str
    api_method: str
    api_url: str
    param_name: str
    attack_payload: str


class XSSRegistry:
    def __init__(self):
        self._records: dict[str, XSSTestRecord] = {}

    def register(
        self,
        api_method: str,
        api_url: str,
        param_name: str,
        attack_payload: str,
    ) -> str:
        xss_id = f"xss_{secrets.token_hex(4)}"
        while xss_id in self._records:
            xss_id = f"xss_{secrets.token_hex(4)}"
        self._records[xss_id] = XSSTestRecord(
            xss_id=xss_id,
            api_method=api_method,
            api_url=api_url,
            param_name=param_name,
            attack_payload=attack_payload,
        )
        return xss_id

    def lookup(self, xss_id: str) -> Optional[XSSTestRecord]:
        return self._records.get(xss_id)

    def find_id_in_text(self, text: str) -> Optional[str]:
        for xss_id in self._records:
            if xss_id in text:
                return xss_id
        return None

    def all_ids(self) -> list[str]:
        return list(self._records.keys())

    def __len__(self) -> int:
        return len(self._records)
