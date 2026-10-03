from enum import Enum, auto
from typing import Optional


class VulnType(Enum):
    SSRF = auto()
    UNRESTRICTED_UPLOAD = auto()
    PATH_TRAVERSAL = auto()
    COMMAND_INJECTION = auto()
    SQLi = auto()
    XSS = auto()


_VULN_TYPE_ALIASES: dict[str, VulnType] = {
    "ssrf": VulnType.SSRF,
    "upload": VulnType.UNRESTRICTED_UPLOAD,
    "unrestrictedupload": VulnType.UNRESTRICTED_UPLOAD,
    "fileupload": VulnType.UNRESTRICTED_UPLOAD,
    "path": VulnType.PATH_TRAVERSAL,
    "pathtraversal": VulnType.PATH_TRAVERSAL,
    "lfi": VulnType.PATH_TRAVERSAL,
    "cmd": VulnType.COMMAND_INJECTION,
    "cmdi": VulnType.COMMAND_INJECTION,
    "command": VulnType.COMMAND_INJECTION,
    "commandinjection": VulnType.COMMAND_INJECTION,
    "sql": VulnType.SQLi,
    "sqli": VulnType.SQLi,
    "sqlinjection": VulnType.SQLi,
    "xss": VulnType.XSS,
}


def parse_vuln_type_filter(raw: Optional[str]) -> Optional[set[VulnType]]:
    if raw is None or not raw.strip():
        return None

    out: set[VulnType] = set()
    unknown: list[str] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        normalized = _normalize_vuln_type_token(token)
        if normalized == "all":
            return None
        vuln_type = _VULN_TYPE_ALIASES.get(normalized)
        if vuln_type is None:
            unknown.append(token)
            continue
        out.add(vuln_type)

    if unknown:
        supported = ", ".join(supported_vuln_type_filter_names())
        raise ValueError(
            f"Unknown vulnerability type(s): {', '.join(unknown)}. "
            f"Supported values: {supported}"
        )
    return out or None


def supported_vuln_type_filter_names() -> list[str]:
    return [
        "ssrf",
        "upload",
        "path_traversal",
        "command_injection",
        "sqli",
        "xss",
    ]


def _normalize_vuln_type_token(token: str) -> str:
    return token.strip().lower().replace("_", "").replace("-", "").replace(" ", "")
