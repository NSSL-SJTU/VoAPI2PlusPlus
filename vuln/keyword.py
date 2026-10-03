from dataclasses import dataclass
from typing import Mapping, List
from vuln.types import VulnType


@dataclass(frozen=True)
class KeywordConfig:
    path_keywords: Mapping[VulnType, list[str]]
    param_keywords: Mapping[VulnType, list[str]]

    def check_path(self, path: str, vuln_type: VulnType) -> bool:
        return any(keyword in path.lower() for keyword in self.path_keywords[vuln_type])
    
    def check_param(self, param: str, vuln_type: VulnType) -> bool:
        return any(keyword in param.lower() for keyword in self.param_keywords[vuln_type])


APIPathKeywords = {
    VulnType.SSRF: [
        "host",
        "link",
        "proxy",
        "fetch",
        "redirect",
        "callback",
        "hook",
        "img",
        "image",
        "connect",
    ],
    VulnType.UNRESTRICTED_UPLOAD: [
        "upload",
        "import",
        "file",
        "pic",
        "image",
        "img",
        "content",
        "page",
        "avatar",
        "attach",
        "submit",
        "post",
    ],
    VulnType.PATH_TRAVERSAL: ["download", "export", "fetch", "file", "path", "category"],
    VulnType.COMMAND_INJECTION: [
        "set",
        "command",
        "cmd",
        "conf",
        "cfg",
        "rpc",
        "exec",
        "diagnose",
        "ping",
        "system",
        "ip",
        "nslookup",
    ],
    VulnType.SQLi: [
        "sql",
        "database",
        "db",
        "query",
        "list",
        "search",
        "order",
        "select",
        "table",
        "column",
        "row",
        "sort",
    ],
    VulnType.XSS: [
        "name",
        "content",
        "edit",
        "desc",
        "title",
        "view",
        "html",
        "link",
        "display",
        "code",
        "text",
        "tab",
        "comment",
        "tag",
        "note",
    ],
}

APIParamKeywords = {
    VulnType.SSRF: [
        "url",
        "uri",
        "host",
        "endpoint",
        "path",
        "href",
        "link",
        "proxy",
        "client",
        "remote",
        "fetch",
        "dest",
        "redirect",
        "site",
        "callback",
        "hook",
        "img",
        "image",
        "access",
        "domain",
        "agent",
        "ping",
    ],
    VulnType.UNRESTRICTED_UPLOAD: [
        "upload",
        "file",
        "path",
        "category",
        "dir",
        "pic",
        "image",
        "img",
    ],
    VulnType.PATH_TRAVERSAL: ["file", "path", "category"],
    VulnType.COMMAND_INJECTION: [
        "set",
        "command",
        "cmd",
        "exec",
        "ping",
        "ip",
        "nslookup",
    ],
    VulnType.SQLi: ["sql", "query", "id", "select", "field", "sort"],
    VulnType.XSS: [
        "name",
        "content",
        "desc",
        "title",
        "view",
        "html",
        "code",
        "text",
        "tab",
        "comment",
        "tag",
        "note",
    ],
}

APIKeywordConfig = KeywordConfig(
    path_keywords=APIPathKeywords,
    param_keywords=APIParamKeywords,
)
