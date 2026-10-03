# runtime/vuln/recorder.py

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
from models.ref import FieldRef
from vuln.types import VulnType
from runtime.http.client import HTTPResponse


@dataclass
class VulnCase:
    target_field: FieldRef
    kind: VulnType
    attack_payload: str
    response: HTTPResponse

    def __repr__(self) -> str:
        lines = [
            f"API Vul Type: {self.kind.name}",
            f"Vul API Url: {self.target_field.api.api_url}",
            f"Vul API Method: {self.target_field.api.api_method}",
            f"API Vul Param: {self.target_field.name}",
            f"API Test Payload: {self.attack_payload}",
        ]
        return "\n".join(lines)


@dataclass
class VulnRecorder:
    root: Path

    # Separators an appended callback segment can start with, once
    # http_verification.py has rewritten "/" to "!" and "?" to "@".
    _SUFFIX_BOUNDARIES: ClassVar[tuple[str, ...]] = ("!", "@")

    def get_vuln_path(self, case: VulnCase) -> Path:
        d = self.root / case.kind.name.lower()
        d.mkdir(parents=True, exist_ok=True)
        fname = self._safe_name(case.target_field)
        return d / fname

    def has_evidence(self, case: VulnCase) -> bool:
        """Whether an out-of-band callback for this case was recorded.

        The callback target may append extra segments to the URL we planted --
        a git client asks for ``<payload>/info/refs?service=git-upload-pack``.
        http_verification.py names the evidence file after the whole callback
        path, so the file carries a suffix after the stem we expect. Match those
        too, but only on a separator boundary so that ``/x`` never claims the
        callback recorded for a sibling ``/x2``.
        """
        expected = self.get_vuln_path(case)
        if expected.exists():
            return True
        stem = expected.name.removesuffix(".txt")
        prefixes = tuple(stem + boundary for boundary in self._SUFFIX_BOUNDARIES)
        return any(
            candidate.name.startswith(prefixes)
            for candidate in expected.parent.glob("*.txt")
        )

    def record(self, case: VulnCase):
        vuln_path = self.get_vuln_path(case)
        with vuln_path.open("a") as f:
            f.write(f"{case}\n")

    def _safe_name(self, target_field: FieldRef) -> str:
        target = target_field.api
        url = target.api_url.replace("/", "!")
        return f"{url}!{target_field.name}.txt"
