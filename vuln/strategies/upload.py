from dataclasses import dataclass
from vuln.strategy import VulnStrategy
from vuln.types import VulnType
from vuln.recorder import VulnCase
from typing import ClassVar, Any, Optional
from models.api_model import APIModel
from models.ref import FieldRef
import mimetypes
import os
from pathlib import Path
import random
import string


@dataclass
class UploadStrategy(VulnStrategy):
    vuln_type: ClassVar[VulnType] = VulnType.UNRESTRICTED_UPLOAD
    file_dir: str = "./APIUploadPayloads/"

    def randomize_file(self, file_name: str) -> str:
        # add random string to file name
        random_string = "".join(random.choices(string.ascii_letters + string.digits, k=4))
        base = os.path.basename((file_name or "").strip().rstrip("/\\"))
        if not base:
            base = "upload.bin"
        file_name_pre, file_name_post = os.path.splitext(base)
        if not file_name_pre:
            file_name_pre = "upload"
        if not file_name_post:
            file_name_post = ".bin"
        return f"{file_name_pre}_{random_string}{file_name_post}"

    def _safe_payload_file(self, attack_payload: str) -> Optional[Path]:
        root = Path(self.file_dir).resolve()
        candidate = (root / attack_payload).resolve()
        try:
            if os.path.commonpath([str(root), str(candidate)]) != str(root):
                return None
        except ValueError:
            return None
        if candidate.is_file():
            return candidate
        return None

    def _fallback_payload_file(self) -> Optional[Path]:
        root = Path(self.file_dir)
        if not root.exists():
            return None
        files = sorted(p for p in root.rglob("*") if p.is_file())
        return files[0] if files else None

    def _build_files(
        self, test_field_ref: FieldRef, attack_payload: str
    ) -> Optional[dict[str, Any]]:
        file_path = self._safe_payload_file(attack_payload) or self._fallback_payload_file()
        if file_path is None:
            return None
        with open(file_path, "rb") as fp:
            payload_bytes = fp.read()
        file_name = self.randomize_file(file_path.name)
        # requests only emits a per-part Content-Type when the tuple has three
        # elements. Servers that read the part's content type answer 500 without
        # it, which makes every upload look non-vulnerable.
        content_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        return {
            test_field_ref.name: (
                file_name,
                payload_bytes,
                content_type,
            )
        }
    
    def has_vuln(self, vuln_case: VulnCase) -> bool:
        vuln_path = self.recorder.get_vuln_path(vuln_case)
        if vuln_path.exists():
            return True
        resp = vuln_case.response
        # method = vuln_case.target_field.api.api_method
        return resp.ok
