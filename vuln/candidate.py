from dataclasses import dataclass
from pyclbr import Class
from typing import Dict, List, Iterable, Mapping, Optional
from models.api_model import APIModel
from models.types import ParamType
from models.ref import FieldRef, ParamLocation
from vuln.types import VulnType
from matching.extractor import FieldExtractor
from vuln.keyword import KeywordConfig

import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CandidateAPI:
    api: APIModel
    test_types: dict[VulnType, list[FieldRef]]

    def __repr__(self):
        test_types_str = ", ".join(
            [f"{k}: {', '.join([f.name for f in v])}" for k, v in self.test_types.items()]
        )
        return f"CandidateAPI(api={self.api.simple_repr()}, test_types={test_types_str})"


def filter_candidate_vuln_types(
    candidates: list[CandidateAPI],
    allowed: set[VulnType],
) -> list[CandidateAPI]:
    filtered: list[CandidateAPI] = []
    for cand in candidates:
        test_types = {
            vuln_type: refs
            for vuln_type, refs in cand.test_types.items()
            if vuln_type in allowed
        }
        if test_types:
            filtered.append(CandidateAPI(cand.api, test_types))
    return filtered


class CandidateExtractor:
    extractor: FieldExtractor
    keyword_config: KeywordConfig

    def __init__(self, extractor: FieldExtractor, keyword_config: KeywordConfig):
        self.extractor = extractor
        self.keyword_config = keyword_config

    def log_candidates(self, candidates: list[CandidateAPI]):
        logger.info("==================Candidates==================")
        for candidate in candidates:
            logger.info(f"Candidate: {candidate.api.api_url} {candidate.api.api_method}")
            for vuln_type in candidate.test_types:
                logger.info(f"Vuln Type: {vuln_type}")
                for field in candidate.test_types[vuln_type]:
                    logger.info(f"Field: {field.name}")

    def extract(self, api_list: list[APIModel]) -> list[CandidateAPI]:
        out: list[CandidateAPI] = []
        for api in api_list:
            logger.info(f"Extract API: {api.api_url} {api.api_method}")
            cand = self.extract_one(api)
            if cand:
                out.append(cand)
        # self.log_candidates(out)
        return out

    def extract_full(self, api_list: list[APIModel]) -> list[CandidateAPI]:
        out: list[CandidateAPI] = []
        for api in api_list:
            logger.info(f"Extract API (full scan): {api.api_url} {api.api_method}")
            cand = self.extract_full_one(api)
            if cand:
                out.append(cand)
        return out

    def extract_one(self, api: APIModel) -> Optional[CandidateAPI]:
        fields = self.extractor.request_fields(api, include_basic_array_items=True)
        test_types: dict[VulnType, list[FieldRef]] = {}
        string_fields: list[FieldRef] = [
            field
            for field in fields
            if field.ptype == ParamType.STRING and field.location != ParamLocation.PATH
        ]
        if string_fields:
            for vuln_type in VulnType:
                if vuln_type == VulnType.UNRESTRICTED_UPLOAD:
                    continue
                candidate_fields = self._fields_for_vuln(string_fields, vuln_type)
                hits = [
                    f
                    for f in candidate_fields
                    if self.keyword_config.check_param(f.name, vuln_type)
                ]
                if hits:
                    test_types[vuln_type] = hits
                    continue
                if self.keyword_config.check_path(api.api_url, vuln_type):
                    test_types[vuln_type] = list(candidate_fields)

        # For upload API, there must be a file field.
        if VulnType.UNRESTRICTED_UPLOAD in VulnType:
            
            file_fields = [f for f in fields if f.ptype == ParamType.FILE]
            if file_fields:
                test_types[VulnType.UNRESTRICTED_UPLOAD] = file_fields

        return CandidateAPI(api, test_types) if test_types else None

    def extract_full_one(self, api: APIModel) -> Optional[CandidateAPI]:
        fields = self.extractor.request_fields(api, include_basic_array_items=True)
        string_fields: list[FieldRef] = [
            field
            for field in fields
        ]
        file_fields = [f for f in fields if f.ptype == ParamType.FILE]

        test_types: dict[VulnType, list[FieldRef]] = {}
        if string_fields:
            for vuln_type in VulnType:
                if vuln_type == VulnType.UNRESTRICTED_UPLOAD:
                    continue
                candidate_fields = self._fields_for_vuln(string_fields, vuln_type)
                if candidate_fields:
                    test_types[vuln_type] = candidate_fields
        if file_fields:
            test_types[VulnType.UNRESTRICTED_UPLOAD] = list(file_fields)

        return CandidateAPI(api, test_types) if test_types else None

    def _fields_for_vuln(
        self,
        fields: list[FieldRef],
        vuln_type: VulnType,
    ) -> list[FieldRef]:
        if vuln_type != VulnType.XSS:
            return list(fields)
        return [
            field
            for field in fields
            if field.location in {ParamLocation.QUERY, ParamLocation.BODY}
        ]
