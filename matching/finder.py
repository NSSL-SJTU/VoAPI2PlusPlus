# matching/finder.py
from dataclasses import dataclass
from typing import Optional
from models.api_model import APIModel
from models.ref import FieldRef
from models.types import ParamLocation
from matching.extractor import FieldExtractor
from matching.matcher import NameMatcher
from matching.rules import ProducerRules
from matching.binding import ProducerHit, Binding, MatchKind
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProducerFinder:
    extractor: FieldExtractor
    rules: ProducerRules

    def find_for_consumer_field(
        self,
        consumer_field: FieldRef,
        candidate_apis: list[APIModel],
        name_matcher: NameMatcher,
    ) -> Optional[Binding]:
        hits: list[ProducerHit] = []

        logger.debug(f"Finding producer for consumer field: {consumer_field.name} (type: {consumer_field.ptype}) in API {consumer_field.api.api_method} {consumer_field.api.api_url}")
        expanded = name_matcher.expand(consumer_field.name)
        logger.debug(f"Consumer field '{consumer_field.name}' expanded to: {expanded}")

        consumer_url = consumer_field.api.api_url
        # remove the same url from candidate_apis
        candidate_apis = [api for api in candidate_apis if api.api_url != consumer_url]

        for api in candidate_apis:
            if not self.rules.is_valid(consumer_field.api, api):
                logger.debug(f"  Skipping {api.api_method} {api.api_url}: failed producer rule validation")
                continue
            for producer_field in self.extractor.response_fields(api):
                if producer_field.ptype != consumer_field.ptype:
                    continue
                if self._reject_same_prefix_path_producer(consumer_field, producer_field):
                    logger.debug(
                        "  Skipping %s %s for field '%s': rejected by path-prefix overlap rule",
                        api.api_method,
                        api.api_url,
                        consumer_field.name,
                    )
                    continue

                logger.debug(f"  Checking producer: {producer_field.name} (type: {producer_field.ptype}) from {api.api_method} {api.api_url}")

                if name_matcher.exact_match(producer_field.name, consumer_field.name):
                    logger.debug(f"    ✓ EXACT match: {producer_field.name} matches {consumer_field.name}")
                    hits.append(self._hit(api, producer_field, MatchKind.EXACT))
                else:
                    matched = False
                    for v in name_matcher.expand(consumer_field.name):
                        if name_matcher.exact_match(producer_field.name, v):
                            logger.debug(f"    ✓ VARIANT match: {producer_field.name} matches variant '{v}' of {consumer_field.name}")
                            hits.append(self._hit(api, producer_field, MatchKind.VARIANT))
                            matched = True
                            break
                    if not matched:
                        logger.debug(f"    ✗ No match")

        if not hits:
            logger.debug(f"No producer found for consumer field: {consumer_field.name}")
            return None

        best = self._choose_best(hits)
        logger.debug(f"Best producer selected: {best.producer_field.name} from {best.producer_field.api.api_method} {best.producer_field.api.api_url}")
        return Binding(consumer=consumer_field, producer=best.producer_field, kind=best.kind)

    # ---- helpers ----
    def _hit(self, api: APIModel, producer_field: FieldRef, kind: MatchKind) -> ProducerHit:
        mp = self.rules.method_priority
        return ProducerHit(
            producer_field=producer_field,
            kind=kind,
            rule_passed=True,
            method_priority=mp.get(api.api_method, -1),
            url_length=len(api.api_url),
        )

    def _choose_best(self, hits: list[ProducerHit]) -> ProducerHit:
        merged: dict[str, ProducerHit] = {}
        for h in hits:
            url = h.producer_field.api.api_url
            if url not in merged or h.method_priority > merged[url].method_priority:
                merged[url] = h
        return max(merged.values(), key=lambda x: x.url_length)

    def _reject_same_prefix_path_producer(
        self,
        consumer_field: FieldRef,
        producer_field: FieldRef,
    ) -> bool:
        """
        Reject same-prefix path producers for path params with the same placeholder name.

        Example:
        - consumer /XXX/{id}/YYY   -> reject producer /XXX/{id}, /XXX/{id}/111
        - consumer /XXX/{id}/YYY/{id} -> allow /XXX/{id} for the trailing {id} case
          (use the last occurrence of {id} in consumer path).
        """
        if consumer_field.location != ParamLocation.PATH:
            return False

        consumer_name = consumer_field.name.lower()
        producer_name = producer_field.name.lower()
        if consumer_name != producer_name:
            return False

        consumer_segments = self._split_url_segments(consumer_field.api.api_url)
        producer_segments = self._split_url_segments(producer_field.api.api_url)
        consumer_idx = self._last_placeholder_index(consumer_segments, consumer_name)
        if consumer_idx is None:
            return False

        for producer_idx in self._placeholder_indices(producer_segments, producer_name):
            if producer_idx != consumer_idx:
                continue
            if self._same_prefix_until(consumer_segments, producer_segments, consumer_idx):
                return True
        return False

    def _split_url_segments(self, url: str) -> list[str]:
        return [seg.strip().lower() for seg in url.split("/") if seg.strip()]

    def _placeholder_name(self, segment: str) -> Optional[str]:
        if segment.startswith("{") and segment.endswith("}") and len(segment) > 2:
            return segment[1:-1].strip().lower()
        return None

    def _last_placeholder_index(
        self,
        segments: list[str],
        placeholder_name: str,
    ) -> Optional[int]:
        for idx in range(len(segments) - 1, -1, -1):
            if self._placeholder_name(segments[idx]) == placeholder_name:
                return idx
        return None

    def _placeholder_indices(
        self,
        segments: list[str],
        placeholder_name: str,
    ) -> list[int]:
        return [
            idx
            for idx, seg in enumerate(segments)
            if self._placeholder_name(seg) == placeholder_name
        ]

    def _same_prefix_until(
        self,
        consumer_segments: list[str],
        producer_segments: list[str],
        idx: int,
    ) -> bool:
        if len(consumer_segments) <= idx or len(producer_segments) <= idx:
            return False
        return consumer_segments[: idx + 1] == producer_segments[: idx + 1]
