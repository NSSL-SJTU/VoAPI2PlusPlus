# planning/sequence.py
from dataclasses import dataclass, field
from typing import Callable, Protocol
import logging

from models.api_model import APIModel
from models.types import APIMethod
from models.ref import FieldRef
from matching.extractor import FieldExtractor
from matching.finder import ProducerFinder
from matching.matcher import NameMatcher
from matching.binding import Binding
from matching.llm_dependency import resolve_dependencies_llm
from planning.graph import DependencyEdge, SequencePlan

logger = logging.getLogger(__name__)


class DependencyResolver(Protocol):
    def resolve(self, api: APIModel, pool: list[APIModel]) -> list[Binding]:
        ...


@dataclass
class OverrideResolver:
    base: DependencyResolver
    overrides: dict[APIModel, list[Binding]]

    def resolve(self, api: APIModel, pool: list[APIModel]) -> list[Binding]:
        if api in self.overrides:
            return self.overrides[api]
        return self.base.resolve(api, pool)


@dataclass
class LLMResolver:
    """Resolve dependencies purely with the LLM, replacing the rule-based matcher.

    Used by the ``--dep_resolver llm`` ablation, which asks whether the LLM can
    take over dependency inference entirely rather than only repairing failures.
    Results are cached per consumer because ``SequencePlanner.build`` resolves the
    same API repeatedly while walking the sequence.
    """

    llm_client: object
    model: str | None = None
    project_name: str = "Unknown"
    resolve_fn: Callable[..., list[Binding]] = resolve_dependencies_llm
    _cache: dict[APIModel, list[Binding]] = field(default_factory=dict, repr=False)

    def resolve(self, api: APIModel, pool: list[APIModel]) -> list[Binding]:
        cached = self._cache.get(api)
        if cached is not None:
            return cached
        try:
            bindings = self.resolve_fn(
                api,
                [p for p in pool if p != api],
                model=self.model,
                llm_client=self.llm_client,
                project_name=self.project_name,
                purpose="dep_resolve_upfront",
            )
        except Exception as exc:
            logger.warning(
                "LLM dependency resolution failed for %s %s: %s",
                api.api_method,
                api.api_url,
                exc,
            )
            bindings = []
        bindings = [
            b for b in bindings if b.consumer.api == api and b.producer.api != api
        ]
        logger.debug(
            "LLMResolver: %s %s -> %d binding(s)",
            api.api_method,
            api.api_url,
            len(bindings),
        )
        self._cache[api] = bindings
        return bindings


@dataclass
class UnionResolver:
    """Rule-based bindings plus any additional ones the LLM proposes."""

    rule: DependencyResolver
    llm: DependencyResolver

    def resolve(self, api: APIModel, pool: list[APIModel]) -> list[Binding]:
        merged = list(self.rule.resolve(api, pool))
        seen = {_binding_key(b) for b in merged}
        for b in self.llm.resolve(api, pool):
            key = _binding_key(b)
            if key in seen:
                continue
            merged.append(b)
            seen.add(key)
        return merged


def _binding_key(binding: Binding) -> tuple:
    return (
        binding.consumer.location,
        binding.consumer.path.segments,
        binding.producer.api,
        binding.producer.location,
        binding.producer.path.segments,
    )


def _resource_tail(url: str) -> tuple:
    """The collection and item segments an endpoint addresses, ignoring prefix.

    /baskets/{name} and /api/baskets/{name} are the same resource reached two
    ways, and Rbaskets exposes every basket operation under both.
    """
    segs = [x for x in url.split("/") if x]
    return tuple(segs[-2:]) if len(segs) >= 2 else tuple(segs)


def _is_self_read(consumer: APIModel, binding: Binding) -> bool:
    """A create must not take its own identifier from a read of the same resource.

    A POST whose path ends in a placeholder lets the CLIENT choose the identifier
    -- POST /baskets/{name}, PUT-style S3 keys -- so the usual "the create returns
    an id, the read consumes it" direction is inverted, and binding it to a read
    of the same resource is backwards twice over: the value has to be fresh, and
    the edge forces the read to run first.

    Measured on Rbaskets, which exposes each basket operation under two prefixes
    and so had each create depending on the OTHER alias's read. The consequences
    ran three deep: GET /api/baskets/{name} was ordered before any basket existed,
    answered 404, was recorded as a failed producer, and
    POST /baskets/{name} was skipped without ever being sent. Two of twenty
    endpoints, from one edge that should not exist.

    Deliberately narrow. Across all ten benchmarks this refuses 10 of 2497
    bindings, all of them Rbaskets': the consumer must be a POST, its path must
    end in a placeholder, and the producer must be a read of the same collection
    and item. PUT is excluded because updating an existing resource genuinely does
    need a real identifier.
    """
    if consumer.api_method != APIMethod.POST:
        return False
    segs = [x for x in consumer.api_url.split("/") if x]
    if not segs or not (segs[-1].startswith("{") and segs[-1].endswith("}")):
        return False
    producer = binding.producer.api
    if producer.api_method not in (APIMethod.GET, APIMethod.HEAD):
        return False
    return _resource_tail(producer.api_url) == _resource_tail(consumer.api_url)


@dataclass
class RuleBasedResolver:
    extractor: FieldExtractor
    finder: ProducerFinder
    name_matcher: NameMatcher

    def resolve(self, api: APIModel, pool: list[APIModel]) -> list[Binding]:
        bindings: list[Binding] = []
        consumer_fields = self._consumer_fields(api)
        logger.debug(f"Resolving dependencies for {api.api_method} {api.api_url}, consumer fields: {[f.name for f in consumer_fields]}")
        for cf in consumer_fields:
            b = self.finder.find_for_consumer_field(cf, pool, self.name_matcher)
            if b and _is_self_read(api, b):
                logger.debug(
                    "  Refusing self-read binding: %s <- %s %s",
                    cf.name, b.producer.api.api_method, b.producer.api.api_url,
                )
                continue
            if b:
                bindings.append(b)
                logger.debug(f"  Binding found: {cf.name} <- {b.producer.name} from {b.producer.api.api_method} {b.producer.api.api_url}")
            else:
                logger.debug(f"  No binding found for: {cf.name}")
        return bindings

    def _consumer_fields(self, api: APIModel) -> list[FieldRef]:
        return self.extractor.request_fields(api)


class SequencePlanner:
    def __init__(
        self,
        extractor: FieldExtractor | None = None,
        finder: ProducerFinder | None = None,
        name_matcher: NameMatcher | None = None,
        resolver: DependencyResolver | None = None,
    ):
        if resolver is None:
            if not extractor or not finder or not name_matcher:
                raise ValueError("extractor, finder, and name_matcher are required")
            resolver = RuleBasedResolver(extractor, finder, name_matcher)
        self.resolver = resolver

    def build(self, consumer_api: APIModel, producer_pool: list[APIModel]) -> SequencePlan:
        logger.debug(f"Building sequence plan for target API: {consumer_api.api_method} {consumer_api.api_url}")
        logger.debug(f"Producer pool size: {len(producer_pool)}")

        seq: list[APIModel] = [consumer_api]
        edges: list[DependencyEdge] = []
        i = -1
        producer_pool = [p for p in producer_pool if p != consumer_api]
        while i >= -len(seq):
            current = seq[i]
            logger.debug(f"Processing API at position {i}: {current.api_method} {current.api_url}")

            pool = [p for p in producer_pool if p not in (seq[-1], current)]
            bindings = self.resolver.resolve(current, pool)
            edges.extend(self._edges_from_bindings(bindings))
            new_producers = []
            for b in bindings:
                if b.producer.api not in seq[:-1] and b.producer.api not in new_producers:
                    new_producers.append(b.producer.api)
            if new_producers:
                logger.debug(f"Adding {len(new_producers)} new producers to sequence")
                for p in new_producers:
                    seq.insert(0, p)
                    logger.debug(f"  Added producer: {p.api_method} {p.api_url}")
            i -= 1

        dedup = list(dict.fromkeys(seq))
        logger.debug(f"Final sequence ({len(dedup)} APIs): {[f'{api.api_method} {api.api_url}' for api in dedup]}")
        return SequencePlan(tuple(dedup), tuple(self._merge_edges(edges)))

    # ---- helpers ----
    def _edges_from_bindings(self, bindings: list[Binding]) -> list[DependencyEdge]:
        by_pair: dict[tuple[APIModel, APIModel], list[Binding]] = {}
        for b in bindings:
            key = (b.producer.api, b.consumer.api)
            by_pair.setdefault(key, []).append(b)
        return [DependencyEdge(prod, cons, tuple(bs)) for (prod, cons), bs in by_pair.items()]

    def _merge_edges(self, edges: list[DependencyEdge]) -> list[DependencyEdge]:
        d: dict[tuple[APIModel, APIModel], list[Binding]] = {}
        for e in edges:
            key = (e.producer, e.consumer)
            d.setdefault(key, []).extend(list(e.bindings))
        return [DependencyEdge(p, c, tuple(v)) for (p, c), v in d.items()]
