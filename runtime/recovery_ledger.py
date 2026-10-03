"""Structured record of what the LLM recovery machinery did, and whether it worked.

AE #3 asks for failure-classification accuracy, dependency- and parameter-repair
success rates, LLM calls per successful repair, and examples of failed repairs.
Those numbers were previously reconstructed by mining the run log, which turned
out to be unreliable in four separate ways:

* a run using ``--custom_judge`` answers HTTP 200 for business failures, so
  reading ``status_code`` lines scored Chat2DB's parameter repair at 94% when
  the real figure is 19.8%;
* parameter repair fires from three different sites that the log renders almost
  identically, so their rates could not be separated;
* dependency recovery re-plans the whole sequence, so "the next request after
  the trigger" is a producer, not the target, and crediting it inflated the rate
  eightfold;
* attribution was temporal ("succeeded after X fired"), which cannot distinguish
  a mechanism that caused the success from one that merely ran before it.

Recording the events as they happen removes all four. The ledger is passive: it
stores what it is told and never infers, so the analysis stays honest about what
was observed versus what was concluded.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

# Where a parameter repair was invoked from. These behave differently and had to
# stop being lumped together: the mix escalation happens inside the first pass,
# before the failure is even classified, while param_hint runs afterwards and is
# the only one that sees the classifier's diagnosis.
SITE_MIX_ESCALATION = "mix_escalation"
SITE_RUNTIME_REGEN = "runtime_regen"
SITE_PARAM_HINT = "param_hint_retry"


@dataclass
class RepairEvent:
    seq: int
    kind: str                      # "param" | "dep" | "repair_step"
    site: str                      # where it was invoked from
    target: str                    # the endpoint whose episode this belongs to
    api: str                       # the endpoint the repair acted on
    on_target: bool                # api == target, or a producer in its chain
    t: float
    detail: dict[str, Any] = field(default_factory=dict)
    # Filled in when the acted-on endpoint is next exercised.
    outcome: Optional[str] = None  # "ok" | "fail" | "not_retried"
    status: Optional[int] = None
    llm_calls: Optional[int] = None
    llm_tokens: Optional[int] = None


@dataclass
class ClassificationEvent:
    seq: int
    target: str
    failed_api: str
    status: str
    predicted: str                 # dependency_error | parameter_error | unknown
    reason: str
    missing_fields: list[str]
    response_excerpt: str
    t: float
    # The episode's eventual result, so accuracy can be judged against something.
    episode_outcome: Optional[str] = None


@dataclass
class EpisodeRecord:
    target: str
    outcome: Optional[str] = None
    started: float = 0.0
    ended: Optional[float] = None
    mechanisms: list[str] = field(default_factory=list)
    llm_calls_start: int = 0
    llm_calls_end: int = 0
    llm_tokens_start: int = 0
    llm_tokens_end: int = 0


class RecoveryLedger:
    """Append-only record of repair attempts and their observed outcomes."""

    def __init__(self) -> None:
        self.repairs: list[RepairEvent] = []
        self.classifications: list[ClassificationEvent] = []
        self.episodes: list[EpisodeRecord] = []
        self._seq = 0
        self._current: Optional[EpisodeRecord] = None
        # Repairs waiting for their endpoint to be exercised again.
        self._pending: dict[str, list[RepairEvent]] = {}

    # ---- episode boundaries -------------------------------------------------

    def begin_episode(self, target: str, llm_calls: int = 0, llm_tokens: int = 0) -> None:
        self.end_episode(None)
        self._current = EpisodeRecord(target=target, started=time.time(),
                                      llm_calls_start=llm_calls,
                                      llm_tokens_start=llm_tokens)

    def end_episode(self, outcome: Optional[str], llm_calls: int = 0,
                    llm_tokens: int = 0) -> None:
        if self._current is None:
            return
        self._current.outcome = outcome
        self._current.ended = time.time()
        self._current.llm_calls_end = llm_calls
        self._current.llm_tokens_end = llm_tokens
        # Anything still waiting was never retried; say so rather than leaving a
        # null that later reads as a failure.
        for evs in self._pending.values():
            for e in evs:
                if e.outcome is None:
                    e.outcome = "not_retried"
        self._pending.clear()
        for c in self.classifications:
            if c.episode_outcome is None and c.target == self._current.target:
                c.episode_outcome = outcome
        self.episodes.append(self._current)
        self._current = None

    # ---- events -------------------------------------------------------------

    def record_repair(self, kind: str, site: str, api: str,
                      detail: Optional[dict] = None) -> RepairEvent:
        self._seq += 1
        target = self._current.target if self._current else api
        ev = RepairEvent(seq=self._seq, kind=kind, site=site, target=target,
                         api=api, on_target=(api == target), t=time.time(),
                         detail=detail or {})
        self.repairs.append(ev)
        self._pending.setdefault(api, []).append(ev)
        if self._current and kind not in self._current.mechanisms:
            self._current.mechanisms.append(kind)
        return ev

    def record_classification(self, target: str, failed_api: str, status: str,
                              predicted: str, reason: str,
                              missing_fields: list[str], response: str) -> None:
        self._seq += 1
        self.classifications.append(ClassificationEvent(
            seq=self._seq, target=target, failed_api=failed_api, status=str(status),
            predicted=predicted, reason=(reason or "")[:500],
            missing_fields=list(missing_fields or []),
            response_excerpt=(response or "")[:300], t=time.time()))

    def record_outcome(self, api: str, ok: bool, status: Optional[int] = None) -> None:
        """Close out repairs waiting on `api`.

        Called with the judged result, not the raw status code, so a 200 that the
        application considers a failure is not counted as a repair that worked.
        """
        for ev in self._pending.pop(api, []):
            if ev.outcome is None:
                ev.outcome = "ok" if ok else "fail"
                ev.status = status

    # ---- output -------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        by: dict[tuple[str, str], dict[str, int]] = {}
        for e in self.repairs:
            b = by.setdefault((e.kind, e.site), {"triggered": 0, "ok": 0,
                                                 "fail": 0, "not_retried": 0})
            b["triggered"] += 1
            if e.outcome in b:
                b[e.outcome] += 1
        rates = {f"{k}/{s}": dict(v, rate=(v["ok"] / v["triggered"] if v["triggered"] else 0.0))
                 for (k, s), v in by.items()}

        # Which mechanisms an endpoint needed, judged only on episodes that
        # succeeded; "needed" here means "ran", and the distinction matters.
        per_target: dict[str, set[str]] = {}
        for e in self.repairs:
            per_target.setdefault(e.target, set()).add(e.kind)
        mech_mix: dict[str, int] = {}
        for ep in self.episodes:
            ms = per_target.get(ep.target, set())
            key = "none" if not ms else "+".join(sorted(ms))
            mech_mix[f"{key}/{ep.outcome}"] = mech_mix.get(f"{key}/{ep.outcome}", 0) + 1

        cls = {}
        for c in self.classifications:
            cls[c.predicted] = cls.get(c.predicted, 0) + 1

        rescued = [ep.target for ep in self.episodes
                   if ep.outcome == "Success" and per_target.get(ep.target)]
        return dict(
            episodes=len(self.episodes),
            succeeded=sum(1 for e in self.episodes if e.outcome == "Success"),
            repairs=len(self.repairs),
            classifications=cls,
            by_mechanism_and_site=rates,
            mechanism_mix=mech_mix,
            rescued_endpoints=sorted(rescued),
            llm_calls_per_rescue=(
                sum(ep.llm_calls_end - ep.llm_calls_start for ep in self.episodes)
                / len(rescued) if rescued else None),
        )

    def failed_examples(self, limit: int = 20) -> list[dict]:
        out = []
        for e in self.repairs:
            if e.outcome == "fail" and e.detail:
                out.append(dict(kind=e.kind, site=e.site, api=e.api,
                                status=e.status, detail=e.detail))
            if len(out) >= limit:
                break
        return out

    def dump(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dict(
            summary=self.summary(),
            failed_examples=self.failed_examples(),
            repairs=[asdict(e) for e in self.repairs],
            classifications=[asdict(c) for c in self.classifications],
            episodes=[asdict(e) for e in self.episodes],
        ), ensure_ascii=False, indent=2), encoding="utf-8")
