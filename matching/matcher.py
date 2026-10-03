from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Callable, Any, Optional
from functools import lru_cache

from symspellpy import SymSpell
from importlib.resources import files
# --------------------------------
# --------------------------------

# ---------------------------
# ---------------------------

SplitFn = Callable[[str], list[str]]
CorrectFn = Callable[[str], list[str]]


@lru_cache(maxsize=None)
def _get_symspell(dict_path: Optional[str],
                  max_edit_distance: int,
                  prefix_length: int) -> "SymSpell":
    if SymSpell is None:
        raise RuntimeError("symspellpy not installed")
    ss = SymSpell(max_dictionary_edit_distance=max_edit_distance,
                  prefix_length=prefix_length)
    if dict_path is None:
        dict_path = str(files("symspellpy")
                        .joinpath("frequency_dictionary_en_82_765.txt"))
    ss.load_dictionary(dict_path, term_index=0, count_index=1)
    return ss

def make_symspell_corrector(dict_path: Optional[str] = None,
                            max_edit_distance: int = 2,
                            prefix_length: int = 7) -> CorrectFn:
    if SymSpell is None:
        return lambda term: [term]

    def _correct(term: str) -> list[str]:
        ss = _get_symspell(dict_path, max_edit_distance, prefix_length)
        suggestions = ss.lookup_compound(
            phrase=term,
            max_edit_distance=max_edit_distance,
            transfer_casing=True,
            ignore_term_with_digits=True,
            ignore_non_words=True,
            split_by_space=True,
        )
        out: list[str] = []
        for s in suggestions:
            out.append(s.term.split(" ")[-1].lower())
        return list(dict.fromkeys(out))
    return _correct

# ---------------------------
# ---------------------------

def extend_consumers(consumers:dict[str, Any],
                     matcher: NameMatcher) ->dict[str, list[Any]]:
    out:dict[str, list[Any]] = {}
    for name, ctype in consumers.items():
        variants = matcher.expand(name)
        out[name] = [ctype, variants]
    return out


def split_tail_variants(name: str) -> list[str]:
    parts: list[str] = []
    camel = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", name)
    if camel:
        parts.append(camel[-1].lower())
    parts.append(name.split("-")[-1].lower())
    parts.append(name.split("_")[-1].lower())
    return list(dict.fromkeys([p for p in parts if p]))

@dataclass(frozen=True)
class NameMatcher:
    split_fn: SplitFn = split_tail_variants
    correct_fn: CorrectFn = field(default_factory=make_symspell_corrector)

    def accurate_pattern(self, consumer: str) -> re.Pattern:
        return re.compile(rf"^[^A-Za-z0-9]*{re.escape(consumer)}(?!.)",
                          re.IGNORECASE)

    def exact_match(self, producer_name: str, consumer_name: str) -> bool:
        return bool(self.accurate_pattern(consumer_name).match(producer_name))

    def expand(self, name: str) -> list[str]:
        out: list[str] = []
        for tail in self.split_fn(name):
            for corr in self.correct_fn(tail):
                out.append(corr.lower())
        out = list(dict.fromkeys(out))
        if name in out:
            out = [x for x in out if x != name]
        return out
