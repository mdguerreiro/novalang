"""Cheap pre-oracle: label an unknown library API from the closest already-labelled APIs.

Representation: TF-IDF over character 3-grams of the last two name components plus whole name tokens
(`pandas.read_sql_query` ~ `pandas.read_sql`, `yaml.unsafe_load` ~ `yaml.load`). Pure Python, no model calls.
Only confident, unanimous neighbourhoods answer; everything else still goes to the LLM. Every answer it gives is
an ordinary knowledge item (origin `knn:`), gated like any machine-made fact.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict


def features(api: str) -> Counter:
    name = api.replace("()", "")
    parts = [p for p in re.split(r"[.]", name) if p]
    tail = parts[-2:] if len(parts) > 1 else parts
    f = Counter()
    for p in parts:
        for tok in re.split(r"_|(?<=[a-z])(?=[A-Z])", p):
            if tok:
                f["t:" + tok.lower()] += 1
    for p in tail:
        s = f"^{p.lower()}$"
        for i in range(len(s) - 2):
            f["g:" + s[i:i + 3]] += 1
    f["root:" + parts[0].lower()] += 1
    f["leaf:" + parts[-1].lower()] += 2
    return f


class NeighborOracle:
    def __init__(self, k: int = 3, min_sim: float = 0.55):
        self.k, self.min_sim = k, min_sim
        self.items: list[tuple[str, str, Counter]] = []  # (api, label, features)
        self.df: Counter = Counter()

    def fit(self, labelled: list[tuple[str, str]]) -> "NeighborOracle":
        self.items, self.df = [], Counter()
        for api, label in labelled:
            f = features(api)
            self.items.append((api, label, f))
            self.df.update(set(f))
        return self

    def _vec(self, f: Counter) -> dict:
        n = max(len(self.items), 1)
        v = {t: c * math.log((1 + n) / (1 + self.df[t])) for t, c in f.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def neighbours(self, api: str, exclude: str | None = None) -> list[tuple[float, str, str]]:
        q = self._vec(features(api))
        out = []
        for other, label, f in self.items:
            if other == exclude:
                continue
            v = self._vec(f)
            out.append((sum(q.get(t, 0.0) * x for t, x in v.items()), other, label))
        return sorted(out, reverse=True)[: self.k]

    def predict(self, api: str, exclude: str | None = None) -> tuple[str, float, list[str]] | None:
        nb = self.neighbours(api, exclude)
        if len(nb) < self.k or nb[-1][0] < self.min_sim:
            return None
        labels = {l for _s, _o, l in nb}
        if len(labels) != 1:
            return None  # neighbours disagree: ask the LLM
        return labels.pop(), sum(s for s, _o, _l in nb) / len(nb), [o for _s, o, _l in nb]
