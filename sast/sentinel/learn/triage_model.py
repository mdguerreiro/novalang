"""Learned triage ranking: P(finding is a real issue) from engine features, trained on analyst decisions.

The Bayesian network ranks with hand-set priors; this model learns them from the organisation's own triage (and,
optionally, a global prior from all orgs). Pure Python logistic regression with L2, so it needs no dependencies and
retrains in milliseconds. The pipeline blends it with the Bayesian posterior by how many labels it has seen.
"""
from __future__ import annotations

import math
from collections import Counter


def features(row: dict) -> Counter:
    d = row.get("data") or {}
    f = Counter()
    f["bias"] = 1
    f["cls=" + row["cls"]] = 1
    f["status=" + row["engine_status"]] = 1
    f["kind=" + (row.get("source_kind") or "none")] = 1
    rule = d.get("sink_rule") or ""
    f["sinkrule=" + ("learned" if rule.startswith(("spec.learned", "learned:")) else "read" if rule == "handler-read"
                     else "curated" if rule.startswith("spec.") else "other")] = 1
    for a in d.get("assumptions", []):
        f["asm=" + str(a["asm"][0])] += 1
    path = d.get("path", [])
    f["path_len"] = min(len(path), 20) / 20
    f["interproc"] = int(row.get("sink_fn") != row.get("source_fn"))
    f["learned_facts"] = int(bool(d.get("learned")))
    f["mitigations"] = min(len(d.get("mitigations", [])), 3) / 3
    f["decided=" + str(d.get("decided_by"))] = 1
    return f


class TriageModel:
    def __init__(self, l2: float = 0.05, epochs: int = 200, lr: float = 0.3):
        self.l2, self.epochs, self.lr = l2, epochs, lr
        self.w: dict[str, float] = {}
        self.n = 0

    def fit(self, rows: list[dict], labels: list[int]) -> "TriageModel":
        xs = [features(r) for r in rows]
        self.n = len(xs)
        w: dict[str, float] = {}
        for _ in range(self.epochs):
            for x, y in zip(xs, labels):
                p = self._sig(sum(w.get(k, 0.0) * v for k, v in x.items()))
                g = p - y
                for k, v in x.items():
                    w[k] = w.get(k, 0.0) - self.lr * (g * v + self.l2 * w.get(k, 0.0) / max(self.n, 1))
        self.w = w
        return self

    @staticmethod
    def _sig(z: float) -> float:
        return 1 / (1 + math.exp(-max(min(z, 30), -30)))

    def predict(self, row: dict) -> float:
        return self._sig(sum(self.w.get(k, 0.0) * v for k, v in features(row).items()))


def auc(scores: list[float], labels: list[int]) -> float | None:
    pos = [s for s, y in zip(scores, labels) if y]
    neg = [s for s, y in zip(scores, labels) if not y]
    if not pos or not neg:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))
