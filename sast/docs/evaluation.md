# Evaluation (demo corpus)

Reproduce with `PYTHONPATH=. .venv/bin/python -m sentinel eval`, which writes `docs/evaluation.json`. The same numbers are asserted by `tests/test_demo_eval.py`.

**Corpus.** Two Flask services from one fictional customer (`acme-shop`, `acme-billing`) share a vendored internal package (`acme_common`). The corpus contains:
- **14 real vulnerabilities**, 5 of them interprocedural, across SQLi, command injection, path traversal, SSTI, SSRF, deserialization and open redirect.
- **20 false-positive traps:**
  - guards, casts and route converters
  - a custom quote-escaping sanitizer
  - `slugify` and `hexdigest`
  - a host allow-list and a regex validator
  - dead code and test-only code
  - parameterized queries, `yaml.safe_load`, and argv-list `subprocess`

Ground truth lives in `demo/ground_truth.yaml`, outside the scanned trees, so it cannot leak into what the engine or agent reads (R13, R16).

## Precision and recall by stage

"Reported" means what a human would see: the Confirmed and Needs-review lanes. Suppressed lanes stay visible and auditable, but nobody has to act on them.

| Stage | Precision | Recall | TP | FP | FN |
|---|---|---|---|---|---|
| S0 Semgrep OSS taint mode (same specs) | 0.64 | 0.64 | 9 | 5 | 5 |
| S1 Tier 0: Datalog engine | 0.64 | **1.00** | 14 | 8 | 0 |
| S2 + Tier 1: spec oracle (mock) | 0.82 | 1.00 | 14 | 3 | 0 |
| S3 + Tier 2: verifier agent (mock), gated | **1.00** | **1.00** | 14 | 0 | 0 |

**S0, Semgrep OSS.**
- Misses all five interprocedural flows: `search`, `link_preview`, `list_invoices`, `archive` (through `run_shell`), `webhook_test`.
- Reports five false positives: the `isdigit` guard, the `isalnum` guard, a regex-guarded path, dead code and test code.

**S1, Datalog engine alone.**
- Finds every vulnerability.
- Of the 22 findings it shows a human, the 8 false alarms are all *undecided*. The engine never wrongly *confirms*: precision of its Confirmed lane is 12/12.
- Each undecided finding carries the exact assumption it could not discharge: `quote_sql` looks like a sanitizer, `slugify`/`hexdigest` are unmodelled, `is_safe_slug` is a guard of unknown strength, the debug console is unreachable.

**S2, spec oracle.** Resolves the unknown APIs, and judges `is_safe_slug` by executing its anchored regex against a payload battery.

**S3, verifier agent.**
- Judges the custom sanitizer: quote-escaping inside a quoted literal.
- Judges the dead function: no route and no references.
- Refutes `_customer_filter` as a sanitizer: a true positive, now confirmed.
- Its samples split on single-pass `../` stripping, so that finding goes to a human.

**Coverage.** 30 of 31 findings were decided without a human (96.8%). The one left is the genuinely ambiguous `../` case.

**AI suppressions that hid a real vulnerability:** 0 of 8. Each AI suppression was accepted only because the engine re-derived the mitigation from the facts the AI proposed.

> **Caveat.** The Tier-1 and Tier-2 components are deterministic mocks tuned to this corpus. S2 and S3 show that the gating, the voting, the counterfactual re-derivation and the routing work end to end. They are **not** a measurement of model quality. That needs the real client (`SENTINEL_LLM=claude`), real repositories, and alerts produced after the model's training cutoff (literature §2, R16).

## The flywheel

| Run | Engine-decided | Oracle calls | Agent calls | Decided by learned knowledge |
|---|---|---|---|---|
| acme-shop, first scan | 80% | 3 | 2 | 0 |
| (AppSec lead reviews: 1 triage + 1 audit; approves K-001, K-003, K-004, K-005) | | | | |
| acme-shop, rescan | **100%** | **0** | **0** | **4** |
| acme-billing onboarded cold | 46% | 1 | 3 | 0 |
| acme-billing onboarded after the shop review | **55%** | 1 | **2** | **1** |

- **One review makes the engine self-sufficient on a repo.** The oracle's library facts and the agent's sanitizer and dead-code facts, once approved, are plain Datalog facts. The next scan decides everything deterministically, for free.
- **Knowledge transfers within an org.** The `quote_sql` sanitizer was learned on `acme-shop` and scoped to the org, because it lives in the shared `acme_common` package. It decides `invoice_search` on `acme-billing`'s first scan. The remaining billing work (the `is_safe_slug` guard, `_customer_filter`) is new to the org, so it still needs AI. That is expected, and it shrinks with every repository onboarded.
- **Rescans of unchanged code cost nothing.** Agent verdicts are cached by content hash. Re-derivations after a knowledge change make no AI calls (`tests/test_pipeline_cache.py`).

## Safety properties exercised by the test suite

98 tests (including 2 browser end-to-end flows) run in about a minute:
- **Canary gate.** Overbroad knowledge such as `os.path.join` as a sanitizer, `regex:[a-z]+` as a validator, or `*.strip` cannot activate.
- **Confirmed findings are protected.** Human-confirmed findings block conflicting knowledge.
- **Rescans are not corroboration.** Machine-proposed suppressing knowledge needs independent support: distinct findings for agent items, distinct repositories for oracle items.
- **Verdicts are checked.** Hallucinated citation hashes, split votes, free-text FP verdicts, and self-contradicting TP verdicts are rejected by the gates.
- **Retraction re-opens.** Retiring a knowledge item re-opens every finding it suppressed.
- **Soundness fixes found by the tests:**
  - a host allow-list no longer survives rebinding the URL variable;
  - chained string methods no longer create false assumptions;
  - proof trees resolve against the derivation graph.
