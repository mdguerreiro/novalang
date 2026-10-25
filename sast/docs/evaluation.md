# Evaluation (demo corpus)

Reproduce with `PYTHONPATH=. .venv/bin/python -m sentinel eval`, which writes `docs/evaluation.json`. The same numbers are asserted by `tests/test_demo_eval.py`.

**Corpus.** Two Flask services from one fictional customer (`acme-shop`, `acme-billing`) share a vendored internal package (`acme_common`). A third service, `acme-admin`, is used only by stage S5 below. The corpus of the first two contains:
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

## Learned spec rules (S5)

Facts such as `sanitizer_api(fn, cls)` are keyed by callee name. They cannot help when the code that makes a call dangerous is not in the repository. `acme-admin` is a third service of the same org. It installs `acme_common` as a package (`requirements.txt`) instead of vendoring it, so the engine cannot see the bodies of `run_shell`, `run_query`, `fetch` or `quote_sql`. Its ground truth has 5 real vulnerabilities and 6 traps.

Learned spec rules are the second kind of knowledge (`sentinel/learn/rules.py`). Each one is an ordinary Semgrep rule in the shape of `specs/python-web.yml`, written by a rule synthesizer:
- A confirmed finding (human, or a gated agent TP) whose sink is inside a shared helper proposes a sink rule for the helper, focused on the parameter the flow enters by.
- A sanitizer judgement (human `SANITIZED` at org scope, or a gated agent FP verdict) proposes a sanitizer rule.

A rule must pass four gates before it can leave `candidate`:
1. Sanity: Semgrep accepts it.
2. Patch differential: the vulnerable and fixed examples, analysed by the full engine with and without the rule, differ as intended.
3. Generalization: the rule matches the originating call site.
4. Canaries and FP budget: no canary is lost, and at most 2 new findings appear on the reference corpora.

Synthesized rules start in shadow, like other machine knowledge.

| Run | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| acme-admin, cold (no org knowledge) | 1 | 1 | 4 | 0.50 | 0.20 |
| acme-admin, after shop + billing were triaged and the rules approved | **5** | **0** | **0** | **1.00** | **1.00** |
| Semgrep OSS on acme-admin, curated pack | 1 | 1 | 4 | 0.50 | 0.20 |
| Semgrep OSS on acme-admin, exported pack (curated + learned) | 4 | 0 | 1 | 1.00 | 0.80 |

- **Cold.** The engine finds only `export_users` (a direct `os.system`). It misses `backup`, `user_search`, `audit_log` and `health_probe`, which all reach a sink inside an installed helper. `user_lookup` (`quote_sql` in a quoted literal) is reported, because `quote_sql` is an unmodelled library call.
- **Triage of shop and billing** confirmed the reported findings and approved the knowledge that passed its gates. Three sink rules (`run_query`, `fetch`, `run_shell`) and one sanitizer rule (`quote_sql`) were synthesized. All four passed every gate.
- **Warm.** The sink rules reveal the four missed flows, including `audit_log`, which goes through a local helper first. The engine still applies what it knows at the call site: `backup_safe` is `shlex.quote`d, and `user_by_id` passes the value as a bound parameter, not in the query text. `user_lookup` and `user_by_ref` are suppressed by the `quote_sql` knowledge (the org fact and the sanitizer rule both apply). No AI calls were needed.
- **Export.** `python -m sentinel export-rules --org acme --format taint` turns the same rules into Semgrep OSS taint rules for CI. On acme-admin they find 4 of 5 flows with no false alarm, and the sanitizer rule removes the `quote_sql` false alarm. `audit_log` is interprocedural, which Semgrep OSS does not follow.
- **Scope of a rule.** A sink rule applies only in repos that do not contain the helper's body. Where the body is present (shop, billing), the engine already sees the real sink, so the rule would only add duplicate findings. S0 to S4 are unchanged.
- **Literal arguments.** A learned sink or source rule focused on a literal (`run_query("... = ?", (uid,))`) does not fall back to the enclosing call node. The curated pack keeps the original fallback, so existing numbers do not move.

The test suite checks that the gate rejects:
- a rule Semgrep cannot parse;
- an over-specific rule that matches its own example but not the real call site;
- `$F($X, ...)` as a sink (FP budget) and `$F(...)` as a sanitizer (canaries);
- a validation pair that does not differ;
- a sanitizer rule that would hide a human-confirmed finding.

## Safety properties exercised by the test suite

132 tests (including 2 browser end-to-end flows) run in about three minutes:
- **Canary gate.** Overbroad knowledge such as `os.path.join` as a sanitizer, `regex:[a-z]+` as a validator, or `*.strip` cannot activate.
- **Confirmed findings are protected.** Human-confirmed findings block conflicting knowledge.
- **Rescans are not corroboration.** Machine-proposed suppressing knowledge needs independent support: distinct findings for agent items, distinct repositories for oracle items.
- **Verdicts are checked.** Hallucinated citation hashes, split votes, free-text FP verdicts, and self-contradicting TP verdicts are rejected by the gates.
- **Retraction re-opens.** Retiring a knowledge item re-opens every finding it suppressed.
- **Soundness fixes found by the tests:**
  - a host allow-list no longer survives rebinding the URL variable;
  - chained string methods no longer create false assumptions;
  - proof trees resolve against the derivation graph.

---

# Live evaluation (real model, code we did not write)

Everything above uses the deterministic mock. This section uses the real model (Opus-class, adaptive thinking,
structured outputs) and measures what a customer would see. Protocol:

- **Frozen code, unseen repositories.** Before each held-out run the code is committed and not changed until the
  run is scored. Repositories inspected while fixing a miss become *development* data; the next run uses a fresh set.
  Every fix made from a held-out run is a general rule (no repository names, no benchmark-specific patterns).
- **Two comparisons.** Semgrep OSS on the same spec pack, and an *LLM that reads every file* (same model, one call per
  file, structured output, medium effort) - the strongest simple baseline, and the one LLM-SAST products resemble.
- **One scoring script** (`bench/score_oss.py`, `bench/pysastbench.py`) scores both systems against the same labels.
- Sentinel "reports" what reaches an analyst: Open + Review lanes. The Candidates lane (unverified IDOR) is not counted.

## External benchmark: PySASTBench (ICSE '26 SAST study)

240 synthetic Python programs, 120 vulnerable/fixed pairs, 6 CWE families, many frameworks (Flask, FastAPI, Django,
Quart, Falcon, raw sockets/http.server, CLI tools). A file is flagged when the expected class is reported at the
ground-truth function. Published numbers for PyFlow (IFDS) are from its README; the others are ours.

| System | Files | Precision | Recall | F1 | Cost |
|---|---:|---:|---:|---:|---:|
| PyFlow ast-dataflow (published) | 240 | 0.857 | 0.450 | 0.590 | - |
| PyFlow IFDS (published, best) | 240 | 0.837 | 0.858 | 0.848 | - |
| Sentinel engine only, no model (start of this work) | 240 | 0.857 | 0.200 | 0.324 | $0 |
| Sentinel engine only, no model (current) | 240 | **1.000** | 0.425 | 0.596 | $0 |
| LLM reads every file | 120 | 0.966 | 0.950 | 0.958 | $1.52 |
| Sentinel + model (before heap/guard fixes) | 120 | 0.875 | 0.700 | 0.778 | $7.98 |
| Sentinel + model (heap, templates, containment) | 120 | 0.917 | 0.733 | 0.815 | $9.56 |
| Sentinel + model (current: guard summaries, cheaper verifier) | 120 | 0.978 | 0.750 | 0.849 | $5.59 |

Reading: on single-file synthetic programs, reading everything is the LLM's best case (the whole program fits in
one prompt). The engine alone (no model, deterministic, explainable) already has zero false positives on 240 files.
Model calls add recall; their cost per file is higher than one read of a tiny file, and lower on real repositories
(next section).

## Open-source repositories (held-out sets 1-4)

15 repositories: intentionally vulnerable apps (DSVW, Vulnerable-Flask-App, VAmPI, vulnpy, DSVPWA, vulnerable-api,
lets-be-bad-guys, python-insecure-app) and real applications (flask-realworld, microblog, full-stack-fastapi-template,
flasky, flaskbb, fastapi-realworld, httpbin, redash, bakerydemo, Flask examples).

What the held-out runs exposed, and the general fixes (each re-checked on the next unseen set):

| Observed on unseen code | Cause | General fix |
|---|---|---|
| 8 IDOR "confirmed" on a clean app | narrow identity model; owner column taken as privacy | identity by name across auth libraries; per-model privacy question; IDOR never engine-confirmed, Candidates lane |
| open redirect FP | an unrecognised check was invisible | checks that inspect a tainted value become unverified-validation points |
| SSRF FP | constant `https://host/` prefix ignored | fixed-host URLs are safe for SSRF/redirect |
| verifier TPs discarded | model narrowed cited ranges and copied another hash | citation valid when the lines were served by a tool call |
| review queue flooded | every candidate verified at full cost | one confirming sample; full unanimous vote only to close |
| vulnpy, DSVPWA misses | dynamic dispatch, framework attributes | CHA by method name (capped); `self.attr` named after the library base |
| VAmPI / vulnerable-api: no entry points | handlers declared in OpenAPI YAML | config keys naming project functions are registrar questions |
| python-insecure-app, Flask-free code: no questions | unknown source + unknown sink | source frontier (mirror of the sink frontier) + handler-read seed |
| flaskbb: 45 min | per-fact gating re-analysed every repo; summaries for all functions | canary-gated additive facts; demand-driven summaries (79 s -> 1.7 s per analysis) |
| crash on one repo | indented method source | robust parsing; one bad function never aborts a scan |

Cost on real repositories (one scan, cold, same model):

| Repository | Size | Sentinel | LLM reads every file |
|---|---:|---:|---:|
| flaskbb | 2,096 functions, 38k lines | $0.48 | $2.50 |
| redash | 2,743 functions, 45k lines | $0.77 | $3.15 |
| vulnpy | 374 functions | $0.17-0.30 | $0.42 |
| fastapi-realworld | 185 functions | $0.004 | $0.35 |

Cross-repository reuse: flaskbb, scanned after four other repositories, answered 14 of its 50 frontier questions from
knowledge learned elsewhere. Unchanged rescans: PENDING (live). With the mock: 3 frontier questions, 0 tier-1, 0 tier-2.

## Engine cost at repository scale

Measured with no model calls (mock oracle), one process, 4 cores.

| Repository | Input facts | Full solve | Solves per first scan | What-if, whole program | What-if, sliced |
|---|---|---|---|---|---|
| redash | 230k | 20-25 s | 2 full + 69 tiny gate checks (1 s) | 25 s | 0.03 s |
| flaskbb | | 4-5 s | | 1.5 s mean | 0.46 s mean |
| Mycodo | 403k | 64-74 s | 2 full + 192 tiny | ~72 s | ~9 s |

- 95% of a full solve is clingo grounding; provenance instrumentation costs ~5%. The ground program has no
  derivation blowup (atoms = rules), so the remaining lever per solve is the backend (Soufflé, backlog).
- Live scans were CPU-bound in the verifier's `what_if` (a whole-program solve per call). It now re-analyses only the
  finding's chop and gives the same answers as the whole program on every finding and hypothesis tested.
- Solves are memoised on their exact input: an unchanged rescan in the same process runs no solve (flaskbb 25 s ->
  5 s, redash 60 s -> 7 s, the rest is parsing).

## Generalization: no framework knowledge at all

`SENTINEL_SPECS=minimal` keeps only Python stdlib sinks and sanitizers (no Flask/FastAPI/Django/pandas/jinja2 specs).
On acme-reports and acme-etl the frontier learns the frameworks itself: same recall (13/13) and precision (no FP), at
20 instead of 14 first-time questions (`tests/test_frontier.py::test_no_framework_knowledge_still_finds_everything`).
The curated pack works as a warm cache, not as the source of coverage.

## Known gaps (measured, not yet fixed)

- Flows through files written and read back (upload saved, later `yaml.load`ed).
- Dynamic calls through `getattr(module, name)`.
- Object-level authorization through dictionaries rather than ORM lookups.
- Stored XSS through server-side templates in other files when the template marks values safe in a macro.
