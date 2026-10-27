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

### Soufflé backend (default when installed)

The same .lp rules, translated to Soufflé and compiled once; identical kept relations, provenance and findings on
every repository compared (tests/test_souffle.py keeps checking it).

| Repository | One solve, clingo | One solve, Soufflé | First scan (no model), clingo | First scan, Soufflé |
|---|---|---|---|---|
| flaskbb | 4.5 s | 1.6 s | | |
| redash | 27.3 s | 2.1 s | 62.3 s | 14.8 s |
| wagtail | 35.9 s | 4.3 s | 956.5 s | 38.3 s |
| wagtail + Django view registration learned | 785.2 s | 5.0 s | | |
| Mycodo | 82.3 s | 3.7 s | 1318.9 s | 32.1 s |

Small solves (gate canaries, what-if slices, under 20k input facts) stay on clingo in-process: a process launch
costs more than they do. What is left of a first scan is parsing and Semgrep (5-11 s), and the model's latency.

## Real vulnerabilities in real repositories (CVE split)

Protocol: each CVE's fix commit was located in the project's git history; the parent commit is the vulnerable
tree, the fix commit the fixed tree. Both are scanned live in one store (vulnerable first), so the fixed scan shows
what learning from the first scan saves. "Caught" = a finding of the CVE's class in a function the fix touched, in
the confirmed or review lane; on the fixed tree that same check counts as a false alarm. Code was frozen before each
run. Two candidate cases were dropped because the located commit was not the fix (bazarr: wrong date; streamlit:
an unrelated 2022 CodeQL clean-up for a 2021 advisory).

Baseline: an LLM that reads every Python file once per scan (same model, structured output). Measured in full on
the two small repositories; on the large ones its cost is estimated from the token volume it would read (calibrated
on the two measured repositories) and its recall checked on the target files only, which is its best case.

| CVE (repo, class) | Sentinel vulnerable | Sentinel fixed | LLM vulnerable | LLM fixed |
|---|---|---|---|---|
| CVE-2024-5547 (devika, path) | caught, $0.19 | clean, $0.00 | caught, $0.45 | clean, $0.43 |
| CVE-2021-43775 (aim, path) | caught, $0.87 | clean, $0.45 | caught, $1.13 | clean, $1.13 |
| CVE-2024-5187 (onnx, tar slip) | caught, $1.03 | 1 review item, $0.05 | caught, ~$8.42 | false alarm, ~$8.42 |
| CVE-2020-11001 (wagtail, stored XSS) | missed, $1.71 (1 other confirmed, 10 IDOR candidates) | clean, $0.00 (30 answers reused, 0 calls) | caught, ~$10.35 | clean, ~$10.37 |
| CVE-2021-41185 (Mycodo, path) | caught, $5.23 (29 reported) | not reached (2 h cap) | caught, ~$9.98 | other alarm, ~$9.98 |

Reading so far:
- Both approaches catch the CVEs measured so far; Sentinel costs a fraction of reading everything at repository
  scale, and the second scan of a project costs little (verdicts and answers are reused; onnx $1.03 -> $0.05).
- onnx needed a capability the engine lacked (archive extraction, "tar slip", CVE-2007-4559 class): added as a
  general source/sink pair, not a repository pattern. Its fixed tree keeps one review item: the fallback branch
  passes `members=` through a project validator the engine cannot see into.
- wagtail is stored XSS (database content rendered unescaped): the engine has no stored-data sources (known gap).
- Mycodo is the expensive case: a first scan of a large app with no prior knowledge asked 331 frontier questions and
  took 103 minutes (engine time, see "Engine cost"). Those answers are global knowledge; the next repository using the
  same libraries asks only what is new. 29 findings reported (18 confirmed, 11 review), precision not yet audited.

Totals over the five valid CVEs (live spend, Sentinel; LLM measured on the two small repos, estimated on the rest):

| | Sentinel | LLM reads everything |
|---|---|---|
| CVEs caught on the vulnerable tree | 4 / 5 (wagtail stored XSS missed) | 5 / 5 (large repos: target files only, its best case) |
| First scans, total | $8.96 | ~$30.33 |
| Rescans of the fixed trees (4 measured) | $0.29 | ~$20.35 (same price every scan) |
| Alarms on patched code | devika 1 (a real unfixed bug), aim 1 debatable + 1 CLI review, onnx 1 review, wagtail 0 | devika 9, aim 2, onnx 1 false alarm on the target file |

Precision audit (findings read by hand, devika and aim, re-run live with a persisted store; $1.23 for all four scans):

| Tree | Sentinel reported (confirmed + review) | Real | LLM reported | Notes |
|---|---|---|---|---|
| devika vulnerable | 5 | 4 | 11 | Sentinel's 5th was an XSS label on the same send_file flow (spec fixed since) |
| devika fixed | 2 | 1 | 9 | engine closed the 3 patched flows itself (basename sanitizer, $0); the LLM still reports 2 of them |
| aim vulnerable | 6 (3 confirmed, 3 review) | 2 + 1 debatable | 5 | review items: `aim up` CLI flows; debatable: RestrictedPython-sandboxed query eval (the LLM reports it too) |
| aim fixed | 2 | 0 + 1 debatable | 2 | CVE flow closed in both |

- New true positive beyond the CVE: devika's fix left `browser_snapshot` (`send_file(request.args["snapshot_path"])`)
  unchanged; Sentinel keeps reporting it on the "fixed" tree, confirmed. The LLM reports it too.
- False positives removed: on patched code the engine derives the mitigation (sanitizer on the path) and closes the
  finding with no model call; the read-everything LLM keeps re-reporting patched flows and speculative ones
  (agent output saved to disk, PDF rendering) at 0.3-0.55 confidence, every scan, at full price.

## Why real CVEs are missed, and what fixed it (dev split, then a held-out split)

The live pass on the pre-registered real-world split (16 CVEs from PySASTBench `RealworldDataset.csv`, seed 20261026)
was stopped after 7 CVEs ($16.89 of a $25 cap, including an aborted first attempt and runs lost to container
restarts and an airflow out-of-memory crash, fixed in 90a9ea8): 1 of 7 caught, and that one (thefuck) is flagged on
the fixed tree too. Rather than finish it, every miss was diagnosed with the engine alone (no model calls, $0).

Where the chain breaks (dev split, 16 CVEs, target functions read by hand):

| Cause | CVEs | Examples |
|---|---|---|
| Attacker input is not a web request | 11 | library API arguments (mlflow, haystack, django `Storage.save`, salt module functions, cookiecutter `clone`), a remote server's reply (llama_index `eval` of an SSE stream), downloaded metadata (yt-dlp), a database value (airflow XCom), a config file (parlai) |
| Dangerous API not modelled as a sink | 5 | templates compiled from strings (mlflow `CardTab`, haystack `PromptBuilder`), `mark_safe` (DRF), argument injection through a `subprocess` list (cookiecutter), `Markup(f'<a href=..>')` (airflow) |
| Data flow lost | 1 | a nested function reading its enclosing function's variable (llama_index) |
| Benchmark data | 3 | target function absent from the vulnerable tree (autogpt, mlflow 37058); target moved in a monorepo split (llama_index) |
| Scorer too loose | - | `stream_complete.gen` matched 26 functions: hits now need the module- or class-qualified name |

Semgrep "detects" 11 of the 16 because it flags any `pickle.load`, `eval`, `shell=True` or `mark_safe` regardless of
data flow; how many other alerts it raises per repository is not in the dataset, so its numbers are not comparable
with a flow-based count.

Fixes (each general, tested, committed separately):
- Library input (c914f9d .. 6d543e2): in a distributable package (`setup.py` / `pyproject.toml` / `setup.cfg`), the
  public parameters of functions within three calls of a sink that executes what it is given (code, template,
  deserialization, shell command) — and the constructor of a class with such a method — are a weak source, modelled
  as one synthetic node (airflow has 12k such parameters). Never for applications, never for other classes, never
  where a reported request flow already reaches the sink, never into a program's argument list.
- Remote replies (4558b34): the reply of a request call (requests, httpx, aiohttp, urllib, urllib3, SSE) is a weak
  source; the client or session object is not (tagging `requests.Session()` took mlflow from 43 to 297 findings).
- Sinks: templates compiled from strings (Jinja2, Django, Mako; sandboxed environments excluded), `mark_safe` /
  `SafeString` / `flask.Markup`, `subprocess` argument injection (CWE-88), `dill` / `cloudpickle` / `joblib` /
  `pandas.read_pickle` / `shelve` / `jsonpickle` / `pickle.Unpickler`, `torch.load` without `weights_only`,
  `numpy.load(allow_pickle=True)`, `yaml.unsafe_load`.
- Closures (6d543e2): a nested function reads its enclosing function's variables.
- Web frameworks (038f983): a curated pack (`knowledge/packs/python-web-frameworks.yml`, from framework
  documentation: Django URLconf, Flask/FastAPI/Starlette/aiohttp registration) and class-based views (HTTP-verb
  methods of Django / DRF / Flask / flask-restx / Tornado / Starlette view classes) as request handlers.

### Held-out split

Built before any of these changes and never read during development: the next CVEs in the same seeded order
(`rw3/build.py`; part a from release tags, part b from the fix commit found in the project's history — a commit naming
the CVE/GHSA id, else the latest commit changing a target function with a security keyword; one bogus pick dropped
after a regex bug). 12 CVEs: path traversal 5, XSS 5, code injection 2 (no deserialization, SQL or command injection
— the dataset rows left after split 1 had no buildable version for those). Two held-out mlflow CVEs are template
injection in the same Recipe-card area as a dev CVE. Engine only, no model calls; "caught" = a finding of the CVE's
class (template injection counts for code injection, CWE-1336 < CWE-94) in a target function; flagged fixed tree =
false alarm.

| Held-out CVE | class | frozen engine (90a9ea8) | new engine (6d543e2) | + web pack (038f983) |
|---|---|---|---|---|
| CVE-2021-25283 | code | missed (52) | missed (107) | missed (107) |
| CVE-2021-25963 | xss | missed (0) | missed (2) | missed (6) |
| CVE-2021-45452 | path | missed (44) | missed (54) | missed (134) |
| CVE-2023-41040 | path | missed (0) | missed (1) | missed (1) |
| CVE-2023-42819 | path | missed (12) | missed (21) | caught, fix flagged (36) |
| CVE-2023-50265 | path | missed, fix flagged (270) | missed, fix flagged (321) | missed, fix flagged (321) |
| CVE-2024-27132 | xss | missed (43) | missed (73) | missed (73) |
| CVE-2024-27133 | xss | missed (43) | missed (73) | missed (73) |
| CVE-2024-31462 | path | missed (0) | missed (25) | missed (25) |
| CVE-2024-39877 | code | missed (650) | caught, fix clean (1316) | caught, fix clean (1323) |
| CVE-2024-41656 | xss | missed (30) | missed (37) | missed (116) |
| CVE-2024-41675 | xss | missed (0) | missed (0) | missed (16) |
| **total** | | **0 caught, 0 with fix clean; 1 fixed trees flagged; 1144 findings** | **1 caught, 1 with fix clean; 1 fixed trees flagged; 2030 findings** | **2 caught, 1 with fix clean; 2 fixed trees flagged; 2231 findings** |

Dev split (the 16 CVEs the fixes were designed from; development evidence, not proof):

| Dev CVE | class | frozen engine (90a9ea8) | new engine (6d543e2) | + web pack (038f983) |
|---|---|---|---|---|
| CVE-2019-1010259 | sqli | missed (37) | missed (101) | missed (101) |
| CVE-2021-34363 | path | caught, fix flagged (4) | caught, fix flagged (5) | caught, fix flagged (5) |
| CVE-2021-39207 | deser | missed (98) | caught, fix clean (205) | caught, fix clean (205) |
| CVE-2022-24065 | cmdi | missed (8) | missed (8) | missed (8) |
| CVE-2022-28347 | sqli | missed (44) | missed (54) | missed (134) |
| CVE-2023-37274 | code | missed (0) | missed (6) | missed (23) |
| CVE-2023-40581 | cmdi | missed (29) | caught, fix clean (34) | caught, fix clean (34) |
| CVE-2023-50943 | deser | missed (481) | caught, fix flagged (974) | caught, fix flagged (981) |
| CVE-2023-6709 | code | missed (43) | caught, fix clean (75) | caught, fix clean (75) |
| CVE-2024-21520 | xss | missed (0) | missed (1) | missed (1) |
| CVE-2024-37058 | deser | missed (36) | missed (66) | missed (66) |
| CVE-2024-37060 | deser | missed (13) | caught, fix flagged (40) | caught, fix flagged (40) |
| CVE-2024-39330 | path | missed (40) | missed (49) | missed (136) |
| CVE-2024-39863 | xss | missed (650) | missed (1316) | missed (1323) |
| CVE-2024-4181 | code | missed (0) | caught, fix flagged (24) | caught, fix flagged (24) |
| CVE-2024-41950 | code | missed (0) | caught, fix clean (9) | caught, fix clean (9) |
| **total** | | **1 caught, 0 with fix clean; 1 fixed trees flagged; 1483 findings** | **8 caught, 4 with fix clean; 4 fixed trees flagged; 2967 findings** | **8 caught, 4 with fix clean; 4 fixed trees flagged; 3165 findings** |

Precision: "fix flagged" is a finding of the CVE's class still in a target function after the fix: the fix is a
check or restructuring the engine does not see as closing the flow (not verified case by case, and held-out code is
not read). The cost shows in the counts: the new sources roughly double what is reported on large libraries
(airflow 650 -> 1316; dev total 1483 -> 2967, held-out 1144 -> 2030). Broken down on one dev tree (mlflow, 43 -> 82):
library input 19 (16 deserialization, 2 command, 1 template), remote replies 18. These are weak-source findings
(review lane, never `confirmed` on their own): the verifier and the triage model exist to rank and remove them, and
their cost is what the live pipeline has to absorb. Engine-only counts here are an upper bound on what a user sees.

What this does and does not show:
- The causes were real and general. Fixing them moved the dev split from 1 to 8 caught (4 with the fix clean), and on
  code it had never seen the engine went from 0 to 1 of 12 (airflow `DAG.get_doc_md` template injection, fixed tree
  clean), with no model calls.
- Most of the held-out misses are path traversal and XSS in web applications (Django, Flask, Gradio). Engine-only, the
  engine knows Flask's request object and nothing else about routing; the curated web pack adds documented routing
  (Django URLconf, Flask/FastAPI registration, class-based views). On the held-out split it adds one catch (jumpserver,
  path traversal through a Django view) but with the fixed tree still flagged, so no new clean catch; it also adds
  findings on the Django-based trees (sentry 37 -> 116, django 54 -> 134). In the product the frontier learns the rest per repository; that is the
  live run still to do on this split.
- The held-out split has no deserialization, SQL or command-injection CVEs (no buildable rows left), so it cannot
  confirm the library-input and deserialization gains from the dev split.
- 12 CVEs is small; one caught case is a signal, not a rate.

## Stored data (second-order flows, RIPS-style)

Writes and reads are matched by table (SQL `INSERT/UPDATE` vs `SELECT ... FROM`), ORM model (constructor /
`objects.create` vs `query.*` / `objects.*`) and file path (an upload saved / a file written, then opened through the
same path value). A read is a source only if attacker data was written there: a table filled with constants is not
(tests/test_stored.py). PySASTBench, engine only: recall 0.450 -> 0.483 (+4 deserialization of uploaded files), no new
false positive. The stored-XSS cases there sit mostly in frameworks the engine has not learned yet (next: framework
knowledge packs + learning across repositories).

## Template engines (XSS)

One adapter per engine, from its documented escaping rules (sentinel/extract/templates.py): Jinja2 (`|safe`,
`{% autoescape false %}`, `jinja2.Template` / `Environment` without autoescape), Django (`|safe`, `{% autoescape off %}`),
Tornado (`{% raw %}`, `{% autoescape None %}`), Bottle (`{{!x}}`), Mako (`${x}` unless `| h`). Render calls of Flask,
Quart, Django, Starlette/FastAPI, aiohttp-jinja2, Tornado, Bottle, Jinja2 and Mako are recognised; templates come from
inline strings, constants or template files; loop/set aliases are followed (`{% for c in comments %}{{ c.body|safe }}`
-> `comments`). Only the value passed for a raw variable becomes a sink (tests/test_templates.py checks every engine,
raw and escaped). Objects built from tainted arguments now carry them (templates read `post.content` off objects).

Measured on the held-out half (engine only, learned pack, no model calls): recall 0.617 -> 0.650, precision 0.95, F1
0.747 -> 0.772; full benchmark engine-only recall 0.483 -> 0.500. No change in findings on six real repositories. The
held-out XSS misses are blocked upstream, not at the template: all nine have no source until the framework is learned
(Django, Pyramid, Falcon, Quart, FastAPI, Tornado request APIs) and several return HTML through framework response
objects the training half never met (Django `HttpResponse`, Falcon `resp.text`). Live, with the frontier, those are
questions; engine-only they need the pack to have seen them.

## Learning frameworks from repositories (transfer, PySASTBench)

Split by case number: the odd half is scanned live (frontier + verification) in one store, and what it learned is
exported as a candidate knowledge pack (`knowledge/candidates/pysastbench-train-half.yml`, 87 facts: 11 framework
entry points such as `cherrypy.expose`, FastAPI/Sanic routes, Pyramid `view_config`; 11 source APIs such as Bottle
`request.forms.get` and Tornado `request.body`; 13 sink APIs such as `sanic.response.html`, Tornado `write`, Pyramid
`HTTPFound`; 45 negative answers that save future questions). The even half, never seen during learning, is then
scanned by the engine alone, with no model calls, with and without that pack.

| Even half (120 files), engine only, no model calls | Precision | Recall | F1 |
|---|---|---|---|
| No learned knowledge | 0.938 | 0.500 | 0.652 |
| With the pack learned from the odd half | 0.949 | 0.617 | 0.747 |

Learning on the odd half cost $8.07 live (856 calls; that run itself scored P 0.979, R 0.767). SQL injection on
unseen files went from 1 to 6 found, code injection from 4 to 6. XSS stayed at 0/10: the unseen files use APIs the
odd half never asked about (Django `HttpResponse` with an f-string, Quart handlers returning HTML), which the next
repositories that use them will teach. A reviewer would drop a few candidates (`tarfile.is_tarfile` as a path
sink); packs are reviewed before they ship, and every pack fact still passes the canary gate on load.

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
