# Architecture: a neurosymbolic SAST with a triage data flywheel

Working name: **Sentinel**. This doc says what we build and why. Requirements `R1`–`R16` come from `docs/literature.md` §2.

## 0. Goals and non-goals

**Goals**
1. **Very low false positives at a fixed, measured recall.** Precision comes from the engine *proving* most decisions and an evidence-gated agent handling the rest, not from trusting a model (R1, R3, R5).
2. **A data flywheel.** Every agent verdict and every human triage decision becomes structured, versioned, testable knowledge that the deterministic engine reuses on the next scan, in the next repository, and (for public APIs) for the next customer (R10, R11, R14). The flywheel KPI is that **Tier-0 decision rate goes up and agent cost per finding goes down** over successive scans.
3. **Best-in-market triage UX:** evidence-first, keyboard-first, root-cause bulk triage, impact previews, calibrated confidence, and an audit trail on everything hidden (R12, R15).

**Non-goals for the POC**
- Multiple languages (Python/Flask only; the front-end is pluggable).
- Production scale (clingo in-process; Soufflé is the scale-up path).
- A real LLM. The agent is **mocked behind the production interface**, and a Claude client can be dropped in.

## 1. The core decision: who decides what

```
                 ┌───────────────────────────── knowledge store (SQLite) ──────────────────────────────┐
                 │  spec packs (Semgrep YAML) · learned facts · rule weights · verdicts · audit log     │
                 └───────▲──────────────────────────────▲───────────────────────────────▲──────────────┘
                         │ active knowledge             │ candidate/shadow knowledge    │ triage events
  repo ──► ① FACT EXTRACTION ──► ② LOGIC ENGINE ──► ③ DECISION ──► ④ NEURAL TIERS ──► ⑤ FLYWHEEL ◄── ⑥ TRIAGE UI
           Semgrep spec match     clingo Datalog     Tier 0:          Tier 1: neural       gates: hash,      evidence-first
           + Python AST facts     + provenance       PROVEN_SAFE      predicates (lazy)    symbolic re-       keyboard triage
                                  ("fire" twins)     CONFIRMED        Tier 2: verifier     derivation,        impact preview
                                                     UNDECIDED ──────►agent (k votes,      canary replay,     knowledge
                                                                       tools, claims)      impact budget,     workbench
                                                                                           shadow → active
```

| Question | Decided by | Why |
|---|---|---|
| Does tainted data reach this sink, across functions? | **Datalog** (compositional summaries) | R1. LLMs fail at global reachability. Semgrep OSS is intraprocedural (verified empirically). |
| Is this API a source, sink, sanitizer or propagator? | Curated Semgrep spec packs → **learned facts** → Tier-1 neural predicate if unknown | R2, R4, R7. Narrow, typed, cacheable questions. |
| Is this finding mitigated? | **Datalog**, from facts. An agent or human may *add facts*, but the engine re-derives the mitigation. | R3. Proof-carrying suppressions. |
| Is this finding exploitable in context (reachable route, attacker-controlled)? | Engine where it can see it (entrypoints, route converters, type annotations). Otherwise the **Tier-2 agent**, gated. | R5, R6 |
| What should a human look at next? | **Bayesian posterior** over the derivation graph (Bingo), calibrated per class | R9, R15 |
| Does a learned item become active? | **Gates**: symbolic re-derivation, canary replay, impact budget, scope rules, human approval for widening | R11, R12 |

## 2. Fact extraction (①)

Two front-ends feed the extensional database (EDB):

**2.1 Semgrep as specification matcher.** Sources, sinks, sanitizers and propagators are written as ordinary Semgrep rules (`specs/*.yml`) with a `metadata.sentinel` block:

```yaml
- id: spec.sink.sqli.dbapi-execute
  languages: [python]
  severity: INFO
  message: sink
  metadata: {sentinel: {role: sink, cls: sqli, cwe: CWE-89}}
  patterns:
    - pattern: $CUR.execute($Q, ...)
    - focus-metavariable: $Q
```

Semgrep is the base matching layer because its pattern language is what customers and LLMs already write. Spec rules are **deterministic artifacts**: an LLM or a human can propose one, and `semgrep --test` plus our canaries can check it (literature §1.4). Matches are joined to AST expression nodes by exact source span (falling back to the smallest enclosing expression). The *same* Semgrep taint rules also run in standard taint mode to give the **baseline** we evaluate against.

**2.2 Python AST extractor** (`sentinel/extract/python_facts.py`). This emits the program structure Semgrep does not expose: expression nodes and value-flow edges, assignments, calls with resolved targets, parameters, returns, entrypoints (Flask route decorators, including path converters such as `<int:id>`), **guards** (early-exit and branch-dominance patterns over `isdigit/isalnum/in ALLOWLIST/re.fullmatch/isinstance`), type annotations, and file classification (test, migration, generated). Literature §7.3 of track 03 notes that **fact quality dominates** what the engine can prove, so most engineering time goes here.

**2.3 EDB schema** (core relations; all IDs are interned strings)

```
% program structure
func(Fn, File, Line).            param(Fn, I, Var).           ret(Fn, E).
expr(E, Fn, File, L1, C1, L2, C2).                             reads(E, Var).
assign(Var, E).                  flow(E1, E2).                 % value of E1 flows into E2 (concat, format, f-string, container, attr base, ...)
call(E, Fn, Callee).             arg(E, I, A).                 kwarg(E, Key, A).
calls(E, Fn2).                   % resolved call target (user function)
entrypoint(Fn, Kind).            route_param(Fn, Var, Converter).
guard(E, Var, Pred).             % E is dominated by a successful Pred(Var) test
annot(Fn, Var, Type).            file_kind(File, Kind).        % test|migration|generated|app
% specifications (from Semgrep matches + knowledge store)
source_at(E, SrcKind).           sink_at(E, Cls).              sanitizer_at(E, Cls).
sanitizer_api(Callee, Cls).      propagator_api(Callee).       safe_pred(Pred, Cls).   safe_type(Type, Cls).
unknown_api(E, Callee).          % call to an unmodelled library function (assumption point)
```

## 3. Logic engine (②)

**3.1 Engine choice: clingo used as stratified Datalog, with provenance by rule instrumentation.** This follows track 03 §7.1:
- It ships as a pip wheel, is the fastest embeddable option measured (0.07 s on a 3k-node reachability test vs 1.2 s for pyDatalog), and supports stratified negation and aggregates.
- We parse rules with `clingo.ast` and generate a **`fire(RuleId, Head, Body…)` twin for every rule**. Every grounded rule instance is then recorded, giving the **full derivation hypergraph**, not just a single proof (R8). We verified this works.
- Negated premises are recorded as `absent(...)`, so explanations can say "no sanitizer applied on this path".
- Rejected: Prolog, because LLM-edited rules risk non-termination and order dependence. ProbLog is kept for slices only, because exact inference timed out at 400 nodes. Scallop needs a nightly Rust build. Soufflé has no Python bindings, but the rule base avoids ASP-only features so it ports to Soufflé `.dl` for scale.

**3.2 Taint analysis as compositional Datalog.** Taint carries a **source** and a **vulnerability class**. Sanitizers are class-specific (R4): `html.escape` kills `xss` but not `sqli`. Three relations run in parallel:

```
traw(E, S)          % E carries data from source S, ignoring all sanitizers (the "raw" flow)
t(E, S, C)          % E carries data from S that is still dangerous for class C
tk(E, S, C, Why)    % the C-danger from S was neutralised by Why on the way to E
```

Interprocedural flow uses **summaries**, so call/return paths stay realizable:

```
pt(E, Fn, I, C)          % E (inside Fn) carries parameter I for class C   (parameter-as-pseudo-source)
p2r(Fn, I, C)            % summary: param I of Fn reaches its return, still dangerous for C
p2s(Fn, I, C, SinkE)     % summary: param I of Fn reaches sink SinkE (possibly through further calls)
t(CallE, S, C)  :- calls(CallE, Fn), arg(CallE, I, A), t(A, S, C), p2r(Fn, I, C).
cand_inter(S, SinkE, C, CallE) :- calls(CallE, Fn), arg(CallE, I, A), traw(A, S), p2s_raw(Fn, I, C, SinkE).
```

The **assumption points** are what make findings undecided: an unknown library call that we assume propagates taint, a guard predicate whose semantics we do not know (for example a regex), an unresolved dynamic call, or a weak source kind such as headers or environment. Each is recorded as `assume(S, SinkE, C, A)` along the path.

**3.3 Decision layer (Tier 0)** (`sentinel/engine/rules/decide.lp`)

```
candidate(S, K, C)  :- traw(K, S), sink_at(K, C).                         % a raw source→sink flow exists
alarm(S, K, C)      :- t(K, S, C), sink_at(K, C).
mitigated(S,K,C,W)  :- candidate(S,K,C), not alarm(S,K,C), tk(K,S,C,W).   % proof-carrying: W names the mitigation
test_only(S,K,C)    :- candidate(S,K,C), expr(K,_,F,_,_,_,_), file_kind(F,test).
undecided(S,K,C,A)  :- alarm(S,K,C), assume(S,K,C,A).
confirmed(S,K,C)    :- alarm(S,K,C), not has_assume(S,K,C), strong_source(S), not test_only(S,K,C).
```

Every candidate gets exactly one status:
- **PROVEN_SAFE**: mitigated, with the mitigating fact named. Shown in the "Suppressed (proved)" lane, never deleted (R12).
- **CONFIRMED**: the engine found a clean path with no assumptions.
- **UNDECIDED**: sent to the neural tiers with the exact list of assumptions to resolve.
- **TEST_ONLY**: kept, at low priority.

## 4. Neural tiers (④): mocked, behind production interfaces

**4.1 Tier 1: neural predicates (`SpecOracle`).** These are lazy, typed questions about a single API or predicate, asked only for assumptions on undecided paths (R2):
- `classify_api(callee, context) → {role: propagator|sanitizer(cls)|source|sink(cls)|neutral, confidence}`
- `judge_guard(pred_src, cls) → {safe_for: [cls…], confidence}` (for example "does `re.fullmatch(r'[a-z0-9_]+', x)` block SQLi?")

Answers are cached by `(api, package, version, prompt_version)`. They are proposed as **knowledge items at global scope in *candidate* state** and are not trusted until the gates admit them (§5). The **mock** answers from a curated table, mimicking a model's calibrated output including deliberate errors, so the gates are exercised.

**4.2 Tier 2: verifier agent (`Verifier`).** Input: the finding, its minimal proof tree (BFS over `fire`), code spans, and tool access:

| Tool | Purpose |
|---|---|
| `read_span(file, l1, l2)` | Returns code and its **sha256** for citations. |
| `datalog_query(goal)` | Ask the engine. |
| `what_if(add_facts)` | Counterfactual re-evaluation: would this fact make the finding PROVEN_SAFE? Which other findings would change? |
| `semgrep_run(rule)` | Search for sibling sites. |
| `retrieve_memory(signature)` | Past verdicts on similar findings (hints only, R13). |
| `abstain(reason)` | Explicitly decline to decide. |

Output is the structured **verdict schema** (track 05 §G3):

```json
{"finding": "…", "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_HUMAN|ABSTAIN", "cls": "sqli",
 "reason_code": "SANITIZED|GUARDED|NOT_ATTACKER_CONTROLLED|UNREACHABLE|TEST_CODE|SAFE_TYPE|null",
 "claims": [{"id": "c1", "kind": "sanitizer", "statement": "…", "cite": {"file": "…", "l1": 9, "l2": 9, "sha256": "…"},
             "fact": {"pred": "sanitizer_api", "args": ["acme_common.db.quote_sql", "sqli"]}}],
 "proposed_knowledge": [{"pred": "sanitizer_api", "args": [...], "scope": "org"}],
 "votes": {"k": 5, "agree": 5}, "confidence": 0.94, "rationale": "…", "cost": {...}}
```

**4.3 Orchestrator gates.** The orchestrator code applies these, never the LLM (R3, R5, R6, R13):
1. **Citation check:** every cited span's hash must match the scanned file. A mismatch rejects the verdict (catches hallucinated code).
2. **Symbolic discharge of an FP:** the engine is re-run with the claim's facts added (`what_if`). The FP verdict stands only if the finding becomes PROVEN_SAFE, meaning the engine reproduces the agent's argument. Otherwise it is downgraded to NEEDS_HUMAN.
3. **Counterfactual load-bearing check:** after the proposed sanitizer is ablated, the engine must still derive the raw flow, which shows the claim concerns this path.
4. **Voting:** suppression needs a unanimous FP among k samples; a TP needs a majority. Anything else is NEEDS_HUMAN. Thresholds are asymmetric to protect recall.
5. **Rationale is not evidence:** only cited spans plus re-derived facts count. Comment text is stripped from the agent's view of code in the real client.
6. **Policy:** classes and rules marked `never_auto_suppress` (for example authz and crypto) always go to a human.

A gated FP verdict suppresses **that finding** (lane "Suppressed by agent — proof attached"). Its proposed knowledge enters the flywheel as a candidate.

**4.4 Real client.** `ClaudeVerifier` and `ClaudeSpecOracle` implement the same interfaces using the Anthropic Messages API with tool use, a JSON-schema-constrained final answer, and `k` samples. They are activated by `SENTINEL_LLM=claude` plus `ANTHROPIC_API_KEY`. They are not exercised in this POC.

## 5. The flywheel (⑤)

**5.1 Knowledge items** (`knowledge` table) are the only way the engine changes behaviour:

| Field | Values |
|---|---|
| `kind` | `sanitizer_api`, `propagator_api`, `source_api`, `sink_api`, `safe_pred`, `safe_type`, `exposure` (route not internet-facing), `test_path`, `spec_rule` (a Semgrep YAML spec), `rule_weight` |
| `scope` | `finding:<fp>` ⊂ `repo:<id>` ⊂ `org:<id>` ⊂ `global` |
| `status` | `candidate → shadow → active → retired` |
| `origin` | `curated` / `agent:<model>` / `oracle:<model>` / `human:<user>` |
| `provenance` | links to the verdicts and triage events that created or support it |
| `gate_report` | canary replay result, impact delta, conflicts |

**5.2 Signal → knowledge mapping** (R10, track 04 synthesis 1)

| Signal | Becomes |
|---|---|
| Human triage "Not exploitable: sanitized by `f`" | `sanitizer_api(f, cls)`. Repo scope by default, org scope if `f` is defined in a shared internal package. |
| "Validated by guard" | `safe_pred(pred, cls)` |
| "Not exposed / dead route" | `exposure(fn, internal)` at repo scope; never a rule change. |
| "Test code" | `test_path(glob)` at repo/org scope. |
| "Rule is wrong" | A `spec_rule` refinement proposal plus a regression fixture. Needs rule-owner review. |
| "Accepted risk" | Governance only (owner, expiry). **No correctness learning.** |
| "Confirmed" | Positive evidence: raises `rule_weight` and adds a canary (a regression TP). |
| Agent FP verdict (gated) | Candidate knowledge from `proposed_knowledge`. Needs N corroborating verdicts or human approval to go beyond the finding. |
| Tier-1 oracle answer | Candidate global knowledge. Shadow mode until corroborated. |
| Reopen / regression on a suppressed finding | **Retract** the knowledge, re-open everything derived from it (provenance), and audit. |

**5.3 Gates** (R11). A knowledge item moves from *candidate* to *active* only if all of these pass:
1. **Symbolic sanity:** the item parses and type-checks against relation signatures. For `spec_rule` items, Semgrep validates the rule.
2. **Canary replay:** the engine runs with the item over the canary set (seeded vulnerable fixtures plus every human-confirmed TP). **Any lost TP blocks activation.**
3. **Impact budget:** if the item would suppress more than `N` findings, or more than `X%` of a rule's findings, it goes to **shadow** (findings are labelled "would be suppressed by K-12", not hidden) and needs approval.
4. **Scope rules:**
   - finding scope: one triager is enough.
   - repo/org: needs an approver, or ≥ k independent agent verdicts with no contradicting human verdict.
   - global: only public-library API facts, corroborated by ≥ k orgs (simulated in the POC). Never customer code (R14).

**5.4 Bayesian ranking** (R9). The `fire` hypergraph becomes a noisy-OR factor graph:
- **Tuple nodes:** OR over the rule instances that derive them.
- **Rule-instance nodes:** AND of their premises, multiplied by the rule weight.
- **Priors on base facts:** 1.0 for structural facts, learned reliability for spec facts, oracle confidence for LLM facts.

Verdicts become evidence on alarm nodes, and loopy belief propagation updates the posterior `P(true positive)` for every other alarm that shares tuples. That is the "you marked one; 6 related findings were re-ranked" moment. Propagation **only re-ranks**; it never suppresses.

**5.5 Calibration.** For each `(cls, rule)` bucket, the posterior is mapped to empirical precision from triage history (binned, with a Beta prior). The UI shows "≈ 91% of findings like this were confirmed (n = 34)", or **"uncalibrated"** when n is small (R15).

**5.6 Retraction and audit.** Every suppressed finding records which knowledge items its proof used (from `fire`). Retiring an item re-runs decisions and re-opens the dependents. A configurable fraction (default 5%) of auto-suppressed findings is sampled into an **audit queue**, and audit results give the **measured false-negative rate** shown on the Insights page (R12).

**5.7 Learned spec rules** (`sentinel/learn/rules.py`). A `spec_rule` item (ids `R-NNN`) holds one Semgrep rule in the shape of the curated pack, plus its validation pair and the originating call site. These are stored in `knowledge.payload`. Facts are keyed by callee name; rules describe code shape. They model a shared helper in repos that install the package without its source, and they export to plain Semgrep.
- **Triggers.**
  - A confirmed finding (human, or a gated agent TP) whose sink lies inside a shared helper proposes a sink rule focused on the parameter the flow enters by.
  - A sanitizer judgement (human `SANITIZED` at org scope, or a gated agent FP verdict) proposes a sanitizer rule.
- **Synthesizer.** `RuleSynthesizer.propose(RuleContext, tools) -> [RuleProposal]`. There are two implementations: a template mock, and `ClaudeRuleSynthesizer` (one structured-output call).
- **Gates.** All must pass before an item leaves `candidate`:
  1. Sanity, including Semgrep accepting the rule.
  2. Patch differential: the full engine runs on the vulnerable and fixed examples, with and without the rule.
  3. Generalization: the rule matches the originating site.
  4. Canaries plus an FP budget on the reference corpora (`Policy.rule_fp_budget`).

  The gate also reports impact on the repos in scope, as for facts.
- **Lifecycle.** Synthesized rules are machine knowledge: shadow until approved or corroborated. Rules written by a human (`POST /api/rules`) activate when their gates pass. Active rules are matched per repo and cached on the rule set. Shadow rules are evaluated only: sanitizer rules set `shadow_by`, and sink rules report the findings they would add (`shadow_rule_findings` in scan stats). A sink rule is not applied in a repo that contains the helper's body, since the engine already sees the real sink there.
- **Export.** `export-rules` / `GET /api/rules/export` returns the curated pack plus active learned rules: as spec rules, or as Semgrep OSS taint rules.

## 6. Persistence

SQLite, one file per deployment, accessed through stdlib `sqlite3` behind a small repository layer:
- `orgs`, `repos`
- `scans(id, repo, started, stats_json)`
- `files(repo, path, sha256, content)` — snapshot, so the UI shows the exact scanned code
- `findings(fingerprint, repo, cls, cwe, rule, source_*, sink_*, status, lane, posterior, …)`
- `finding_scans`
- `paths(finding, step, file, line, col, kind, label)`
- `proofs(finding, json)`
- `verdicts(id, finding, actor, kind, verdict, reason_code, evidence_json, created)`
- `knowledge(id, kind, args_json, scope, status, origin, gate_json, created, payload_json, …)` (`payload`: spec rule YAML and validation pair; added by migration to existing databases)
- `knowledge_links(knowledge, verdict|finding, relation)`
- `events(id, ts, actor, type, payload_json)` — append-only audit log

**Fingerprints are semantic**, so triage survives refactors, line moves and rule upgrades: `hash(cls, source callee + enclosing function, sink callee + enclosing function, normalized sink argument shape)`.

## 7. API and UI (⑥)

**Backend:** FastAPI (`sentinel/api`), JSON over HTTP. **Frontend:** React + TypeScript + Vite, with hand-built design tokens (light and dark) and syntax highlighting. It is served as static files by the API.

**Screens and features** (R15; P0/P1 from track 04 synthesis 2):
1. **Inbox (triage).** A three-pane layout: queue, evidence, actions.
   - The queue is ordered by information gain (posterior near 0.5 × severity), with lanes: *Needs review*, *Confirmed*, *Suppressed (proved)*, *Suppressed by agent*, *Shadow*, *Audit*.
   - **Keyboard first:** `j/k` move, `c` confirm, `x` not exploitable (opens a reason picker with evidence), `.` apply to the whole root-cause group, `u` undo, `s` snooze, `/` search, `?` help.
2. **Evidence view.**
   - The source → … → sink trace drawn over the **real code**, with each step highlighted inline.
   - A **"Why this is a finding"** card (the minimal proof tree in plain language).
   - A **"Why it might not be"** card: each candidate mitigation the engine checked and why it was rejected, plus the counterfactual ("would be proved safe if `quote_sql` were a SQL sanitizer").
   - The agent's verdict with claims and ✓/✗ symbolic-check badges, votes and calibrated confidence.
3. **Impact preview.** Before a verdict that teaches the engine is committed, a sheet shows the knowledge item it creates, the findings it would resolve across repos, the canary replay result and any conflicts. Large impact defaults to shadow mode.
4. **Root-cause groups.** Findings clustered by shared derivation cut (same sink helper, same unknown API, same missing-sanitizer hypothesis), with one-shot group triage and per-member exceptions.
5. **Knowledge workbench.** Every learned item, with provenance ("created from triage of 3 findings by alice, corroborated by 2 agent verdicts"), status, gate report, and promote / demote / retire with live effect.
6. **Insights.** Flywheel KPIs per scan: Tier-0 decision rate, agent calls per finding, findings auto-resolved by learned knowledge, measured precision, audited FN rate, effective FP rate, time to triage.

## 8. Evaluation plan (R16)

- **Corpus:** `demo/` contains two repositories from one fictional customer (`acme-shop`, `acme-billing`) that share an internal package. Each has realistic vulnerabilities and **FP traps**:
  - a custom sanitizer
  - `isdigit` guards
  - `<int:id>` converters
  - `int()` casts
  - parameterized queries
  - `subprocess` with list args and `shlex.quote`
  - `os.path.basename`
  - an allow-listed SSRF
  - `markupsafe.escape`
  - `yaml.safe_load`
  - test-only code, dead routes
  - interprocedural flows through helpers

  Ground truth lives in `demo/ground_truth.yaml`, **outside** the scanned tree, so it cannot leak into the agent's view.
- **Stages measured:**
  1. Semgrep OSS taint baseline
  2. Engine Tier 0
  3. + Tier 1 oracle
  4. + Tier 2 agent (mock)
  5. After triage of repo A, a **fresh scan of repo B** (cross-repo transfer: the flywheel effect)
- **Metrics:** precision, recall, FDR, coverage (fraction decided without a human), agent calls, canary losses.
- **Caveat:** with a mocked agent these numbers validate the *machinery*, not model quality. A real-model evaluation needs a key, real repos and post-cutoff alerts.

## 9. Code layout

```
sast/
  sentinel/
    extract/      python_facts.py, semgrep_specs.py
    engine/       datalog.py (clingo + provenance), rules/*.lp, taint.py (decisions + paths + proofs)
    agent/        interfaces.py, mock.py, claude.py, orchestrator.py (gates)
    learn/        knowledge.py (lifecycle + gates), bayes.py (BP ranking), calibrate.py
    store/        db.py (schema + repositories)
    api/          app.py (FastAPI)
    pipeline.py   scan orchestration (Tier 0 → 1 → 2)
    cli.py        sentinel scan|serve|eval|demo
  specs/          Semgrep spec packs (sources/sinks/sanitizers) + baseline taint rules
  demo/           acme-shop, acme-billing, acme_common, ground_truth.yaml
  ui/             React app
  tests/          unit + integration + E2E (Playwright screenshots)
  docs/           literature.md, lit/*, architecture.md, STATUS.md
```

## 10. Production roadmap (beyond the POC)

1. Tree-sitter/CPG front-ends for JS/TS, Java and Go. The Semgrep spec packs are already multi-language.
2. Soufflé backend generated from the same rule IR; incremental evaluation on diffs (IncA/DDlog ideas) for PR-time scans.
3. Real Claude verifier with k-sample voting across model families; per-CWE model selection on the eval gate.
4. Execution oracles (sink-hooked harnesses) for Tier 3 on high-severity injection classes.
5. A PR-time surface (high-precision tier only, "Not useful" button feeding rule probation at ≥10%).
6. A federated global knowledge tier with k-anonymity across tenants.
