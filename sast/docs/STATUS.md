# STATUS — neurosymbolic SAST POC

Running plan/status, updated every loop iteration so work can resume from here.

## Phases
1. [x] Literature review — 5 parallel research tracks -> docs/lit/*.md, synthesized into docs/literature.md
2. [x] Architecture — docs/architecture.md
3. [x] Build (POC complete; polishing) — scanner pipeline, logic engine, mocked agent, flywheel, persistence, triage UI, tests, demo codebase, E2E + screenshots

## Log
- Iter 1: branch created; research tracks launched (taint-spec inference, LLM FP filtering, Datalog/logic analysis, triage learning & UX, neurosymbolic/agentic); semgrep toolchain probe.

## Empirical notes
- semgrep 1.182.1 OSS: taint mode is **intraprocedural only** — a source in `view()` flowing into `run_query(q)` -> `execute(q)` is NOT reported; inline flow is. `--dataflow-traces` gives no trace in OSS JSON (fingerprint/lines say "requires login").
  => Implication: Semgrep is best used as a *fact/spec matcher* (sources, sinks, sanitizers, calls) whose matches become Datalog base facts; interprocedural taint + provenance (explanations) must live in our logic layer. This is the IRIS-style split.
- Network: arxiv.org, openreview.net, dl.acm.org, usenix.org, semanticscholar, openalex, semgrep.dev are **blocked** by the environment network policy (DNS/403). WebSearch works; github.com + raw.githubusercontent.com work. => Paper claims come from search-result paper text and GitHub artifact repos (READMEs/PDFs); unverified numbers are tagged in docs/lit/*. Plan: after the 5 tracks land, a verification pass for load-bearing claims via GitHub-hosted artifacts (paper repos, semgrep/semgrep-docs).
- Track 01 (taint-spec inference) DONE.
- Track 04 (triage learning & UX) DONE — key numbers: Google <10% effective FP bar; FB diff-time fix rate >70% vs ~0% batch; Bingo -44.2% alarms inspected; 50.8% of suppressions match no warning.
- Track 05 (neurosymbolic & agentic) DONE — no published system reaches very low FP on real code (IRIS FDR 84.8%, NESA 66% prec, RepoAudit 78%); precision comes from symbolic confirmation of LLM claims; AIxCC top teams act only with PoV; Theori arch ~ ours.
- Track 02 (LLM FP filtering) DONE — LLM4PFA 94-98% FP elimination @ $0.001-0.12/alarm; no vendor publishes FN rate; synthetic-benchmark rankings do not transfer (ZeroFalse gemini F1 0.91 OWASP -> 0.37 real); Juliet memorised. Verdicts must be typed+evidenced facts re-checked by Datalog.
- Track 03 (Datalog/logic) DONE — recommendation: clingo as stratified Datalog + provenance via auto-generated fire/N twins (verified working with clingo 5.8.2 ast API); Python BP layer for Bingo-style ranking.
- Iter 2: docs/literature.md (synthesis, R1-R16) and docs/architecture.md written. Semgrep moved to its own venv (.venv-semgrep) due to opentelemetry pin conflict with FastAPI.

## Build plan (phase 3) — done
- [x] demo corpus (acme-shop, acme-billing, acme_common) + ground_truth.yaml (outside scanned trees)
- [x] specs/ Semgrep spec pack + generated Semgrep-OSS taint baseline
- [x] extract/python_facts.py (reaching defs, guard refinement nodes, routes/converters) + semgrep_specs.py
- [x] engine: clingo stratified Datalog, provenance via fire twins, summary-based interprocedural taint, decision layer
- [x] store (SQLite), agent (interfaces, mock, Claude client, gates), learn (knowledge lifecycle + gates, Bayes BP)
- [x] pipeline (Tier 0/1/2, Tier-2 verdict cache, shadow eval, audit sampling), triage service, explanations
- [x] API (FastAPI) + UI (React/TS: inbox, evidence, triage rail w/ impact preview, knowledge workbench, insights, activity)
- [x] tests: 96 passing (unit, integration, eval regression, offline Claude client); Playwright screenshots
- [x] docs/evaluation.md, README.md

## Iteration log (build)
- Iter 3: corpus, specs, extractor, engine. Tier-0 matches GT (all TPs found; FPs only as undecided).
- Iter 4: neural tiers + gates + knowledge + Bayes + pipeline; eval harness (S0 .64/.64 -> S3 1.0/1.0 with mock).
- Iter 5: API + UI; test agent found 4 real bugs (proof lookup quoting, host allow-list rebinding, chained str methods, rescans counted as corroboration) — fixed.
- Iter 6: Tier-2 cache by content hash; scan triggers; honest flywheel demo (billing onboarded after shop review: 46% -> 55% engine-decided); Claude client + offline tests.

## Next ideas (if continuing)
- E2E Playwright triage flow test (x -> reason -> commit -> knowledge active -> other repo resolved).
- Remaining UX: diff lenses (new since last scan), suppression-health view, PR-time surface.
- Engine: method resolution on objects, context-sensitive summaries, Soufflé backend for scale.
