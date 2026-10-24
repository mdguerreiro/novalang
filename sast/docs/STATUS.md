# STATUS — neurosymbolic SAST POC

Running plan/status, updated every loop iteration so work can resume from here.

## Phases
1. [ ] Literature review — 5 parallel research tracks -> docs/lit/*.md, synthesized into docs/literature.md
2. [ ] Architecture — docs/architecture.md
3. [ ] Build — scanner pipeline, logic engine, mocked agent, flywheel, persistence, triage UI, tests, demo codebase, E2E + screenshots

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
