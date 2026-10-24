# State of the art: neurosymbolic SAST, LLM verification, and learning from triage

This document combines five research tracks into the design requirements for our scanner. The detailed per-paper notes are in `docs/lit/`, with full citations, numbers, limitations and a "design implication" for every entry:

| Track | File | Coverage |
|---|---|---|
| 01 | [`lit/01-llm-taint-spec-inference.md`](lit/01-llm-taint-spec-inference.md) | IRIS, SemTaint, Artemis, LATTE, AdaTaint, LLMDFA, LLMSA/NESA, LLift, BugLens, KNighter, MoCQ, QLPro, QLCoder, Autogrep; Merlin, Seldon, USpec |
| 02 | [`lit/02-llm-fp-filtering.md`](lit/02-llm-fp-filtering.md) | LLM4SA, LLM4FPM, LLM4PFA, Tencent ICSE-SEIP'26, ZeroFalse, Sifting the Noise, LASAA, Chapman et al.; Semgrep Assistant/Memories, Copilot Autofix, Snyk, Corgea, ZeroPath, Datadog, Vulnhalla; 13 benchmarks rated |
| 03 | [`lit/03-datalog-logic-analysis.md`](lit/03-datalog-logic-analysis.md) | Doop, Soufflé (+provenance), CodeQL/QL, Flix, IncA, DDlog, Bingo, Drake, BayeSmith, ALPS, Difflog, ProSynth, Scallop, Semgrep taint internals, Joern/CPG, LogicLoc, NeuroLog; package availability and micro-benchmarks |
| 04 | [`lit/04-triage-learning-and-ux.md`](lit/04-triage-learning-and-ux.md) | Z-Ranking, Kremenek'04, Heckman & Williams, Kang'22, Koc'17, Kharkar'22, Yang/Menzies; Tricorder, Google CACM'18, Facebook CACM'19, Johnson'13, Christakis & Bird'16, Imtiaz'19; suppression studies; SARIF; Checkmarx, Semgrep, GitHub, Veracode, Sonar, Snyk |
| 05 | [`lit/05-neurosymbolic-agentic.md`](lit/05-neurosymbolic-agentic.md) | Naptime, Big Sleep, AIxCC finalists, Vulnhuntr; IRIS, LLMDFA, NESA, LLMxCPG, GPTScan, KNighter, RepoAudit, Lemur, AutoSpec; Vul-RAG, LLM4Vuln; SecLLMHolmes, PrimeVul; FaultLine, PoCGen, CVE-Genie, PoC-validity study, TestGen-LLM |

**About the evidence.** The environment's network policy blocked arxiv.org, openreview.net, dl.acm.org, usenix.org and semgrep.dev during this review. Numbers were taken from paper text quoted in search results, and from GitHub artifact READMEs where those could be fetched. The track files tag each number by source ([PT]/[S] = primary text via search extract, [R] = README read directly, [unverified], [vendor-reported]). Load-bearing numbers should be re-checked against the PDFs before external use. Paper versions also disagree in places: for example, IRIS reports 69/120 detections in arXiv v1 and 55/120 in the ICLR camera-ready.

---

## 1. Where the field stands (late 2026)

**1.1 Pure LLM detection does not work; LLM + symbolic does, but precision on real code is still poor.**
- On their own, LLMs are non-deterministic: answers change between runs and flip under identifier renaming in 17–26% of cases (SecLLMHolmes, S&P'24).
- On clean, de-duplicated labels, function-level F1 collapses from 68% to 3% (PrimeVul, ICSE'25).
- End-to-end LLM detection is the weakest baseline in every hybrid paper (LLMDFA: −0.36 F1).
- The hybrids improve recall: IRIS + GPT-4 finds 55 vs CodeQL's 27 on CWE-Bench-Java.
- **No published neurosymbolic system has low false positives on real repositories:**

| System | Real-code precision |
|---|---|
| IRIS | ~85% false discovery rate |
| NESA/LLMSA | ~66% precision |
| RepoAudit | ~78% precision |
| GPTScan (large projects) | ~57% precision |
| KNighter (after LLM triage) | ~35% FP |

  The numbers that look excellent come from saturated synthetic benchmarks (ZeroFalse F1 0.91 on OWASP Benchmark collapses to 0.37 on real code for the same model) or are vendor-reported (Semgrep "95–96% agreement").

**1.2 The successful pattern: "LLM proposes, symbolic disposes".** Every strong result keeps the global fixpoint (reachability, propagation, path feasibility) symbolic. The LLM only answers narrow, local, typed questions or translates into a checkable form:
- IRIS, SemTaint, LATTE: the LLM labels sources and sinks; CodeQL or taint analysis does reachability.
- NESA: LLM-filled relations inside a Datalog-style policy.
- LLMDFA, LLM4PFA, RepoAudit: the LLM writes Z3 constraints for path feasibility.
- GPTScan: static confirmation removed about two-thirds of LLM false positives.
- Lemur: LLM proposals discharged by a verifier, with a soundness proof.

LLM4PFA's Z3-backed filter removed 94–98% of false positives in the Tencent industrial study, the best result in the cluster, at $0.001–$0.12 per alarm.

**1.3 Inferring specs with an LLM raises recall but hurts precision; guards and sanitizers are where precision is won.**
- LLMs over-label sources and sinks, which is why IRIS doubled recall but kept a ~85% false discovery rate.
- The best precision in the spec-inference cluster (Artemis: 207 true-positive paths vs 15 false-positive) came from modelling guards and path conditions per vulnerability class, plus exploit validation.
- No paper evaluates LLM *sanitizer* inference precision in isolation. That is an open niche.

**1.4 Deterministic artifacts beat verdicts.** Systems where the LLM *writes* checkers or queries are inspectable, testable, cacheable and free of sampling drift: KNighter (Clang checkers from patches), QLCoder/MoCQ/QLPro (CodeQL), Autogrep (Semgrep YAML) and LLMDFA (extractors). Their failure mode is overfitting: Autogrep discarded 71% of its generated rules as over-specific. The fix is the patch-differential oracle (the rule must fire on the vulnerable version and stay silent on the fixed one) plus a false-positive budget on clean code.

**1.5 Agentic verification works only with oracles the agent cannot fake.**
- The two top AIxCC 2025 teams never acted without a working proof of vulnerability.
- Naptime and Big Sleep use controllers and sanitizer oracles.
- A 2026 study found 71.5% of LLM-generated PoCs invalid, including some that pipelines had reported as successes.
- Theori's AIxCC design (static analysis produces candidates, LLM agents judge them) has the same shape as ours.

**1.6 Industry: auto-triage exists, structured learning does not.** Semgrep Assistant reports handling ~60% of triage with Memories, against ~20% without org context. It reports 95–96% user agreement and never auto-closes a finding; filtered findings are hidden but kept for bulk review. Its Memories are **natural-language** context, activated by an admin, with an impact preview. No vendor publishes a **false-negative rate** for its AI triage. No product turns triage into versioned, testable, provenance-tracked engine knowledge.

**1.7 Learning from feedback is old, sound, and under-used.**
- Z-Ranking and Kremenek'04 correlate alarms so one verdict re-ranks related alarms.
- Bingo (PLDI'18) runs Bayesian inference over the Datalog derivation graph, so a single label propagates to every alarm that shares its derivation. It needed 44.2% fewer inspections [S].
- Drake does the same diff-aware; BayeSmith learns model structure across programs.
- Kang et al. (ICSE'22) showed that much of the earlier "learn to classify warnings" accuracy came from data leakage, so evaluation must be time-split and grouped by repository.
- Suppressions rot: 50.8% of suppressions match no warning at all (FSE'25).

**1.8 What practitioners need.**
- Google keeps analyzers below 10% *effective* FP, with probation at a 10% "Not useful" rate. The overall effective rate is just under 5% (Tricorder; CACM'18).
- Facebook: the same analysis had a ~0% fix rate as a nightly dashboard and >70% when shown at diff time (CACM'19).
- Developers tolerate 15–20% FP. "Irrelevant checks on by default" annoys them more than individual false positives, and bad explanations rank #2 among pain points (Christakis & Bird, ASE'16).
- Fixes are small (median 4 lines) but slow (median 96 days), and delay comes from routing (Imtiaz, ISSRE'19).

---

## 2. Design requirements derived from the literature

Each requirement is referenced by the architecture (`docs/architecture.md`).

| # | Requirement | Evidence |
|---|---|---|
| **R1** | The symbolic engine owns reachability, propagation and the final decision. The LLM never decides reachability. | §1.1–1.2; IRIS, NESA, LLMDFA, GPTScan, Lemur |
| **R2** | Ask the LLM narrow, typed, local questions, as **neural predicates evaluated lazily**, only for code on a candidate path. | NESA lazy prompting; Chapman et al.; LLift progressive prompting |
| **R3** | LLM output enters the engine as **typed facts with confidence and provenance**, never as a free-text verdict. A suppression must be **re-derived by the engine** from evidenced facts. | LLM4PFA, NESA, NeuroLog, GPTScan; track 02 L1 |
| **R4** | Prioritise **sanitizer, guard and validator** knowledge over new sources and sinks. Sanitizers are **vulnerability-class specific**. | Artemis, IRIS's 85% FDR; track 01 lesson 2 |
| **R5** | The verifier returns a **structured verdict**: TP / FP / NEEDS_HUMAN / ABSTAIN, with claims citing **hash-checked code spans**, CWE-specific checklists, self-consistency voting and asymmetric thresholds (suppress only on unanimous, evidenced FP). | LASAA, BugLens 0.10→0.72, ZeroFalse CWE prompts, SecLLMHolmes, multi-LLM ensembles |
| **R6** | **Counterfactual checks** on agent claims: removing the claimed sanitizer must make the engine derive the flow; the verdict must not change under renaming; a patched variant must flip the verdict. | SecLLMHolmes, PrimeVul pairing; track 05 G3 |
| **R7** | **Tiered cost control**: cached knowledge → engine decision (Tier 0) → cheap neural predicate (Tier 1) → full agent with tools and voting (Tier 2) → execution or human (Tier 3). Cache by content hash and by (package, version, API, CWE). | Theori funnel, NESA, IRIS small-model result, Tencent costs |
| **R8** | Every derivation carries **provenance**: the full derivation graph, not just one proof. It is used for explanations, Bingo-style feedback propagation and retraction. | Soufflé provenance, Bingo, truth maintenance (Chapman) |
| **R9** | **Bayesian ranking over derivations**: each verdict is evidence on shared intermediate tuples and immediately re-ranks related findings. Propagation can only *re-rank*; *suppression* requires direct evidence. | Bingo, Kremenek'04, BayeSmith over-generalisation risk |
| **R10** | Triage captures **structured reasons with evidence**, each mapped to a specific kind of learned knowledge and scope: sanitized-by → sanitizer model; unreachable → exposure model; test-only → path classifier; rule-wrong → rule refinement; accepted risk → governance only. | Track 04 synthesis 1; Semgrep Memories breakdown (non-prod 25.6%, framework protections 21.9%) |
| **R11** | Learned knowledge is **structured, versioned, scoped** (finding ⊂ repo ⊂ org ⊂ global), with a lifecycle **candidate → shadow → active → retired**, and gated by canary replay, an impact budget and two-person scope escalation. Retraction by provenance re-opens everything downstream. | KNighter/Autogrep gates, TestGen-LLM filter cascade, track 04 guardrails 1–9 |
| **R12** | **Never auto-close.** Suppressed findings remain auditable with their proof. A random sample of auto-suppressed findings is audited, so the **false-negative rate is measured and shown** in the product. | Semgrep (no auto-close), track 02 L5, no vendor publishes FN rate |
| **R13** | **Untrusted-text hygiene**: comments and strings in scanned code, and triage justifications, are data. Rationale text is never evidence. | A10 adversarial comments; track 02 L9 |
| **R14** | **Tenant isolation**: only public-API specs and aggregate rule statistics cross tenants, with k-of-n corroboration. | Track 04 A11 |
| **R15** | UX: explanations that state **why it is a finding and why it might not be**, with counterfactuals; **calibrated** confidence; **root-cause bulk triage**; **impact preview** before committing; keyboard-first inbox; diff lenses; a knowledge workbench; suppression health. | Track 04 synthesis 2; Christakis & Bird; Facebook diff-time result |
| **R16** | Evaluate on **real code with paired vulnerable/fixed variants**, report **recall loss first**, measure coverage (fraction auto-decided), use time and repository splits, and run memorisation (rename) checks. Juliet and OWASP are smoke tests only. | Kang'22, LASAA Juliet memorisation, ZeroFalse transfer collapse, PrimeVul |

---

## 3. Where our design goes beyond the literature

1. **Proof-carrying suppressions.** An FP verdict, from the agent or a human, is accepted only when it can be expressed as a knowledge item (a sanitizer, guard predicate, type fact, exposure fact, or test-path fact) under which the Datalog engine *derives* that the finding is mitigated. That is a symbolic discharge of the LLM's claim. NESA and NeuroLog use LLM facts *as input to* Datalog. We know of no system that also requires the LLM's FP argument to be *reproduced* by the engine before it suppresses anything.
2. **One derivation graph serves three purposes:** explanations (minimal proof tree in the UI), Bingo-style posterior ranking after each verdict, and truth maintenance (retracting knowledge re-opens its consequences). Published systems pick one of these.
3. **Structured, symbolic triage memory.** Semgrep's Memories are free text. Ours are Datalog facts and Semgrep spec rules with provenance, canary-replay results, impact previews and rollback, so the flywheel moves knowledge out of LLM calls into cheap deterministic rules. The KPI is the *Tier-0 decision rate rising and agent cost per finding falling* as an org's codebases are scanned.
4. **Measured false negatives** via audit sampling of auto-suppressed findings, shown in the product.
5. **Interprocedural taint on top of Semgrep OSS.** Semgrep's open-source engine is intraprocedural; we verified that it misses a source→helper→sink flow. We use Semgrep as a *specification matcher* and lift its matches into a Datalog program that computes compositional, summary-based interprocedural taint.

---

## 4. Open problems this POC does not solve (honest list)

- Precise interprocedural analysis at scale: our Python extractor is AST-based and partly flow-insensitive. Production needs tree-sitter/CPG front-ends per language and Soufflé-scale evaluation.
- Classes without oracles (authorization, IDOR, business logic): execution evidence is weakest exactly where SAST false positives are most common.
- Calibration needs triage volume. Until then confidence is labelled "uncalibrated".
- Real LLM behaviour: the agent is **mocked** in this POC. The interfaces, gates and schemas are real; the measured numbers only show that the *machinery* works, not how well a real model performs.

---

## 5. Key references (short form; full citations in the track files)

- Li, Dutta, Naik. *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities.* ICLR 2025. arXiv:2405.17238.
- Wang et al. *LLMDFA: Analyzing Dataflow in Code with Large Language Models.* NeurIPS 2024. arXiv:2402.10754.
- Wang et al. *LLMSA/NESA: Relational Neuro-Symbolic Static Program Analysis.* FSE 2026. arXiv:2412.14399.
- Li et al. *Enhancing Static Analysis for Practical Bug Detection: An LLM-Integrated Approach (LLift).* OOPSLA 2024.
- Yang et al. *KNighter: Transforming Static Analysis with LLM-Synthesized Checkers.* SOSP 2025.
- Guo et al. *RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing.* ICML 2025.
- Sun et al. *GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis.* ICSE 2024.
- Wu et al. *Lemur: Integrating Large Language Models in Automated Program Verification.* ICLR 2024.
- Wen et al. *Automatically Inspecting Thousands of Static Bug Warnings with LLM: How Far Are We? (LLM4SA).* TKDD 2024.
- *ZeroFalse: Improving Precision in Static Analysis with LLMs.* arXiv:2510.02534, 2025.
- *Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry.* ICSE-SEIP 2026. arXiv:2601.18844.
- *LLM4PFA: Minimizing False Positives in Static Bug Detection via LLM-Enhanced Path Feasibility Analysis.* arXiv:2506.10322.
- Ullah et al. *LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?) (SecLLMHolmes).* IEEE S&P 2024.
- Ding et al. *Vulnerability Detection with Code Language Models: How Far Are We? (PrimeVul).* ICSE 2025.
- Raghothaman, Kulkarni, Heo, Naik. *User-Guided Program Reasoning using Bayesian Inference (Bingo).* PLDI 2018.
- Raghothaman et al. *Provenance-guided synthesis of Datalog programs (ProSynth).* POPL 2020. Si et al. *Syntax-guided synthesis of Datalog programs (ALPS).* FSE 2018.
- Bravenboer, Smaragdakis. *Strictly Declarative Specification of Sophisticated Points-to Analyses (Doop).* OOPSLA 2009.
- Jordan, Scholz, Subotić. *Soufflé: On Synthesis of Program Analyzers.* CAV 2016. Zhao, Subotić, Scholz. *Debugging Large-scale Datalog: A Scalable Provenance Evaluation Strategy.* TOPLAS 2020.
- Avgustinov et al. *QL: Object-oriented Queries on Relational Data.* ECOOP 2016.
- Li, Huang, Naik. *Scallop: A Language for Neurosymbolic Programming.* PLDI 2023.
- Yamaguchi et al. *Modeling and Discovering Vulnerabilities with Code Property Graphs.* IEEE S&P 2014.
- Rawat. *NeuroLog: Reasoning You Can Audit — Neuro-Symbolic Vulnerability Discovery via LLM Facts, Datalog, and SMT.* arXiv:2606.00669, 2026.
- *LogicLoc: Neurosymbolic Repo-level Code Localization.* arXiv:2604.16021, 2026.
- Kremenek, Engler. *Z-Ranking.* SAS 2003. Kremenek et al. *Correlation Exploitation in Error Ranking.* FSE 2004.
- Heckman, Williams. *A systematic literature review of actionable alert identification techniques.* IST 2011.
- Kang, Aw, Lo. *Detecting False Alarms from Automatic Static Analysis Tools: How Far are We?* ICSE 2022.
- Sadowski et al. *Tricorder.* ICSE 2015; *Lessons from Building Static Analysis Tools at Google.* CACM 2018.
- Distefano et al. *Scaling Static Analyses at Facebook.* CACM 2019.
- Christakis, Bird. *What Developers Want and Need from Program Analysis.* ASE 2016.
- Johnson et al. *Why Don't Software Developers Use Static Analysis Tools to Find Bugs?* ICSE 2013.
- OASIS. *SARIF v2.1.0.*
- Semgrep. *Announcing AI noise filtering and triage memories* (2025); *Semgrep is confidently handling 60% of all triage* (2025). Vendor-reported.
