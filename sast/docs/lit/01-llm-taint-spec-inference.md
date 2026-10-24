# 01: LLM-inferred taint specifications and LLM + static-analysis hybrids

Scope: work that uses LLMs to (a) infer taint specs (sources, sinks, sanitizers, propagators, summaries), (b) synthesize whole checkers or queries (CodeQL, Semgrep, Clang SA), or (c) wrap a symbolic engine and do path-level reasoning or FP filtering. Classic probabilistic spec inference (Merlin, Seldon, USpec) is included as a baseline. We read everything with one design in mind: **Semgrep (taint mode) + Datalog reasoning layer + LLM verifier agent + data flywheel, with very low false positives as the goal.**

Date compiled: 2026-10-24.

## Methodology and evidence grading (read this first)

From this environment, direct fetches of arxiv.org, openreview.net, dl.acm.org, proceedings.neurips.cc, Semantic Scholar, NSF PAR and all `*.github.io` hosts **failed (DNS blocked)**. Only `github.com` / `raw.githubusercontent.com` could be fetched directly. So the evidence comes from:

- **[GH]**: read directly from the project's GitHub README (IRIS, LLMDFA, LLift, KNighter, Autogrep).
- **[PT]**: paper text (abstract or body sentences) quoted in search results that index the arXiv/ACM/OpenReview/NSF pages. Numbers marked [PT] appear as sentences from the paper, but I did not see them in the PDF myself.
- **[2nd]**: secondary summaries (review sites, vendor blogs, other papers describing the work).
- **[unverified]**: from memory, or the sources disagree.

Before any number here goes into an external claim, re-check it against the PDF. Where versions of a paper disagree, I note it.

---

## Part A: LLM as spec labeler; symbolic engine does reachability

### A1. IRIS: LLM-assisted static analysis (CodeQL + LLM)

- **Citation:** Ziyang Li, Saikat Dutta, Mayur Naik. "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities" (arXiv title: "LLM-Assisted Static Analysis for Detecting Security Vulnerabilities"). ICLR 2025. arXiv:2405.17238. https://arxiv.org/abs/2405.17238 · code: https://github.com/iris-sast/iris
- **Problem:** CodeQL-style whole-program taint analysis misses vulnerabilities because hand-written source/sink models do not cover third-party and project-internal APIs. On Java CVEs, CodeQL finds a small fraction.
- **Mechanism [GH][PT]:**
  1. CodeQL extracts *candidate* APIs: external library calls, plus internal function parameters and return values.
  2. The LLM labels each candidate for a given CWE as source, sink, taint-propagator, or none. External APIs use few-shot prompts with JDK examples. Internal APIs use zero-shot prompts with repo context and docs [2nd]. The LLM never writes query code. Labels go into CodeQL through templates (data extensions).
  3. CodeQL runs the standard taint queries with these extra specs.
  4. **Contextual analysis:** the LLM reviews each candidate path (source/sink context and path snippet) and filters likely FPs.
  - Sanitizers are deliberately not inferred: "typically do not vary for the vulnerability classes that we consider" [PT].
- **Benchmark:** CWE-Bench-Java. The paper has 120 manually validated vulns [PT]. The current repo has 213 CVEs across 49 CWEs (60 of them CWE-22, 38 CWE-79, 23 CWE-94, 13 CWE-78), with manual source/sink annotations for 50 CVEs. 93 CVEs were added in Aug 2025 [GH].
- **Results [PT]:**
  - IRIS+GPT-4 detects 55/120 vs CodeQL 27/120 (+28, +103.7%).
  - Average FDR is 84.82% for IRIS vs 90.03% for CodeQL (5.21 points lower).
  - DeepSeekCoder-7B still detects 52.
  - A manual look at 50 random IRIS alarms found 27/50 with a potential attack surface, so the authors estimate the "refined" FDR at 46%.
  - 4 previously unknown vulns found in the latest versions of 30 projects.
  - The repo has results for 121 projects × 9 LLMs [GH].
  - An independent comparison (in arXiv:2504.16057, MoCQ) on 132 Java vulns: CodeQL + IRIS specs has 51.5% TPR / 82.7% FDR vs 28.0% / 87.3% for stock CodeQL [2nd].
- **Limitations:**
  - **Precision is terrible in absolute terms.** An FDR of about 85% means roughly 6 of 7 alarms are false. Recall roughly doubles, but precision barely moves.
  - The LLM over-labels: "sometimes they detect specifications that are not relevant to the vulnerability class… resulting in too many predicted sources or sinks" [PT].
  - It needs a buildable project (CodeQL database).
  - CWE-specific, Java-only.
  - The later QLCoder paper by the same group reports that IRIS's *general* query suite gets F1 = 0.048 under a stricter "detect in vulnerable, not in patched" criterion [PT]. Either IRIS-style recall comes with an enormous alarm volume, or the metric is very harsh.
- **Design implication for us:** IRIS is our base pattern: the LLM labels API roles and Semgrep taint mode/Datalog does reachability. But IRIS shows that **spec inference alone raises recall and wrecks precision**. We need (i) sanitizer and propagator inference, which IRIS skipped and which is critical for FPs in web code; (ii) a strong verification stage after reachability; (iii) confidence-gated spec admission (a low-confidence sink should not fire on its own). Labels are per-API and per-CWE, so they cache well across customers.

### A2. SemTaint: multi-agent taint spec extraction (JS/npm)

- **Citation:** "Multi-Agent Taint Specification Extraction for Vulnerability Detection" (SemTaint). NC State / UCSB / BU authors [author list not verified]. arXiv:2601.10865, 2026. https://arxiv.org/abs/2601.10865
- **Problem:** In dynamic JS, static call graphs are incomplete and per-package sources/sinks are unknown. The paper cites Brito et al.: CodeQL was the best SAST tool on 957 npm vulns yet detected only 31.3% [PT].
- **Mechanism [PT][2nd]:** static analysis builds the call graph. The LLM (1) resolves call edges static analysis cannot and (2) labels sources and sinks per CWE for each npm package. Agents output CSV files that CodeQL imports as external predicates, so neither the database nor the queries are recompiled.
- **Results [PT]:** detects 106 of 162 vulns that CodeQL previously missed; 4 new vulns in popular npm packages.
- **Limitations:** recall-focused. I found no FP or precision figure. LLM-resolved call edges are unsound additions and can create spurious paths.
- **Design implication:** the spec format should be **per-package and versioned**, which suits a cross-customer cache keyed by (ecosystem, package, version range). Separately, the **LLM can patch call-graph holes**, not just label endpoints. In Semgrep this maps to adding inferred edges as Datalog facts with provenance, so they can be weighted down or excluded in high-precision mode.

### A3. Artemis: LLM-assisted SSRF taint analysis for PHP

- **Citation:** Yuchen Ji, Ting Dai, Zhichao Zhou, Yutian Tang, Jingzhu He. "Artemis: Toward Accurate Detection of Server-Side Request Forgeries through LLM-Assisted Inter-procedural Path-Sensitive Taint Analysis." PACMPL 9(OOPSLA1), Art. 128, April 2025. DOI 10.1145/3720488. arXiv:2502.21026.
- **Mechanism [PT]:** four modules:
  1. Source/sink identification: PHP built-ins come from a manual list. **The LLM labels third-party functions** as sources or sinks.
  2. Static call-graph inference for dynamic PHP.
  3. Rule-based taint analysis.
  4. **FP pruning:** path conditions are extracted, and paths with always-unsatisfiable or "URL rejection" conditions (allow-list checks) are pruned.

  Then a multi-turn LLM conversation builds a concrete SSRF exploit for each reported path, as validation.
- **Results [PT]:**
  - 250 PHP apps.
  - 207 true vulnerable paths (106 true SSRFs) with 15 FP paths.
  - Path-condition pruning cut FP paths from 35 to 15.
  - 35 new SSRFs, 24 CVEs.
- **Limitations:** SSRF only, PHP only. The "URL rejection" condition modeling is SSRF-specific hand engineering.
- **Design implication:** this is the best precision result in the cluster, and it comes from **vuln-class-specific semantic modeling of guards** (allow-list and validation checks treated as sanitizing conditions), not from the LLM. Our Datalog layer should encode per-CWE "guard" predicates such as URL host allow-list, path canonicalize-then-prefix-check, and parameterized query. The LLM's job is to *recognize* that a custom function implements one of these guards, which is a labeling task we can cache. Also note the exploit synthesis: a concrete PoC is the strongest verdict our agent can give.

### A4. LATTE: LLM-powered static binary taint analysis

- **Citation:** Puzhuo Liu, Chengnian Sun, Yaowen Zheng, Xuan Feng, Chuan Qin, Yuncheng Wang, Zhenyang Xu, Zhi Li, Peng Di, Yu Jiang, Limin Sun. "LLM-Powered Static Binary Taint Analysis." ACM TOSEM, 2025. DOI 10.1145/3711816. Preprint: "Harnessing the Power of LLM to Support Binary Taint Analysis," arXiv:2310.08275.
- **Mechanism [PT]:**
  1. Disassemble and decompile.
  2. The LLM flags security-sensitive call sites (sinks) and sources.
  3. Symbolic backward intra- and inter-procedural data-dependency slicing builds "dangerous flows" (call chains).
  4. GPT-4 does the final vulnerability inspection of each flow via a prompt sequence.
- **Results [PT]:**
  - Sink/source identification precision 82.1%, with 100% coverage of expected pairs on Juliet subjects.
  - More than 95% of correct dangerous flows recovered.
  - On Karonte's firmware dataset: 119 unique bugs (the TOSEM version says 117), 37 previously unknown, 10 CVEs.
  - Claims to beat EmTaint/Arbiter/Karonte on accuracy/F1 [2nd].
- **Limitations:** the authors attribute FPs mainly to GPT-4 response instability [PT]. Missed flows cascade, because the LLM is the final checker.
- **Design implication:** the authors note that **cached sink/source results can be reused across binaries sharing libraries** [PT], which directly supports a shared spec cache. Instability argues for self-consistency (k samples / voting) on spec labels before admitting them into the cache, and for pinning model + prompt versions per cached label.

### A5. AdaTaint: adaptive source/sink identification + neuro-symbolic FP mitigation

- **Citation:** Shiyin Lin. "LLM-Driven Adaptive Source–Sink Identification and False Positive Mitigation for Static Analysis." arXiv:2511.04023, Nov 2025 (also appears in an ACM proceedings, DOI 10.1145/3773365.3773410 [unverified venue]).
- **Mechanism [PT]:** the LLM proposes source/sink specs. Suggestions are "grounded in program facts and constraint validation" before use, and alerts are filtered via neuro-symbolic reasoning.
- **Results [PT]:** on Juliet 1.3, SV-COMP-style C, and 3 real projects, FPs drop 43.7% on average and recall rises 11.2% vs CodeQL, Joern and LLM-only pipelines.
- **Limitations:** single-author preprint, synthetic-heavy benchmarks, no independent replication. Weak evidence.
- **Design implication:** the pattern "LLM proposes, symbolic checks validate the proposal" (for example, does the proposed sink actually reach a dangerous primitive? does the proposed sanitizer actually transform the value?) is cheap and worth having. Treat the numbers as anecdotal.

---

## Part B: LLM as the semantic oracle inside a compositional analysis

### B1. LLMDFA: LLM-powered dataflow analysis

- **Citation:** Chengpeng Wang, Wuqi Zhang, Zian Su, Xiangzhe Xu, Xiaoheng Xie, Xiangyu Zhang. "LLMDFA: Analyzing Dataflow in Code with Large Language Models." NeurIPS 2024. arXiv:2402.10754. Code: https://github.com/chengpeng-wang/LLMDFA [author list from memory: unverified]
- **Mechanism [GH][PT]:** compilation-free, bottom-up, summary-based dataflow:
  1. **Source/sink extraction:** the LLM *synthesizes extractor scripts* over the tree-sitter AST instead of labeling directly.
  2. **Intra-procedural:** the LLM summarizes dataflow facts per function, with CoT.
  3. **Inter-procedural:** summaries are composed bottom-up.
  4. **Path feasibility:** the LLM *synthesizes SMT-encoding scripts* and an SMT solver checks the path conditions.
- **Results [PT]:**
  - Average precision 87.10%, recall 80.77%.
  - F1 is up 0.23 vs CodeFuseQuery and up 0.36 vs few-shot CoT end-to-end.
  - Juliet with gpt-3.5: DBZ/XSS/OSCI precision 73.75/100/100%, recall 92.16/92.31/78.38%.
  - TaintBench (Android): about 75% precision, about 60–61% recall (74.63/60.24 vs 75.38/61.25 depending on version or subset).
  - Source/sink extraction phase reported at 100% P/R on Juliet [2nd].
- **Limitations:** mostly Juliet, which is synthetic and has an easy, uniform API surface. DBZ precision suffers because path conditions are hard to encode. Per-function LLM summarization is expensive at repo scale. The "summaries" are not verified.
- **Design implication:** have the **LLM write deterministic artifacts (extractors, Semgrep patterns, encodings) instead of giving verdicts**. A synthesized extractor is inspectable and cacheable, costs nothing to re-run, and does not drift. Use an SMT/Datalog check on path conditions after the LLM proposes them. Our analogue: the LLM emits Semgrep `pattern-sources`/`pattern-sanitizers` snippets, which are executed and tested, not trusted.

### B2. LLMSA → NESA: compositional neuro-symbolic static analysis with a Datalog-like policy

- **Citation:** Chengpeng Wang et al. "LLMSA: A Compositional Neuro-Symbolic Approach to Compilation-free and Customizable Static Analysis." arXiv:2412.14399v1, Dec 2024. Later retitled "NESA: Relational Neuro-Symbolic Static Program Analysis," FSE 2026, DOI 10.1145/3808161. https://arxiv.org/abs/2412.14399
- **Mechanism [PT]:**
  - The user writes an *analysis policy*. In NESA this is "a restricted form of Datalog".
  - The policy decomposes the problem into relations. **Syntactic relations** are computed by parsing-based analysis (no hallucination). **Semantic relations** are answered by LLM prompts on small snippets.
  - The policy is evaluated with **lazy, incremental and parallel prompting**: the LLM is queried only when a rule needs that fact, so neural facts are demand-driven.
- **Results [PT]:**
  - Alias analysis P 72.37% / R 85.94%.
  - Program slicing P 91.50% / R 84.61%.
  - Juliet bug detection P 82.77% / R 85.00%.
  - TaintBench taint detection P 66.27% / R 78.57%, F1 +0.20 vs an industrial tool.
  - Up to 3.79× faster than ablations.
  - 13 previously unknown bugs, confirmed and fixed.
- **Limitations:** TaintBench precision of 66% is not enterprise-grade. Neural facts enter the Datalog fixpoint unweighted, so one hallucinated fact propagates. Token cost at monorepo scale was not found [unverified].
- **Design implication:** **the closest prior art to our architecture.** Take these from it:
  - (1) Datalog as the glue, with *neural predicates* (e.g. `is_sanitizer(f, CWE)`, `flows_through(f, arg, ret)`) evaluated lazily.
  - (2) Demand-driven LLM calls, so only facts on a candidate source→sink path are ever asked, which is the main cost lever.

  Improve on it: (a) attach confidence and provenance to every neural fact and run the fixpoint under a semiring (max-product or Scallop-style top-k proofs) so a finding's confidence is the weakest link in its derivation; (b) memoize neural facts globally (content-hash of the function + model version) so the incremental re-analysis NESA hints at becomes cross-customer reuse for library code.

### B3. LLift: LLM-integrated static analysis for UBI bugs (Linux)

- **Citation:** Haonan Li, Yu Hao, Yizhuo Zhai, Zhiyun Qian. "Enhancing Static Analysis for Practical Bug Detection: An LLM-Integrated Approach." PACMPL (OOPSLA 2024), DOI 10.1145/3649828. Preprint: "The Hitchhiker's Guide to Program Analysis: A Journey with Large Language Models," arXiv:2308.00245. Code: https://github.com/seclab-ucr/LLift [author list from memory: unverified]
- **Problem:** UBITect (summary-based static + symbolic execution) leaves many use-before-initialization candidates undecided or false. The undecided cases sit exactly where static analysis loses precision: initializer functions whose effect depends on return-value checks.
- **Mechanism [PT][GH]:** the LLM (GPT-4) acts as a *function-summary oracle* for initializer calls (does `f` must-initialize `var` under the post-condition the caller checks?).
  - **Post-constraint guided path analysis:** only the paths consistent with the caller's check of the return value are considered.
  - **Progressive prompting:** callee bodies are given on demand, not all upfront.
  - **Task decomposition.**
  - **Self-validation:** the LLM re-checks its own answer.

  Output is a `must_init` set per case [GH].
- **Results [PT]:**
  - On about 1,000 potential UBI bugs from static analysis: about 50% precision with "no missing bugs" on the evaluated set.
  - 13 previously unknown UBI bugs.
  - Cmp-40 ablation set: 13 real bugs + 27 UBITect FPs [GH].
- **Limitations:**
  - 50% precision is still a coin flip.
  - Output is nondeterministic (the README warns of GPT-4 randomness [GH]).
  - Only for one bug class with a well-defined summary shape.
- **Design implication:** the LLM is most useful where it answers **one narrow, well-typed question at the exact point where the symbolic engine gives up** (here, "does callee X initialize/sanitize arg Y on the path where ret==0?"). Its output is a reusable *function summary*, not a bug verdict. For us, sanitizer and propagator summaries for project-internal helpers should take this form, asked lazily and cached by function hash.

### B4. BugLens: Hitchhiker's Guide Part II (LLM post-refinement of static taint reports)

- **Citation:** Haonan Li, Hang Zhang, Kexin Pei, Zhiyun Qian. "The Hitchhiker's Guide to Program Analysis, Part II: Deep Thoughts by LLMs." arXiv:2504.11711 (v3, May 2025).
- **Mechanism [PT]:** after static analysis, the LLM (a) assesses the security impact of the flagged pattern and (b) checks the path/data constraints behind each warning, following the structure of traditional analysis steps rather than one naive "is this a bug?" prompt.
- **Results [PT]:** on Suture's Android-kernel taint reports (251 reports, about 90% raw FP), precision rises from 0.10 raw, and 0.50 after Suture's semi-automated refinement, to 0.72. 4 new vulns.
- **Design implication:** **structured verification beats a monolithic verdict.** Our verifier agent should run a fixed checklist (source really attacker-controlled? each hop sound? sanitizer adequate for this sink and CWE? sink reachable in deployed config? impact?). Each answer should be a separate, loggable judgment. Those per-step labels are also better flywheel data than one boolean.

---

## Part C: LLM synthesizes whole checkers or queries

### C1. KNighter: LLM-synthesized Clang Static Analyzer checkers from patches

- **Citation:** Chenyuan Yang, Zijie Zhao, Zichen Xie, Haoyu Li, Lingming Zhang. "KNighter: Transforming Static Analysis with LLM-Synthesized Checkers." SOSP 2025. DOI 10.1145/3731569.3764827. arXiv:2503.09002. Code: https://github.com/ise-uiuc/KNighter
- **Mechanism [GH][PT]:**
  1. Analyze a historical fix commit → bug pattern.
  2. The LLM plans and writes a CSA checker.
  3. **Validation:** the checker must flag the pre-patch code and not the patched code.
  4. **Refinement loop:** compile errors and FPs are fed back to iterate.
  5. Scan the kernel.
  6. **Triage agent:** an LLM labels reports.

  Models: o3-mini by default; OpenAI, Claude, Gemini, DeepSeek and local models supported [GH].
- **Results [PT]:**
  - v3: 92 new bugs (average age 4.3 years), 77 confirmed, 57 fixed, 30 CVEs.
  - High-quality checkers produced for 61% of commits.
  - About 35% FP rate *with* the triage agent. (v1: 90 "bug"-labeled reports → 61 TPs, so 32.2% FP.)
  - Refinement fixed 84.6% of initially non-plausible valid checkers.
  - Failure analysis: 22/61 commits gave no valid checker, and 59% of those failures were implementation problems (e.g. inlining hid calls).
  - FPs come from bug patterns that "lacked the necessary precision… across different contexts".
- **Limitations:** a 35% residual FP rate even after an LLM triage pass. Generating the checker is the main failure point (TyPatch, arXiv 2609.13728, argues full-checker generation is unreliable and expensive [2nd]). It is C-only and relies on CSA path sensitivity.
- **Design implication:** the **patch-differential oracle** ("fires on vulnerable, silent on fixed") is the single most reusable validation trick. Use it for every LLM-authored Semgrep rule, and for flywheel-promoted rules: a TP from human triage plus its fix commit forms a regression pair. Also: **generating the pattern is easier than generating the checker.** Have the LLM fill a constrained template (Semgrep taint rule YAML, Datalog facts), not write free-form analyzer code.

### C2. MoCQ: holistic neuro-symbolic query generation (CodeQL / Joern)

- **Citation:** Penghui Li, Songchen Yao, Josef Sarfati Korich, Changhua Luo, Jianjia Yu, Yinzhi Cao, Junfeng Yang. "Automated Static Vulnerability Detection via a Holistic Neuro-symbolic Approach" (v1), retitled "Neuro-symbolic Static Analysis with LLM-generated Vulnerability Patterns." arXiv:2504.16057, 2025.
- **Mechanism [PT]:** the LLM extracts vulnerability patterns and writes full detection queries in a DSL (CodeQL, Joern). A static-analysis feedback loop runs the queries and returns errors and results so the LLM can refine them.
- **Results [PT]:**
  - v1: 7 vuln types, 2 languages. At least 12 patterns experts missed, P/R "comparable to expert-written queries," 7 new vulns.
  - Later version: 12 vuln types × 4 languages (C/C++, Java, PHP, JS), 46 new patterns experts missed, 7 new vulns, expert-time savings.
  - "Nearly doubles CodeQL detection" is a secondary claim only [2nd].
- **Limitations:** "comparable to experts" is a low bar for precision when expert CodeQL suites already have about 87–90% FDR on CWE-Bench-Java (see IRIS).
- **Design implication:** query-level synthesis is viable *offline*, to grow the rule corpus, with a human-review gate. It is not a per-scan action.

### C3. QLPro: LLM + CodeQL with triple-voting spec classification

- **Citation:** "QLPro: Automated Code Vulnerability Discovery via LLM and Static Code Analysis Integration." arXiv:2506.23644, 2025 [authors not verified].
- **Mechanism [PT]:** static analysis extracts *all* taint-spec candidates in a project. LLMs classify them with a **triple-voting** scheme. A **three-role** LLM mechanism then writes project-specific CodeQL rules from the matched specs.
- **Results [PT]:** JavaTest (10 projects, 62 confirmed vulns): QLPro with two Claude-3.7-sonnet-thinking instances found 41/62 (66.1%) vs 24/62 (38.7%) for official CodeQL rules.
- **Limitations:** tiny benchmark. No FP or precision figure surfaced. Project-specific rules are expensive and do not transfer.
- **Design implication:** voting or self-consistency on spec labels is cheap and effective noise control. *Project-specific* rule generation conflicts with cross-customer caching, so keep generated artifacts at library or framework granularity where possible.

### C4. QLCoder: agentic CodeQL query synthesis from CVE descriptions

- **Citation:** Claire Wang, Ziyang Li, Saikat Dutta, Mayur Naik. "QLCoder: A Query Synthesizer for Static Analysis of Security Vulnerabilities." ICLR 2026. arXiv:2511.08462.
- **Mechanism [PT]:** an agent built on Claude Code, with execution feedback, a CodeQL **Language Server** for syntax help, and retrieval over CodeQL queries and docs. Success means the query detects the CVE in the vulnerable version and not in the patched one.
- **Results [PT]:**
  - 176 CVEs, 42 CWEs (CWE-Bench-Java).
  - Correct queries for 53.4% of CVEs vs 10% for plain Claude Code.
  - F1 0.7 vs 0.048 (IRIS general suite) and 0.073 (CodeQL).
- **Limitations:** one query per known CVE is variant analysis, not discovery. F1 is computed per CVE (the query is targeted by construction).
- **Design implication:** the **tooling around the LLM matters 5×** (53.4% vs 10%). Our rule-writing agent needs a Semgrep validator / LSP, `semgrep --test` fixtures, retrieval over the existing rule corpus, and the vulnerable/patched oracle. This is also the pattern for turning a confirmed customer TP into a variant-hunting rule.

### C5. Autogrep: LLM-generated Semgrep rules from patches

- **Citation:** Lambda Security. "Autogrep: Automated Generation and Filtering of Semgrep Rules from Vulnerability Patches." Blog / tool, Feb 2025. https://github.com/lambdasec/autogrep
- **Mechanism [GH]:**
  - Takes CVE fix commits from the MoreFixes dataset and skips patches touching more than 1 file.
  - The LLM generates Semgrep rules (up to 3 attempts) and validates them against the original vuln.
  - Filtering: embedding dedupe (all-MiniLM-L6-v2) plus an LLM quality judge that removes project-specific or low-quality rules.
  - Output works with Semgrep and Opengrep.
  - Motivated by the license change on Semgrep's official rules.
- **Results [2nd, from the write-up via search]:**
  - 39,931 patches → 645 rules across 20 languages.
  - The filter removed 71.15% of rules as overly specific and 10.75% as duplicates.
  - No precision measured on held-out code.
- **Limitations:** yield is about 1.6%. Quality is judged by an LLM, not by FP rate on unrelated code.
- **Design implication:** the cheapest corpus-bootstrapping path for a Semgrep base, but every rule needs an **FP budget measured on a clean corpus** (e.g. top-N repos, with alerts sampled and triaged) before promotion. The main failure mode of patch-mined rules is overfitting to one project's identifiers.

(Related: RuleLLM, arXiv:2504.17198, generates YARA and Semgrep rules for *malicious packages*: 763 rules, P 85.2% / R 91.8% [PT]. Different task.)

---

## Part D: Classic (pre-LLM) spec inference, for contrast

### D1. Merlin

- **Citation:** Benjamin Livshits, Aditya V. Nori, Sriram K. Rajamani, Anindya Banerjee. "Merlin: Specification Inference for Explicit Information Flow Problems." PLDI 2009. https://www.microsoft.com/en-us/research/publication/merlin-specification-inference-for-explicit-information-flow-problems-2/
- **Mechanism [PT]:**
  - Builds an interprocedural *propagation graph*.
  - Each node has unknown role variables (source, sanitizer, sink).
  - Paths are modeled with probabilistic constraints, e.g. "a source→sink path probably passes through a sanitizer". Exponential path constraints are approximated by constraints on node triples (cubic).
  - Solved with factor graphs (belief propagation).
  - Run with CAT.NET.
- **Results [PT]:**
  - 10 large .NET web apps.
  - 167 new confirmed specs → 322 additional vulns (the MSR page says 302).
  - Removed 13 FPs, a 15% reduction in CAT.NET's FP rate.
- **Design implication:** the key idea LLM papers mostly dropped is **joint inference over the flow graph**. Roles must be mutually consistent: if most flows from X to Y pass through f and are never exploited, f is likely a sanitizer. We can run Merlin-style consistency *over LLM priors*: LLM labels become priors on factor-graph nodes, human triage verdicts become observed evidence, and a global solve propagates them. This is a principled flywheel mechanism. A dismissed finding becomes evidence that some node on its path is a sanitizer.

### D2. Seldon

- **Citation:** Victor Chibotaru, Benjamin Bichsel, Veselin Raychev, Martin Vechev. "Scalable Taint Specification Inference with Big Code." PLDI 2019, pp. 760–774. DOI 10.1145/3314221.3314648.
- **Mechanism [PT]:** information-flow constraints from many programs, posed as a **linear optimization** (relaxed LP) and solved off-the-shelf.
- **Results [PT]:** Python. About 7,000 API roles learned from more than 210,000 candidates, with fewer than 300 annotations, at an estimated 67% precision.
- **Design implication:** cross-codebase statistics are a cheap signal that is *complementary* to LLM semantics. With many customers' (anonymized) flow graphs, we can run Seldon-style LP to flag API roles that LLM labels disagree with. 67% precision means it is a candidate generator, not ground truth.

### D3. USpec

- **Citation:** Jan Eberhardt, Samuel Steffen, Veselin Raychev, Martin Vechev. "Unsupervised Learning of API Aliasing Specifications." PLDI 2019.
- **Results [PT]:** learned more than 2,000 aliasing specs for Java/Python APIs from millions of files, unsupervised, which improved a points-to analysis. DAInfer+ (arXiv:2603.28060) notes USpec's aliasing form is restrictive.
- **Design implication:** taint propagation through containers and builders (e.g. `map.put`/`get`, `StringBuilder`) is a big FN and FP source in Semgrep-style analysis. Propagator/alias specs deserve as much attention as sources and sinks. DAInfer+ reports a direct-ChatGPT alias-spec baseline at only 14.11% precision / 11.44% recall [PT]. **Raw LLM prompting is bad at alias and propagator specs**, and structured (embedding + symbolic) methods do much better. Do not let the LLM free-label propagators without validation.

---

## Part E: Adjacent evidence on the "LLM filters FPs" step (brief)

These are not spec inference, but they bound what our verifier can achieve:

- **Tencent industrial study:** "Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry," ICSE-SEIP 2026, arXiv:2601.18844 [PT]. 433 alarms (328 FP / 105 TP). Hybrid LLM + static analysis removed 94–98% of FPs "while maintaining high recall". Cost was 2.1–109.5 s and $0.0011–$0.12 per alarm, vs 10–20 min of manual review.
- **LLM4PFA:** arXiv:2506.10322 [PT]. LLM path-feasibility analysis filters 72–96% of FPs.
- **Munson, Gomez, Cárdenas (ICSE 2025 LLM4Code):** "With a Little Help from My LLM Friends." LLM triage of **Semgrep** Java findings [PT]. Some models *reduced* accuracy vs raw Semgrep. o1-mini was best. Each new model improved. Conclusion: "not ready for prime time".
- **Semgrep Assistant (vendor claim) [2nd]:** about 20% of triage auto-handled without org context, about 60% with "Memories" (org-specific context), at 96% agreement with security researchers. Not peer reviewed, but the jump from 20% to 60% is direct evidence that *per-org memory* is the main value driver.

---

## Synthesis: design lessons for our scanner

1. **Split the labor: the LLM labels and summarizes, the symbolic engine does reachability, and the LLM never decides reachability.** Every successful system (IRIS, SemTaint, Artemis, LATTE, LLift, NESA) keeps the global fixpoint symbolic and asks the LLM narrow, local, typed questions: what role does API X play for CWE Y; does function f sanitize or propagate arg i; does this guard enforce an allow-list? End-to-end LLM detection is consistently the worst baseline (LLMDFA: −0.36 F1).

2. **Spec inference alone hurts precision, so the budget must go to sanitizers, guards and verification.** IRIS doubled recall but stayed at about 85% FDR. The LLM over-labels sinks and sources. The best precision in the cluster (Artemis: 207 TP paths / 15 FP) came from modeling **guards and path conditions** per vuln class, plus PoC validation. For our goal, the order of priority is: (a) sanitizer/guard/validator recognition, (b) propagator correctness, (c) new sinks, (d) new sources. IRIS skipped (a). Do not copy that.

3. **Neural facts belong in Datalog as first-class, confidence-weighted, provenance-tracked predicates evaluated lazily** (NESA/LLMSA pattern, plus our extension). Evaluate LLM predicates only on demand, i.e. only for functions on a candidate source→sink derivation, with lazy/incremental/parallel prompting. Run the fixpoint with confidence semantics (weakest-link or top-k proofs) so each finding carries a calibrated score and an explanation listing which neural facts it depends on. That gives the verifier agent a precise list of assumptions to check.

4. **Prefer LLM-authored deterministic artifacts over LLM verdicts.** LLMDFA synthesizes extractors and SMT encodings. KNighter, QLCoder, MoCQ and Autogrep synthesize checkers or queries. Artifacts are inspectable, testable, cacheable, free to re-run and immune to sampling drift. Concretely, the LLM emits Semgrep `pattern-sanitizers`/`pattern-sources` YAML or Datalog facts, validated by `semgrep --test`. Constrain it to templates (rules, facts), not free-form analyzer code: KNighter's largest failure source was checker implementation.

5. **Use the patch-differential oracle everywhere a rule is born or promoted.** "Fires on vulnerable, silent on fixed" (KNighter, QLCoder, Autogrep) is cheap ground truth. Add a clean-corpus FP budget, because the main failure of patch-mined rules is overfitting (Autogrep discarded 71% as over-specific). Every human-confirmed TP plus its fix commit becomes a regression pair in the rule test suite.

6. **Make spec labels a cross-customer cache keyed by (ecosystem, package, version range, API signature, CWE, model+prompt version).** Library and framework specs are customer-independent (SemTaint is per-npm-package; LATTE notes cache reuse across binaries; IRIS external-API labels are per-CWE). Admit labels to the shared cache only after self-consistency (QLPro-style voting; LATTE blames instability for FPs) **and** symbolic validation (AdaTaint/Artemis-style). Project-internal summaries are cached per content hash and stay tenant-private. This is also the main cost control: steady-state LLM spend should scale with *new* code and *new* library versions, not with scans.

7. **Turn triage verdicts into evidence for joint inference, not just per-finding suppressions.** Merlin/Seldon show that roles should be solved *jointly* over the flow graph. Feed LLM labels in as priors and human or agent verdicts as observations. A dismissed finding becomes evidence that some node on its path is a sanitizer or guard, or that a source is not attacker-controlled. Solving globally localizes which spec was wrong, and that is how the engine "learns" from triage without memorizing individual findings. Semgrep's 20%→60% auto-triage jump with org memory suggests that per-org context drives most of the value.

8. **Verify with a structured checklist and record per-step judgments.** BugLens (precision 0.10→0.72) and LLift (progressive prompting, self-validation) show that decomposed, analysis-shaped prompts beat one "is this a bug?" prompt. Munson et al. show naive LLM triage of Semgrep output can *lower* accuracy. Per-step labels (source controllable? sanitizer adequate? reachable?) are much better flywheel training data than a single boolean, because they say *which* layer was wrong.

9. **Escalate in tiers to control cost; reserve PoC synthesis for the top tier.** The tiers:
   - Cached spec lookup (free).
   - Lazy neural predicate (one small-model call per new function).
   - Structured verifier (frontier model, per surviving finding).
   - PoC or exploit synthesis (Artemis), for high-severity findings only.

   The Tencent study puts LLM FP filtering at $0.001–$0.12 per alarm. Small models are viable for labeling (IRIS: DeepSeekCoder-7B found 52 vs 55 for GPT-4).

10. **Be skeptical of benchmarks; build our own precision-first eval.** Juliet-style numbers (LLMDFA, NESA, AdaTaint) overstate real-world performance: TaintBench precision falls to about 66–75%. Real-repo FDRs are 80–90% even for state-of-the-art systems (IRIS, CodeQL). KNighter still has about 35% FP after LLM triage. The headline metric should be **FDR at a fixed alert budget on real repos, with human-adjudicated samples**, plus the CWE-Bench-Java vulnerable/patched protocol for recall regression.

### Open questions / gaps worth a follow-up read (PDF access needed)

- IRIS exact prompts, candidate counts per project and cost per project (not surfaced).
- NESA/LLMSA token cost at repo scale and how its policy language handles recursion over neural relations.
- Whether any system calibrates LLM spec-label confidence. None found, which looks like an open niche for us.
- Sanitizer inference specifically: no LLM paper in this cluster evaluates sanitizer inference precision in isolation.
