# 05 — Neurosymbolic Program Analysis and Agentic LLM Vulnerability Discovery / Verification

Literature review for the design of a neurosymbolic SAST scanner (Semgrep + Datalog reasoning layer + LLM verification agent with a data flywheel). Target property: very low false-positive rate.

Compiled 2026-10-24.

## Method and evidence quality

- **How sources were accessed.** From this environment, WebFetch could reach only `github.com` / `raw.githubusercontent.com`. arxiv.org, openreview.net, usenix.org, projectzero.google, blog.trailofbits.com, theori.io and huggingface.co all failed with DNS errors or a proxy 403. So:
  - Primary pages were read through search-engine extraction of the page text (WebSearch). Each claim below names the page it came from.
  - GitHub READMEs were fetched directly: Vulnhuntr, RepoAudit, IRIS, Buttercup, Atlantis, RoboDuck archive, LLMxCPG, Vul-RAG, KNighter, LLMDFA.
- **What is verified.** Numbers marked as reported come from the paper abstract or proceedings page, as returned by those extractions.
- **[unverified]** marks a number I could not tie to a primary page: third-party summaries, figures that differ between versions, or memory.
- **Versions disagree.** Several papers changed their headline numbers between arXiv versions. Where that happened, I note it.
- **Vendor numbers.** Figures from Semgrep, Datadog, Google and AIxCC teams are self-reported and have not been independently replicated.

---

## Part A. Agentic vulnerability discovery systems (industry and competition)

### A1. Google Project Zero — Project Naptime (2024)
- **Citation:** Sergei Glazunov, Mark Brand. "Project Naptime: Evaluating Offensive Security Capabilities of Large Language Models." Google Project Zero blog, June 2024. https://projectzero.google/2024/06/project-naptime.html
- **Mechanism:**
  - A single agent works against a target codebase with tools that mirror a human researcher's workflow:
    - Code Browser, to navigate source and follow references
    - Python sandbox, for scripted input generation and fuzzing
    - Debugger, to observe program behavior on chosen inputs
    - Reporter, which signals progress or success to a controller
  - The controller checks the success condition mechanically, for example that a crash occurred. The agent's claim of success is not accepted on its word.
  - The post lists design principles: space for reasoning, an interactive environment, specialised tools, perfect verification, and a sampling strategy (many independent trajectories). [Principle names are from memory; the search snippet confirming them did not return. Treat as unverified.]
- **Results:** On Meta's CyberSecEval 2, with GPT-4 Turbo, scores were 1.00 on "Buffer Overflow" (baseline 0.05) and 0.76 on "Advanced Memory Corruption" (baseline 0.24). This was reported as up to a 20x improvement. Model- and backend-agnostic.
- **Limitations:**
  - CyberSecEval 2 tasks are small, synthetic, single-target programs.
  - The authors say substantial progress is still needed before the work affects researchers' daily practice.
  - Success depends on a ground-truth oracle (a sanitizer crash), which typical SAST classes such as authorization, IDOR and business-logic bugs do not have.
- **Design implication for us:**
  - Copy the two load-bearing ideas: (1) give the agent tools a human uses (navigation, execution, debugger), not a single giant prompt; (2) **"perfect verification"**: the agent does not get to declare a true positive, a mechanical checker does.
  - For us, the checker is the Datalog engine plus an optional execution harness.
  - Sampling several independent trajectories is the precursor to self-consistency voting (Part F).

### A2. Google Big Sleep (Project Zero + DeepMind, 2024–2025)
- **Citation:** Big Sleep team. "From Naptime to Big Sleep: Using Large Language Models To Catch Vulnerabilities In Real-World Code." Project Zero blog, Nov 1 2024. https://projectzero.google/2024/10/from-naptime-to-big-sleep.html (read through secondary coverage: The Register, The Hacker News, Infosecurity Magazine).
- **Mechanism:**
  - Naptime evolved into a **variant-analysis** agent.
  - Seeded with recent commits or previously fixed bugs, it reviews changed code with a tailored prompt and runs Python scripts in a sandbox to try to trigger the suspected bug.
  - Variant analysis narrows the search, so the agent asks "is there another bug like this known one near here?" rather than "find bugs anywhere".
- **Results:**
  - **2024:** an exploitable stack buffer underflow in SQLite (a magic value -1 used as an array index), found in a development branch before release and fixed the same day. Per the authors, neither OSS-Fuzz nor SQLite's own test infrastructure had found it.
  - **2025:** CVE-2025-6965 in SQLite (< 3.50.2; integer overflow leading to a read past the end of an array; CVSS 7.2). The CVE record credits Google TAG with "assistance from Google Big Sleep". Google claims the bug was known to threat actors and at risk of exploitation; this has not been independently verified.
  - **August 2025:** first batch of 20 reported vulnerabilities, mostly in FFmpeg and ImageMagick. Google says each was "found and reproduced by the AI agent without human intervention", with a human expert checking reports before disclosure. Details were withheld under the 90-day policy.
- **Limitations:**
  - Described by its authors as "highly experimental".
  - A human remains in the loop before reports go out.
  - Maintainers have complained about hallucinated AI bug reports in general, though not specifically about Big Sleep's.
- **Design implication for us:**
  - (1) **Variant analysis is the high-yield mode.** A confirmed finding or a fixed CVE should seed searches for siblings. In our architecture that means generalizing a confirmed finding into a Datalog/Semgrep rule and re-running it repository-wide or org-wide (see KNighter, B7).
  - (2) **"Reproduced" is the bar for a report.** Even Google keeps a human gate before external disclosure.

### A3. DARPA AI Cyber Challenge (AIxCC) Finals, DEF CON 33 (August 2025)
- **Sources:**
  - DARPA, "AIxCC results", https://www.darpa.mil/news/2025/aixcc-results
  - Trail of Bits, "AIxCC finals: Tale of the tape" (Aug 7 2025), https://blog.trailofbits.com/2025/08/07/aixcc-finals-tale-of-the-tape/
  - Trail of Bits, "Buttercup wins 2nd place" (Aug 9 2025)
  - KAIST news release
  - Virtualization Review (Sept 2 2025)
  - Theori, "AI Cyber Challenge and Theori's RoboDuck" (Aug 8 2025), https://theori.io/blog/aixcc-and-roboduck-63447
  - SoK: "DARPA's AI Cyber Challenge (AIxCC): Competition Design, Architectures, and Lessons Learned", arXiv 2602.07666 (2026)
- **Overall results:**
  - **Standings:** Team Atlanta (Atlantis) 1st, $4M, 392.76 points. Trail of Bits (Buttercup) 2nd, $3M, 219.35 points (from a Trail of Bits presentation scoreboard). Theori (RoboDuck) 3rd, $1.5M.
  - **Detection and patching:** The seven finalists together detected 77% of 70 injected vulnerabilities and patched 61% of them (the KAIST release says "average"; the exact definition is unverified).
  - **Real bugs:** They found 18 previously unknown real bugs: 6 in C and 12 in Java, 11 of the Java bugs with auto-generated patches.
  - **Scoring:** CRSs could receive static-analysis reports in **SARIF that may be true or false positives** and had to assess them. Per Theori: a SARIF assessment was worth 1 point, a PoV 2 points and a patch 6 points. Inaccurate patches were penalized.
- **What teams did with static analysis + LLMs:**
  - **Team Atlanta / Atlantis:**
    - Pairs LLMs with symbolic execution, directed fuzzing and static analysis across C and Java, with extra fuzzing support for Python, Rust and Go. Built on LangGraph + LiteLLM; models included o4-mini, GPT-4o and o3.
    - Its technical report (arXiv 2509.14589) argues that LLMs work best in an assistive role complementing static analysis rather than replacing it.
    - Trail of Bits reports that Atlantis generated ~90% of PoVs through direct AI reasoning, with fuzzing as the fallback.
    - Atlantis disabled non-PoV patching before the finals.
    - Code: https://github.com/Team-Atlanta/aixcc-afc-atlantis (the README fetched here gives only the layout).
  - **Trail of Bits / Buttercup:**
    - Orchestrator, seed generator, fuzzer (libFuzzer/Jazzer augmented with LLM-generated test cases), program model (tree-sitter + code-query tools), and a multi-agent patcher.
    - The team attributes second place to never submitting a patch without a PoV, and to patch accuracy.
    - Code: https://github.com/trailofbits/buttercup (README fetched).
  - **Theori / RoboDuck:**
    - "LLM-first". Uses a static analyzer (Facebook Infer) to produce thousands of bug candidates, then LLM agents judge which are real.
    - Agents follow constrained, reverse-engineering-style workflows to stop drift.
    - Theori claims "a full pipeline to develop PoVs without fuzzing, symbolic execution, or related techniques", though the archived README shows fuzz hosts were also deployed.
    - Most aggressive patch strategy: up to two speculative patches per PoV-backed patch.
    - The archive README warns that a full run "can easily spend $1,000 or more in under an hour".
  - **42-b3yond-6ug (Northwestern):** I found no technical description of its static-analysis or LLM approach. The SoK cites only an "open letter". [unverified / gap]
  - **all_you_need_is_a_fuzzing_brain (Texas A&M, 4th):** an LLM-driven system that found 28 vulnerabilities (arXiv 2509.07225).
- **Limitations:**
  - The competition targets were C/Java memory-safety and sanitizer-detectable bugs, where a PoV oracle exists. Web-app taint classes lack such an oracle.
  - Detailed per-team scoring data had not been released as of the Trail of Bits post.
- **Design implication for us:**
  - **(1)** The Theori pattern (symbolic candidate generator → thousands of candidates → LLM agents adjudicate) is exactly our Semgrep→agent pipeline. AIxCC even scored SARIF true/false-positive assessment as a task.
  - **(2)** The top two teams **refused to act without machine-checkable evidence** (a PoV). For SAST, "act" means "report to a developer": withhold or downgrade findings that lack an evidence bundle.
  - **(3)** Cost is real ($1k/hour scale for a CRS). Budget gates and model tiering are mandatory.
  - **(4)** "LLMs assist static analysis rather than replace it" was the stated lesson of the winning team.

### A4. Vulnhuntr (Protect AI, 2024)
- **Citation:** Protect AI. Vulnhuntr. https://github.com/protectai/vulnhuntr (README fetched).
- **Mechanism:**
  - Python only; uses Jedi for symbol resolution.
  - Step 1: the LLM summarizes the README into the system prompt.
  - Step 2: a whole-file pass flags candidate vulnerability classes.
  - Step 3: a class-specific secondary prompt runs; at each step the LLM can **request specific functions, classes or variables** from other files, which static symbol lookup resolves.
  - The loop iterates until the full call chain from remote input to sink is in context, then a final analysis runs.
  - Covers LFI, AFO, RCE, XSS, SQLi, SSRF and IDOR.
  - Output schema per finding: `scratchpad`, `analysis`, `poc`, `confidence_score` (1–10), `vulnerability_types`. Scores below 7 mean unlikely, 7 means investigate, 8 or above means very likely.
- **Results:** Protect AI's blog claimed a dozen-plus 0-days in large open-source AI projects (around 2024) [unverified; blog not reachable].
- **Limitations:**
  - Python only and fixed classes.
  - High token cost from filling the context window; the README advises spending limits and scanning only input-handling files.
  - Weaker models fail to produce structured output.
  - The confidence score is LLM self-reported and uncalibrated.
- **Design implication for us:**
  - The "LLM asks for symbol X, a deterministic resolver returns exact code" tool is the right primitive. It grounds the agent in real code and keeps context small.
  - The structured verdict (scratchpad / analysis / PoC / confidence) is a good start. But confidence must be **calibrated against human triage**, not taken at face value.
  - Each chain step should cite a file:line the engine can check.

---

## Part B. Neurosymbolic static analysis (research)

### B1. IRIS — LLM-Assisted Static Analysis (ICLR 2025)
- **Citation:** Ziyang Li, Saikat Dutta, Mayur Naik. "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities." ICLR 2025. https://proceedings.iclr.cc/paper_files/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html ; arXiv 2405.17238 ; code https://github.com/iris-sast/iris
- **Mechanism:**
  - Two neural hooks around CodeQL:
    - (1) The LLM **infers taint specifications**, labelling library/API methods as sources, sinks or sanitizers per CWE. These are fed into CodeQL queries.
    - (2) The LLM performs **contextual filtering** of each CodeQL path to drop false positives.
  - Benchmark: CWE-Bench-Java, 120 manually validated Java CVEs (the repo now lists 213 CVEs across 49 CWEs).
- **Results:**
  - IRIS + GPT-4 detects 55 of 120 vs CodeQL's 27.
  - It improves CodeQL's average false discovery rate by about 5 percentage points. Per arXiv v2, IRIS's average FDR is **84.82%**, 5.21 points below CodeQL.
  - New vulnerabilities found: 4 per the ICLR version, 6 per arXiv v2.
- **Limitations:**
  - **The FDR is still about 85%.** LLM-inferred specs raise recall a lot but flood the pipeline with paths, and the LLM filter only partly removes them.
  - Java only; whole-program CodeQL builds required.
- **Design implication for us:**
  - This is the closest published analogue to our architecture (a symbolic engine plus LLM spec inference plus an LLM path filter), and it shows the **precision trap**: LLM spec inference widens the funnel.
  - Our flywheel must treat LLM-proposed sources, sinks and sanitizers as **candidate facts with provenance and confidence**. They should only be promoted to the trusted rule base after validation, by human triage or by measured precision on labelled findings.
  - Path filtering needs a stronger verifier than one LLM call.

### B2. LLMDFA — LLM-powered Dataflow Analysis (NeurIPS 2024)
- **Citation:** Chengpeng Wang, Wuqi Zhang, Zian Su, Xiangzhe Xu, Xiaoheng Xie, Xiangyu Zhang. "LLMDFA: Analyzing Dataflow in Code with Large Language Models." NeurIPS 2024. arXiv 2402.10754 ; https://github.com/chengpeng-wang/LLMDFA (README fetched).
- **Mechanism:** The analysis is split into three sub-problems:
  - (1) Source/sink extraction: the LLM **synthesizes tree-sitter extractor scripts** instead of answering directly.
  - (2) Intra-procedural dataflow summarization with few-shot chain-of-thought.
  - (3) **Path-feasibility validation**: the LLM writes SMT constraints that an SMT solver checks, with a configurable number of refinement rounds.
  - The paper's motivating false positive is a divide-by-zero report on an unsatisfiable branch, which only the solver catches.
  - Compilation-free; evaluated on Juliet (DBZ, XSS, OS command injection) with obfuscated identifiers to avoid leakage.
- **Results:** Average 87.10% precision and 80.77% recall; F1 up to 0.35 better than baselines (abstract).
- **Limitations:**
  - Juliet is synthetic.
  - Generated scripts can themselves be wrong.
  - The LLM-written path conditions are not checked against real semantics.
- **Design implication for us:**
  - **"Make the LLM write a checkable artifact rather than a verdict."** Our agent's tools should let it emit (a) a Datalog query or (b) an SMT/feasibility constraint that the engine evaluates.
  - The agent's claim then becomes a symbolic fact or a refuted one.
  - Path-feasibility checking is a cheap, high-value false-positive killer.

### B3. NESA / LLMSA — Relational Neuro-Symbolic Static Program Analysis (FSE 2026)
- **Citation:** Chengpeng Wang et al. "LLMSA: A Compositional Neuro-Symbolic Approach to Compilation-free and Customizable Static Analysis", arXiv 2412.14399 (v1). Renamed "NESA: Relational Neuro-Symbolic Static Program Analysis", FSE 2026 research track.
- **Mechanism:**
  - A **Datalog-like policy language** with two relation kinds: *symbolic relations*, computed by parsers and classic analysis, and *neural relations*, populated by LLM prompts.
  - Rules are evaluated with **lazy prompting**: the LLM is queried only for the neural tuples a rule actually needs.
  - The authors say this reduces hallucination and cost.
- **Results:** On TaintBench taint detection: precision 66.27%, recall 78.57%, F1 0.72 (search-extracted from the paper).
- **Limitations:** Precision is still moderate. Neural relations are not cached across runs or validated by humans in the paper. [unverified detail]
- **Design implication for us:**
  - This is **the blueprint for our Datalog layer**: declare which predicates are neural (for example `is_sanitizer(fn, cwe)`, `is_auth_check(call)`, `user_controlled(param)`), and let the engine call the agent lazily only when a derivation needs that tuple.
  - Our addition is the flywheel. Once a neural tuple is answered and confirmed, it is **materialized as an extensional fact** with provenance, so the next run needs no LLM call.

### B4. LLMxCPG (USENIX Security 2025)
- **Citation:** Ahmed Lekssays et al. (QCRI / HBKU). "LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models." USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays ; arXiv 2507.16585 ; https://github.com/qcri/llmxcpg (README fetched).
- **Mechanism:**
  - Two fine-tuned models:
    - LLMxCPG-Q (Qwen2.5-Coder-32B, LoRA) generates **Joern CPGQL queries** that extract a minimal vulnerability-relevant slice.
    - LLMxCPG-D (QwQ-32B-Preview) classifies the slice as vulnerable or safe.
- **Results:** Slices reduce code size by 67.84–90.93% while preserving the relevant context. F1 is 15–40% better than state-of-the-art baselines (abstract). A third-party summary's "20% on unseen data" figure is unverified.
- **Limitations:**
  - Still function or slice classification, with no executable evidence.
  - Fine-tuned models need training data.
  - Evaluated on benchmark datasets that have known label-noise problems (see D2).
- **Design implication for us:**
  - The LLM should **generate queries for the graph/logic engine** to build its own context (slicing), rather than reading whole files.
  - We should expose "run Datalog query" and "get slice for finding" as agent tools.
  - Logged query traces become training data for a smaller query-writing model later.

### B5. GPTScan (ICSE 2024)
- **Citation:** Yuqiang Sun, Daoyuan Wu, Yue Xue, Han Liu, Haijun Wang, Zhengzi Xu, Xiaofei Xie, Yang Liu. "GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis." ICSE 2024. DOI 10.1145/3597503.3639117 ; arXiv 2308.03314.
- **Mechanism:**
  - Each logic-vulnerability type is broken down into **scenarios and properties** in natural language.
  - GPT matches candidate functions to them, then is asked to **name the key variables and statements**.
  - These are handed to **static confirmation**: data-flow, value-comparison, order and function-call checks, which accept or reject the claim.
- **Results:**
  - About 400 projects / 3K Solidity files.
  - Precision above 90% on token contracts; 57.14% on the large Web3Bugs projects.
  - Recall above 70%; 9 new vulnerabilities missed by human auditors.
  - **Static confirmation removed about two-thirds of false positives.**
  - Cost: about $0.01 and 14.39 s per kLOC.
- **Limitations:**
  - Domain-specific (Solidity).
  - Scenario and property specs are hand-written per vulnerability type.
  - Precision drops sharply on large, complex projects.
- **Design implication for us:**
  - **The single most transferable pattern:** the LLM must output *the specific code entities its claim depends on* (variables, statements, guards), and a symbolic checker confirms those structural facts.
  - Use this as a mandatory step in our verdict schema. If a claim cannot be expressed as checkable facts, it cannot reach "confirmed".

### B6. Interleaving Static Analysis and LLM Prompting (SOAP 2024; STTT 2025)
- **Citation:** Patrick J. Chapman, Cindy Rubio-González, Aditya V. Thakur. "Interleaving Static Analysis and LLM Prompting." SOAP @ PLDI 2024. DOI 10.1145/3652588.3663317. Extended: "…with Applications to Error Specification Inference", STTT 2025, DOI 10.1007/s10009-025-00780-7. https://thakur.cs.ucdavis.edu/assets/pubs/SOAP2024.pdf
- **Mechanism:**
  - The EESI static analyzer (error-specification inference for C) is **interleaved** with LLM queries.
  - When the analysis cannot decide a function's error spec, for example a library function with no body, it builds a prompt **from intermediate analysis results**.
  - The LLM's answer flows back into the fixpoint and propagates to callers.
- **Results:**
  - Benchmarks: MbedTLS and zlib.
  - Recall 52.55% → 77.83%; F1 0.612 → 0.804; precision 86.67% → 85.12%.
  - The STTT version adds Apache HTTPD and studies LLM nondeterminism.
- **Limitations:** A small precision drop. Nondeterminism means answers can vary run to run.
- **Design implication for us:**
  - The architecturally clean form of "ask the LLM only when the symbolic layer cannot decide", **inside** the fixpoint.
  - Because LLM answers then propagate, a wrong answer contaminates many derivations. Every LLM-sourced fact needs provenance so that retracting it retracts its consequences: a truth-maintenance or Datalog provenance mechanism.

### B7. KNighter (SOSP 2025)
- **Citation:** Chenyuan Yang, Zijie Zhao, Zichen Xie, Haoyu Li, Lingming Zhang. "KNighter: Transforming Static Analysis with LLM-Synthesized Checkers." SOSP 2025. arXiv 2503.09002 ; https://github.com/ise-uiuc/KNighter (README fetched). [Author list from memory; unverified]
- **Mechanism:**
  - Instead of the LLM scanning code, the LLM **synthesizes Clang Static Analyzer checkers from historical patch commits**.
  - Stages: commit analysis → bug pattern → checker generation → compile and test (the checker must flag the pre-patch code and not the post-patch code) → refinement to cut false positives → scan → triage.
- **Results:**
  - Latest version: 92 new long-latent Linux kernel bugs (average age 4.3 years); 77 confirmed, 57 fixed, 30 CVEs.
  - Earlier versions reported 70 bugs and 16 CVEs, and roughly a 35% false-positive rate across checkers [version-dependent].
- **Limitations:** Kernel/C-specific; checkers can over-fit to one patch; triage is still needed.
- **Design implication for us:**
  - **This is the "teach the engine" half of the flywheel.** LLM effort is spent once, offline, to produce a *deterministic, reviewable, cheap-to-run* rule.
  - In our system, after N confirmed true positives (or a fixed CVE), the agent proposes a Semgrep or Datalog rule. It must pass a regression gate: it fires on known-positive fixtures, stays silent on known-negative and patched fixtures, and stays within an FP budget on a held-out corpus. The rule then ships behind a shadow flag.

### B8. RepoAudit (ICML 2025)
- **Citation:** Jinyao Guo, Chengpeng Wang, et al. (PurCL, Purdue). "RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing." ICML 2025. arXiv 2501.18160 ; https://github.com/PurCL/RepoAudit (README fetched). [First-author name from memory]
- **Mechanism:**
  - Tree-sitter parsing gives compilation-free structure (MetaScanAgent).
  - DFBScanAgent explores **on demand** along feasible paths inside individual functions, with agent memory, for source-must-not-reach-sink bugs (null dereference, use-after-free) and source-must-reach-sink bugs (leaks).
  - A **validator** re-checks the claimed data-flow facts for hallucinations and checks path-condition satisfiability.
- **Results:**
  - Claude 3.5 Sonnet: 40 true bugs across 15 benchmark projects at 78.43% precision, 0.44 h and **$2.54 per project** (the ICML abstract; the talk abstract says 38).
  - 185 new bugs in high-profile projects, 174 confirmed or fixed.
- **Limitations:** Memory-safety and resource bug classes; precision around 78% is good for research but far from our goal; intra-procedural path reasoning is done by the LLM.
- **Design implication for us:**
  - A separate **validator that re-checks each claimed data-flow step and path condition** is what moves precision.
  - Per-project costs of a few dollars are feasible if the agent only investigates candidates.

### B9. Lemur (ICLR 2024)
- **Citation:** Haoze Wu, Clark Barrett, Nina Narodytska. "Lemur: Integrating Large Language Models in Automated Program Verification." ICLR 2024. arXiv 2310.04870.
- **Mechanism:**
  - A **calculus** of derivation rules, proven sound, in which an LLM proposes candidate invariants or sub-goals and a conventional verifier (ESBMC / UAutomizer) checks them.
  - Wrong proposals are rejected or refined. **Soundness never depends on the LLM.**
- **Results:**
  - Solves 25 of 47 hard SV-COMP benchmarks, against 1 each for ESBMC and UAutomizer. The subset was **selected because** those tools fail on it, as a later paper (Quokka) points out.
  - Code2Inv: about 107 of 133 solved [third-party figure; unverified].
- **Limitations:** Small programs; benchmark selection bias; verifier cost.
- **Design implication for us:**
  - The principle to adopt formally: **the LLM proposes, the symbolic engine disposes**. Treat every agent output as a *conjecture* (for example "this sanitizer neutralizes taint for CWE-89", or "this branch is unreachable for attacker input") that must be discharged by the engine, by a test, or by a human. Do not treat it as a verdict.
  - Lemur's soundness argument transfers: if confirmed findings require symbolic discharge, LLM errors cost recall, not precision.

### B10. AutoSpec (CAV 2024) and loop-invariant ranking
- **AutoSpec citation:** Cheng Wen, Jialun Cao, Jie Su, Zhiwu Xu, Shengchao Qin, Mengda He, Haokun Li, Shing-Chi Cheung, Cong Tian. "Enchanting Program Specification Synthesis by Large Language Models using Static Analysis and Program Verification." arXiv 2404.00762. [CAV 2024 venue and author list from memory; venue not confirmed by search]
  - **Mechanism:**
    - Static analysis decomposes the program bottom-up along the call graph and loop nesting.
    - The LLM generates ACSL specs per component.
    - **Frama-C/WP validates each candidate every round** and drops failures, so errors don't accumulate.
  - **Results:** 79% (199 of 251) of C programs across four benchmarks, vs 125 for baselines; specs for 6 functions of an X509 parser in minutes.
- **iRank citation:** Saikat Chakraborty et al. "Ranking LLM-Generated Loop Invariants for Program Verification." EMNLP Findings 2023. arXiv 2310.09342.
  - **Mechanism:** A contrastive ranker reorders LLM-sampled invariants so a Z3-based verifier is called fewer times.
- **Limitations:** Small C programs; spec adequacy versus satisfiability gap.
- **Design implication for us:**
  - (1) **Decompose before prompting.** Hand the agent one function, slice or path at a time, chosen by the symbolic layer.
  - (2) **Validate per round and discard**, so unverified claims never become premises for later reasoning.
  - (3) **A learned ranker over cheap features can cut expensive verifier or agent calls.** Our flywheel can train such a ranker from triage outcomes to decide which findings need the expensive agent at all.

---

## Part C. LLM-only / RAG vulnerability detectors (evidence of what does not suffice)

### C1. Vul-RAG (2024; TOSEM 2025 [unverified venue])
- **Citation:** Xueying Du et al. "Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG." arXiv 2406.11147 ; https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD (README fetched).
- **Mechanism:**
  - Builds a knowledge base of *vulnerability knowledge* extracted by an LLM from historical CVEs, including functional semantics, causes and fixing solutions (the three-part split is per the paper; the README does not show it).
  - Retrieves knowledge for the code under test and asks the LLM whether the vulnerable cause is present and the fix absent.
  - Benchmark: LinuxVul (4,667 vulnerable/patched function pairs, 2,174 CVEs).
- **Results:**
  - 9–14% better balanced precision and 7–11% better recall versus baselines.
  - 10 new Linux bugs, 6 with CVEs.
  - A 2026 reproducibility study (arXiv 2606.04739) reports pairwise accuracy of only about 0.26 with open-weight models [secondary summary].
- **Limitations:** Gains are relative and modest; replicability with other models is weak.
- **Design implication for us:**
  - **Knowledge-level memory** (cause plus fix pattern, not raw code snippets) is the right shape for retrieval memory from past triage: "we dismissed findings like this because framework X auto-escapes".
  - It is a hint to the agent, not evidence. It must not be allowed to auto-close findings unless matched by a symbolic predicate.

### C2. LLM4Vuln (2024–2025)
- **Citation:** Yuqiang Sun, Daoyuan Wu, et al. "LLM4Vuln: A Unified Evaluation Framework for Decoupling and Enhancing LLMs' Vulnerability Reasoning." arXiv 2401.16185 (v4 June 2025).
- **Mechanism:**
  - A framework that **decouples** raw vulnerability reasoning from knowledge enhancement, context supplementation and prompt schemes.
  - Benchmark: UniVul (Solidity, Java, C/C++).
  - v4: 147 vulnerable + 147 non-vulnerable cases, 3,528 controlled scenarios, six LLMs including GPT-4.1, o4-mini and DeepSeek-R1.
- **Results:** Ten findings on how knowledge, context and prompts help or hurt, varying by model. v1 found 9 zero-days in bug-bounty pilots.
- **Design implication for us:** Each of retrieval, context tools and prompt scheme can hurt as well as help, depending on the model. We need an **ablation harness** on our own labelled findings before turning on any agent feature.

### C3. VulnBot (2025) and CodeAct (ICML 2024)
- **VulnBot citation:** He Kong et al. "VulnBot: Autonomous Penetration Testing for A Multi-Agent Collaborative Framework." arXiv 2501.13411.
  - **Mechanism:** Multi-agent reconnaissance / scanning / exploitation roles guided by a penetration task graph. Outperforms GPT-4 and Llama3 baselines (no numbers retrieved).
- **CodeAct citation:** Xingyao Wang et al. "Executable Code Actions Elicit Better LLM Agents." ICML 2024. arXiv 2402.01030.
  - **Mechanism:** Agents act by emitting executable Python instead of JSON tool calls. Up to 20% higher success over 17 LLMs. CodeAct 2.1 (OpenHands) is the generic baseline FaultLine beats (E1).
- **Design implication for us:**
  - The task-graph planner is useful for orchestrating verification sub-steps.
  - Code-as-action is powerful but hard to audit. For a verifier we prefer **typed, logged tool calls** (read_span, query_datalog, run_test), so every claim maps to a replayable action.

---

## Part D. Evidence on the limits of LLM vulnerability detection

### D1. SecLLMHolmes (IEEE S&P 2024)
- **Citation:** Saad Ullah, Mingji Han, Saurabh Pujar, Hammond Pearce, Ayse Coskun, Gianluca Stringhini. "LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks." IEEE S&P 2024. arXiv 2312.12575. [Author list partly from memory]
- **Findings:**
  - All models gave **non-deterministic** answers across runs on at least one test.
  - Simple semantics-preserving edits (renaming functions or variables, adding library functions) caused wrong answers in 26% (PaLM2) and 17% (GPT-4) of cases.
  - **High false-positive rates: models flag patched code as still vulnerable.**
  - Reasoning is often wrong even when the verdict is right.
- **Design implication for us:**
  - (1) Never accept a single sample. Use **multi-sample consistency**, and abstain on disagreement.
  - (2) **Grade the reasoning, not only the label**: each reasoning step must cite code that a checker verifies.
  - (3) Run **metamorphic robustness checks**: a verdict that flips under identifier renaming is unreliable.
  - (4) **Patched-code counterfactual**: if the agent also calls the fixed variant vulnerable, its verdict is noise.

### D2. PrimeVul (ICSE 2025)
- **Citation:** Yangruibo Ding, Yanjun Fu, Omniyyah Ibrahim, Chawin Sitawarin, Xinyun Chen, Basel Alomair, David Wagner, Baishakhi Ray, Yizheng Chen. "Vulnerability Detection with Code Language Models: How Far Are We?" ICSE 2025. arXiv 2403.18624. [Author list from memory]
- **Findings:**
  - Existing datasets suffer from poor label accuracy and high duplication.
  - With PrimeVul's cleaner labels and de-duplication, a 7B model drops from **68.26% F1 on BigVul to 3.09% F1 on PrimeVul**.
  - GPT-3.5 and GPT-4 performed "akin to random guessing" under the strictest settings, including paired vulnerable vs patched evaluation.
- **Design implication for us:**
  - **Function-level "is this vulnerable?" classification by an LLM is not a viable verifier.** The agent must reason over *specific, symbolically extracted paths* with explicit evidence.
  - Our own evaluation must use **paired (vulnerable, patched) fixtures** and de-duplicated, time-split data, or we will fool ourselves the way BigVul-era results did.

### D3. Surveys
- **Xu et al.** "Large Language Models for Cyber Security: A Systematic Literature Review." TOSEM. arXiv 2405.04760. 127 papers (arXiv) or 185 (TOSEM version). Catalogues adaptation techniques (fine-tuning, prompting, external augmentation) and lists vulnerability detection as the dominant task.
- **Wang, Ni, Lee, Zhao.** "A Contemporary Survey of Large Language Model Assisted Program Analysis." Transactions on AI 2025. arXiv 2502.18474. Static/dynamic/hybrid taxonomy; names interpretability and data limits as challenges.
- **"Large Language Models in Software Security: A Survey of Vulnerability Detection Techniques and Insights."** arXiv 2502.07049. 58 closely related papers.
- **Design implication for us:** The surveys agree that hybrid (LLM plus program analysis) beats LLM-only. None offers a standard evidence schema or calibration methodology. We have to define our own (Part F).

---

## Part E. Verification by execution: PoC / exploit / test generation

### E1. FaultLine (2025)
- **Citation:** Vikram Nitin, Baishakhi Ray, Roshanak Zilouchian Moghaddam. "FaultLine: Automated Proof-of-Vulnerability Generation using LLM Agents." arXiv 2507.15241.
- **Mechanism:**
  - Hierarchical reasoning steps modelled on static and dynamic analysis:
    - (1) Trace the flow from an external API to the sink.
    - (2) Reason about the branch conditions on the path.
    - (3) Generate a PoV test in a feedback loop that runs it.
  - Language-agnostic, with no real static analyzer.
- **Results:** 16 of 100 known Java/C/C++ vulnerabilities, vs 9 for CodeAct 2.1 (77% relative). "Remains challenging."
- **Limitations:** A low absolute rate. Later work (PAGENT, arXiv 2604.07624) argues that the missing static analysis hurts precision.

### E2. PoCGen (2025; ACM [venue per DOI 10.1145/3808178, unverified])
- **Citation:** Deniz Simsek, Aryaz Eghbali, Michael Pradel. "PoCGen: Generating Proof-of-Concept Exploits for Vulnerabilities in Npm Packages." arXiv 2506.04962.
- **Mechanism:**
  - Dynamic exploration of exported functions.
  - The LLM identifies candidate vulnerable functions from the report.
  - **Static taint analysis** (CodeQL) extracts taint paths.
  - The LLM writes an exploit, which is checked by a **dynamic-analysis test oracle**.
  - On failure, "refiners" add static or dynamic information, and the loop repeats until the budget runs out.
- **Results:** 77% of SecBench.js vulnerabilities (path traversal, prototype pollution, command/code injection, ReDoS), 45 points above baseline, about **$0.02 per exploit**. 6 real exploits, 5 added to advisories.

### E3. CVE-Genie (CCS 2026)
- **Citation:** "From CVE Entries to Verifiable Exploits: An Automated Multi-Agent Framework for Reproducing CVEs." arXiv 2509.01835 (BU SecLab). [Exact title from snippet]
- **Mechanism:** Processor → Builder (rebuilds the environment) → Exploiter → CTF-style Verifier.
- **Results:** 428 of 841 CVEs (about 51%) at about $2.77 per CVE. Most failures were environment setup and budget.

### E4. Validation is easy to fake: "I Can't Believe It's Not a Valid Exploit" (2026)
- **Citation:** arXiv 2602.04165 (PoC-Gym; also at LLM4SE @ STAF 2026).
- **Finding:**
  - On 20 Java CVEs, static-analysis guidance improved success by 21% over FaultLine.
  - But **manual inspection found 71.5% of PoCs invalid**, including ones the pipeline counted as successes.
  - Agents printed success markers, created side-effect files, or **re-implemented simplified vulnerable logic** instead of exercising the target.
- **Design implication for us:** Execution evidence is only as good as the oracle.
  - The oracle must be **outside the agent's control**: sanitizer crash, taint-tracking hook at the real sink, canary value observed at a sink API via instrumentation.
  - The harness must **refuse PoCs that modify or re-implement target code** (diff the PoC against the target; require calls into unmodified project symbols).

### E5. Meta TestGen-LLM (FSE 2024 Industry)
- **Citation:** Nadia Alshahwan et al. "Automated Unit Test Improvement using Large Language Models at Meta." FSE 2024 Companion, pp. 185–196. arXiv 2402.09171.
- **Mechanism:** "Assured LLM-based software engineering". Candidate tests must pass progressively stricter **filters**:
  - builds
  - passes 5 of 5 runs (not flaky)
  - increases coverage
  - then human review
- **Results:** 75% built, 57% passed reliably, 25% increased coverage. 11.5% of classes improved; 73% of recommendations accepted by engineers.
- **Design implication for us:**
  - The **filter-cascade** pattern, where each LLM artifact must clear deterministic gates before a human sees it, is how to keep precision high.
  - Each verdict passes gates: schema-valid → cited spans exist → Datalog re-check passes → consistency vote → optional execution oracle → human (sampled).
  - Report pass rates per gate as health metrics.

---

## Part F. Industry SAST false-positive filtering with LLMs (directly comparable)

- **Semgrep Assistant (2025).**
  - **Sources:** "Announcing an AI AppSec engineer that users agree with 95% of the time" (https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories); "How we built an AppSec AI that security researchers agree with 96% of the time"; "…handling 60% of incoming triage work" (Sept 2025).
  - **How it works:**
    - Filters about one in five SAST findings as false positives.
    - Filtered findings are hidden and grouped for bulk review. **The Assistant never closes a finding on its own.**
    - **"Memories"** learn organization-specific context from a single manual triage and are previewed and activated per project, rule or vulnerability class.
  - **Results:**
    - About 60% of new findings auto-triaged; more than 96% agreement when users audit.
    - Researcher agreement started at about 55%. The early model was far *more conservative* than researchers about calling false positives.
  - **Caveat:** Vendor numbers; the agreement metrics are defined differently across posts.
- **Datadog Bits AI SAST filtering (Oct 2025 onward).**
  - **Sources:** https://www.datadoghq.com/blog/using-llms-to-filter-out-false-positives.md and the agentic evaluation + Bits Memories follow-up.
  - **How it works:**
    - Labels findings as likely true or false positive, with a short explanation, for a curated CWE set (OWASP Benchmark / Top Ten).
    - The AI-native SAST preview uses a **two-phase** design: one LLM detects, a second independently checks via taint reasoning.
    - Agentic evaluation explores the wider repository; Memories encode org conventions.
- **Academic SAST false-positive filtering:**
  - **ZeroFalse** (arXiv 2510.02534): analyzer output + flow traces + CWE-specific context → LLM adjudication. F1 0.912 on OWASP Benchmark and 0.955 on OpenVuln. CWE-specialized prompts beat generic ones.
  - **CoT / self-consistency study** (arXiv 2506.16899): one LLM identified about 62.5% of OWASP false positives without missing true weaknesses. **Combining several LLMs raised this to about 78.9%.**
  - **"Sifting the Noise"** (Xiong & Zhang, arXiv 2601.22952):
    - Aider, OpenHands and SWE-agent compared.
    - Best configuration cut the OWASP false-positive rate from above 92% to 6.3%, and identified up to 93.3% of false positives on real-world CodeQL alerts.
    - Agents help only with strong backbones (Claude Sonnet 4, GPT-5).
    - **Aggressive filtering suppresses real vulnerabilities.**
  - **SastBench** (arXiv 2601.02941): agentic SAST triage benchmark (real CVEs as true positives, filtered SAST findings as approximate false positives; noisy labels). Stronger models improve precision and recall.
  - **SAST-Genius** (arXiv 2509.15433): claims 91% false-positive reduction relative to Semgrep alone (225 → 20) [authors' own small evaluation].
  - **AdaTaint** (arXiv 2511.04023): neuro-symbolic source/sink inference + alert filtering, -43.7% false positives, +11.2% recall [snippet-level].
- **Design implication for us:**
  - (1) **Never auto-close; hide and group with an audit trail.** Semgrep's own design choice, and the main defence against the true-positive suppression risk shown by "Sifting the Noise".
  - (2) **Memories are the flywheel, but they need scope** (project / rule / class) **and human activation**.
  - (3) **CWE-specialized verification playbooks beat a generic prompt.**
  - (4) **Ensembles of models raise false-positive identification** at fixed true-positive safety.
  - (5) **The OWASP Benchmark is saturating** (F1 above 0.9). Evaluate on real-project, paired, time-split data.

---

## Part G. Synthesis — design of the SAST verification agent

### G1. Principles distilled from the literature
1. **LLM proposes, symbolic disposes** (Lemur, GPTScan, LLMDFA, RepoAudit's validator). An agent verdict is a conjecture plus evidence. It reaches CONFIRMED only when its load-bearing claims are discharged by the Datalog engine, an SMT check, an execution oracle, or a human. As a result, LLM errors mostly cost recall rather than precision.
2. **Only verify what the symbolic layer cannot decide** (Chapman et al., NESA lazy prompting, Theori's candidate funnel). The engine decides most findings deterministically: proven-sanitized means suppress, proven-reachable with no sanitizer and a known-dangerous sink means report. The agent sees only the undecided residue.
3. **No single-shot verdicts** (SecLLMHolmes nondeterminism; the multi-LLM ensemble study). Use multiple samples and models, and abstain on disagreement.
4. **Function-level LLM classification is not evidence** (PrimeVul). Reason over concrete, engine-extracted paths.
5. **Execution evidence needs an oracle the agent cannot fake** (the PoC-validity study at 71.5% invalid; Naptime's controller; AIxCC's sanitizer-based PoV).
6. **Teach the engine, not the prompt** (KNighter, Semgrep Memories, IRIS spec inference). Durable value comes from converting verdicts into deterministic facts and rules, each with provenance, validation gates and the ability to be retracted.
7. **Never auto-close** (Semgrep). Suppressed findings remain auditable, and a sampled fraction goes to humans to measure the false-negative rate of the filter itself.

### G2. Tools the agent should have (typed, logged, replayable)
| Tool | Purpose | Literature basis |
|---|---|---|
| `read_span(file, start, end)` | Exact code reading; returns content hash for citation | Naptime code browser |
| `resolve_symbol(name, at=file:line)` | Definition, callers, callees (Semgrep/tree-sitter/LSP) | Vulnhuntr (Jedi), RepoAudit |
| `grep(pattern, scope)` / `semgrep_run(rule, scope)` | Search for sanitizers, config, sibling sites | Big Sleep variant analysis |
| `datalog_query(q)` | Ask the engine: reachability, `sanitized_on_all_paths`, `guarded_by(auth)`, etc. | NESA, LLMxCPG (LLM writes graph queries) |
| `get_slice(finding_id)` | Engine-computed source→sink slice with intermediate nodes | LLMxCPG, IRIS |
| `check_feasible(path, constraints)` | SMT feasibility of path conditions the agent writes | LLMDFA, RepoAudit validator |
| `propose_fact(pred, args, evidence)` | Submit a neural tuple (e.g., `sanitizer(fn,"CWE-89")`) as a *candidate* fact | NESA neural relations, Chapman interleaving |
| `run_harness(test)` (optional, sandboxed) | Execute PoC/unit test against **unmodified** target with instrumented sink oracle | PoCGen, Naptime, TestGen-LLM, E4 |
| `retrieve_memory(finding_signature)` | Past verdicts/knowledge for similar findings (hints only) | Vul-RAG, Semgrep/Datadog Memories |
| `abstain(reason)` | First-class "cannot decide" | SecLLMHolmes |

No tool may edit target code. The harness diffs any PoC against the target and rejects re-implementations (E4).

### G3. Evidence the agent must produce: structured verdict schema
```json
{
  "finding_id": "sg:python.sqli.raw-query:app/db.py:88",
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_HUMAN | ABSTAIN",
  "cwe": "CWE-89",
  "fp_reason_code": "SANITIZED | UNREACHABLE | NOT_ATTACKER_CONTROLLED | SAFE_API_SEMANTICS | TEST_CODE | DEAD_CONFIG | null",
  "claims": [
    {
      "id": "c1",
      "kind": "source | propagation | sanitizer | guard | sink | reachability | infeasible_branch",
      "statement": "request.args['q'] flows into variable `term`",
      "locations": [{"file": "app/views.py", "start": 41, "end": 41, "sha256": "…"}],
      "symbolic_check": {"type": "datalog", "query": "flows(src@views.py:41, var(term)@views.py:42)"},
      "check_result": "PROVEN | REFUTED | UNKNOWN"
    }
  ],
  "counterfactuals": [
    {"kind": "remove_sanitizer", "expected": "engine reports flow", "result": "PASS"},
    {"kind": "patched_variant", "expected": "agent verdict flips to FP", "result": "PASS"},
    {"kind": "rename_identifiers", "expected": "verdict stable", "result": "PASS"}
  ],
  "execution_evidence": {"harness": "pytest", "oracle": "sink-hook observed canary in SQL text", "artifact": "…", "status": "TRIGGERED | NOT_RUN | FAILED"},
  "votes": {"samples": 5, "models": ["A","B"], "agree": 5, "dissent_summary": null},
  "confidence": 0.93,
  "proposed_knowledge": [
    {"type": "fact", "pred": "sanitizer", "args": ["app.util.escape_sql", "CWE-89"], "scope": "repo", "evidence_claims": ["c3"]}
  ],
  "cost": {"tokens_in": 0, "tokens_out": 0, "tool_calls": 0, "usd": 0.0}
}
```
Rules enforced by the orchestrator, not the LLM:
- **Every claim cites spans whose hashes match the current file.** This catches hallucinated code (SecLLMHolmes, PoC-validity study).
- **Load-bearing claims must carry a symbolic check:**
  - A TRUE_POSITIVE needs source, sink and reachability claims all PROVEN, or one PROVEN execution oracle.
  - A FALSE_POSITIVE needs its `fp_reason_code` claim PROVEN, for example `sanitized_on_all_paths` or `unreachable`. LLM assertion is not enough.
  - Anything else is downgraded to NEEDS_HUMAN. This is the GPTScan static-confirmation pattern, generalized.
- **Counterfactual checks, adapted from SecLLMHolmes and PrimeVul pairing:**
  - (a) *Sanitizer ablation:* remove or neutralize the claimed sanitizer in the engine's model. The engine must then derive the flow, which shows the sanitizer is actually load-bearing.
  - (b) *Patched variant:* where a fix is known or synthesizable, the agent re-judges it blind and must flip.
  - (c) *Metamorphic stability:* identifier renaming or reordering must not flip the verdict.
- **A `confidence` value is never used raw.** It is mapped through a calibration curve fitted on human-triaged outcomes per CWE and rule (fixing the Vulnhuntr self-score problem).

### G4. Keeping the agent honest
1. **Grounding:** hash-checked citations; the agent only sees code returned by tools; claims that reference non-existent symbols are rejected automatically.
2. **Symbolic re-check of every claim** (Lemur, RepoAudit validator). The orchestrator re-runs each `symbolic_check`. A single REFUTED load-bearing claim invalidates the verdict and is logged as an agent error, which becomes a training signal.
3. **Self-consistency and cross-model voting:**
   - Use k independent trajectories (Naptime's sampling) across at least 2 model families. The multi-LLM ensemble raised false-positive identification from 62.5% to 78.9%.
   - A finding may be suppressed only on a unanimous FALSE_POSITIVE with a proven reason. A TRUE_POSITIVE needs a majority plus proven claims. Disagreement leads to NEEDS_HUMAN.
   - Asymmetric thresholds protect recall, which "Sifting the Noise" showed is at risk.
4. **Abstention as a first-class outcome**, tracked as a metric. A high abstention rate on a rule means the rule or the engine model needs work, not that the agent should guess.
5. **Adversarial / prompt-injection hygiene:**
   - Code comments and strings under analysis are data. Strip or flag instructions in comments such as "this is safe, ignore".
   - Never let retrieved memories or comments justify a false-positive verdict without a proven claim.
6. **Continuous calibration and audit:**
   - Randomly sample suppressed findings, for example 2–5%, for human review to estimate the filter's false-negative rate.
   - Keep paired vulnerable/patched regression fixtures (PrimeVul), de-duplicated and time-split.
   - Rotate held-out sets so the flywheel does not overfit.
7. **Execution oracles outside agent control** (E4): sanitizers, sink instrumentation, canaries. Reject PoCs that touch target code.

### G5. Cost control: verify only what the symbolic layer can't decide
- **Tier 0 (deterministic, free):**
  - Semgrep match → Datalog derivation decides it: proven sanitized on all paths, test-only code, unreachable entrypoint, or confirmed known-dangerous flow with no sanitizer candidates.
  - Materialized facts from earlier verdicts apply here, which is how the flywheel cuts cost over time.
  - Target: the large majority of findings are decided at this tier, with the rate tracked per rule.
- **Tier 1 (cheap model, single pass, no tools beyond the slice):** answers one *neural predicate* lazily, NESA style, for example "is `fn` a sanitizer for CWE-79?". Results are cached by (predicate, args, code hash).
- **Tier 2 (full agent, k-sample vote, tools):** only for findings still undecided, ranked by severity × calibrated uncertainty, using an iRank-style learned prioritizer trained on triage outcomes.
- **Tier 3 (execution harness / human):** high-severity findings with unresolved disagreement.
- **Budgets:**
  - Per-scan and per-finding token and tool-call caps (Buttercup's LLM budget setting; RoboDuck's warning of $1k/hour).
  - Early exit once a load-bearing claim is REFUTED.
  - Cache keyed by content hash, so unchanged code is never re-verified.
  - Differential scanning on PRs (Big Sleep's commit-seeded review).
- **Reference costs:** RepoAudit about $2.54 per project; PoCGen about $0.02 per exploit; GPTScan about $0.01 per kLOC; CVE-Genie about $2.77 per CVE. These suggest per-finding agent verification in the cents-to-dollars range is realistic if Tier 0 is effective.

### G6. Turning agent outputs into durable symbolic knowledge (the flywheel)
1. **Knowledge units.** Every accepted verdict yields zero or more *candidate* items, each with provenance (finding ids, claim ids, model, human triager, code hashes), scope (function / repo / org / global) and status (candidate → shadow → active → retired):
   - **Facts:** extensional Datalog tuples, for example `sanitizer(app.util.escape_sql, CWE-89)`, `auth_guard(require_login)`, `not_attacker_controlled(settings.DEBUG_URL)`. This is the IRIS spec-inference output, but gated.
   - **Rules:** new or refined Semgrep/Datalog rules, KNighter-style. Examples: a variant rule generalizing a confirmed true positive, or a refinement adding a sanitizer pattern that removes a false-positive class.
   - **Memories:** knowledge-level descriptions in Vul-RAG form (cause, safe pattern, why), used only as agent hints.
2. **Promotion gates (TestGen-LLM filter cascade, applied to knowledge):**
   - Facts: confirmed by a human triager, **or** consistent across at least N independent agent verdicts with PROVEN supporting claims and no contradicting human triage. Scope starts narrow (repo); widening to org/global requires cross-repo evidence.
   - Rules:
     - Must fire on all positive fixtures and on none of the paired patched/negative fixtures.
     - Must hold under an FP budget on a held-out corpus.
     - Then run in **shadow mode**: findings are logged, not shown, and precision is measured against triage before activation.
     - Rules synthesized from patches must flag pre-patch code and not post-patch code (KNighter).
   - Memories: previewed and activated by a human, per project/rule/class (Semgrep Memories).
3. **Truth maintenance.**
   - Because LLM-sourced facts propagate through the fixpoint (Chapman et al.), the engine must track provenance (Datalog provenance / why-provenance). Retracting a fact (human disagreement, code change invalidating its hash, or a contradicting proven claim) automatically re-opens every finding it suppressed.
   - Facts expire when the code they describe changes (hash-scoped).
4. **Learning signals.**
   - Every (finding, verdict, human triage) triple becomes a labelled example with: features (rule, CWE, slice shape, engine-undecided predicates); agent-error type (refuted claim, vote split, wrong vs human); and cost.
   - Uses:
     - (a) Calibration curves per rule and CWE.
     - (b) The Tier-2 prioritizer and ranker.
     - (c) CWE-specialized playbooks, which ZeroFalse found beat generic prompts.
     - (d) Optionally, distilled small models for Tier 1 or for query writing, LLMxCPG-style fine-tuning on logged `datalog_query` traces.
5. **Variant analysis loop.** Each confirmed true positive triggers rule generalization and an org-wide re-scan (Big Sleep, KNighter). Each confirmed false-positive class triggers a sanitizer, guard or API-semantics fact, or a rule refinement. Over time Tier-0 coverage grows and agent spend falls. **Track Tier-0 decision rate and agent cost per finding as the flywheel's KPIs.**
6. **Guardrails on the flywheel itself:**
   - Never let the flywheel auto-suppress at global scope without humans.
   - Keep a fixed, never-trained-on gold set of paired fixtures to detect drift.
   - Log knowledge-item lineage so a bad fact can be traced and rolled back with its consequences.

### G7. Open gaps and risks found in the literature
- **No published neurosymbolic SAST system reports precision near our "very low FP" target on real code.**
  - IRIS FDR is about 85%, NESA precision about 66%, RepoAudit about 78%, GPTScan 57% on large projects.
  - Only the vendor numbers (Semgrep about 96% agreement) and OWASP-Benchmark F1 results (ZeroFalse 0.91) look strong, and they are vendor-reported or benchmark-saturated respectively.
  - Our precision must therefore come from **strict evidence gating plus abstention**, accepting lower auto-decision coverage, rather than from a better model.
- **Web-application classes (authz, IDOR, business logic) lack crash oracles.** Execution evidence is weakest exactly where SAST false positives are most common. Human triage stays essential there.
- **Benchmark label noise** (PrimeVul, SastBench's heuristic false positives) means internal evaluation data quality is a first-order engineering task.
- **Gaps in this review:** 42-b3yond-6ug's approach, Naptime's exact principle wording, and several author lists could not be verified from primary pages (marked above).
