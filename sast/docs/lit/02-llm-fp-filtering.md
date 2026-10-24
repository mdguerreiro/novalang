# 02 — LLM-based false-positive filtering / alert verification for static analysis

Cluster: LLMs that adjudicate static-analysis warnings (TP vs FP), the hybrid static+LLM systems that do this best, vendor products that ship it, and the benchmarks used to measure it.
Target design: Semgrep (+taint mode) → Datalog reasoning layer → LLM verifier agent → data flywheel (agent verdicts + human triage teach the engine).
Date of review: 2026-10-24.

## 0. Evidence provenance (read this first)

The research environment only let `WebFetch` reach `github.com`. arXiv, ACM DL, researchr, semgrep.dev, docs.github.com, datadoghq.com and similar hosts all failed DNS from the fetch tool, and shell `curl` was blocked by the proxy. So:

- **[R]** = I read the primary artifact directly (a GitHub README of the paper/tool repository).
- **[S]** = number taken from a search-engine extract of the cited primary page (arXiv abstract/HTML, vendor blog, or docs). These extracts quote the page, but I did not see the whole paper, so tables, ablations and fine print may be missing.
- **[unverified]** = only secondary summaries, figures that conflict between versions, or my own inference.

Anything quantitative not tagged [R] or [S] should be treated as [unverified]. Re-check every number against the PDF before quoting it in a design decision or external document.

---

## 1. Academic work: LLM adjudication of static-analysis warnings

### 1.1 LLM4SA: Wen et al. (TKDD 2024)

- **Citation.** Chen Wen, Yuandao Cai, Bin Zhang, Jie Su, Zhiwu Xu, Dugang Liu, Shengchao Qin, Zhong Ming, Cong Tian. "Automatically Inspecting Thousands of Static Bug Warnings with Large Language Model: How Far Are We?" *ACM Transactions on Knowledge Discovery from Data* (TKDD), 2024. DOI 10.1145/3653718. https://dl.acm.org/doi/10.1145/3653718
- **Problem.** C/C++ static bug finders produce warnings that are mostly false. Manual inspection doesn't scale to thousands of warnings.
- **Mechanism.** A static analysis pass pulls the code relevant to each warning by **program-dependence traversal guided by the warning report**, which is a slice rather than the whole file. The LLM then gets **customized questions enriched with domain knowledge and representative cases** (per-bug-type prompts with few-shot examples). [S]
- **Results.** Juliet plus 11 real-world C/C++ projects, **9,547 warnings: precision 81.13%, recall 94.64%**. [S] I did not see the per-tool (Cppcheck/Infer/CSA) breakdown or the per-project split.
- **Limitations.** Juliet is synthetic and almost certainly in training corpora (see §4). "Precision" here measures the TP verdicts, so roughly one in five "real bug" verdicts is wrong. The recall of about 95% means about 5% of true bugs would be auto-dismissed if the filter were trusted blindly.
- **Design implication for us.** LLM4SA set the template that later work refines: slice, then bug-type-specific question, then few-shot cases. For us, the "slice" is the Semgrep taint trace plus the Datalog provenance of the finding, and the "bug-type question" is a per-CWE checklist (§6).

### 1.2 LLM4FPM: precise and complete code context (arXiv 2411.03079, 2024/2025)

- **Citation.** (USTC authors.) "Utilizing Precise and Complete Code Context to Guide LLM in Automatic False Positive Mitigation." arXiv:2411.03079, v1 Nov 2024, v2 May 2025. https://arxiv.org/abs/2411.03079
- **Problem.** Prior LLM FP filters fed snippets that were too broad (noise) or missed critical context (callee definitions, other files).
- **Mechanism.** **eCPG-Slicer** builds an extended code property graph and extracts *line-level* context for the warning. **FARF** builds a file-reference graph that finds all files relevant to a warning in linear time, with no whole-program analysis. The model is a lightweight open-source LLM. [S]
- **Results.** Juliet: **F1 > 99% across CWEs**, beating the LLM4SA-style baseline. D2A: **86% "label accuracy"**. Average **4.7 s per warning** on Juliet, with a claimed saving of up to **$2,758 per run ($0.384 per warning)** compared with manual review. [S] A secondary summary claims over 85% FP elimination on real projects totalling about 2.5 MLOC. [unverified]
- **Limitations.** F1 > 99% on Juliet is more likely a measure of benchmark familiarity than of capability (§4). D2A labels are themselves noisy (they come from differential analysis), so 86% "label accuracy" is agreement with noisy labels. The paper only covers C.
- **Design implication.** Precision of context beats volume of context. We should give the verifier the **minimal complete slice**: taint path statements, sanitizer and guard definitions, and the bodies of callees on the path, with cross-file resolution. We should not hand it whole files. Our Datalog layer can compute that slice cheaply, because it plays the same role as the eCPG.

### 1.3 LLM4PFA: path-feasibility analysis with LLM agents + Z3 (arXiv 2506.10322, 2025)

- **Citation.** Xueying Du et al. (Fudan University). "Minimizing False Positives in Static Bug Detection via LLM-Enhanced Path Feasibility Analysis." arXiv:2506.10322, June 2025. https://arxiv.org/abs/2506.10322
- **Problem.** Many C false positives come from **infeasible paths**: a guard upstream makes the null deref, OOB access or divide-by-zero unreachable. Static tools approximate these guards away.
- **Mechanism.** The analysis is iterative and goes function by function, starting from the target variable, its source, its sink and the call trace. For each function the LLM identifies the **critical conditional branches** between source and sink and summarizes the feasible path conditions. **LLM agents then do symbolic range reasoning** on the variables and calls in those conditions, and the constraints are compiled into **SMT scripts solved by Z3**. [S]
- **Results.** Filters **72%–96% of FPs**, which is **41.1%–105.7% better than the baselines**. Recall is 0.93, **missing 3 of 45 true bugs**. [S] One summary says the evaluation used 364 hand-labelled warnings from Linux, OpenSSL and Libav. [unverified]
- **Limitations.** The ground-truth TP count is small (45), so the recall estimate is coarse. LLM-to-SMT translation can itself hallucinate constraints. The method suits value/range bugs (NPD, OOB, DBZ) better than taint-style web bugs, where the question is "is this sanitizer adequate", not "is this path feasible".
- **Design implication.** The **LLM should translate and the solver should decide.** For guard-dependent findings, the agent should emit *machine-checkable* facts, such as path conditions or Datalog facts like `guarded(var, pred)`, that our symbolic layer verifies. It should not emit a free-text verdict. This is the strongest neurosymbolic pattern in the cluster.

### 1.4 Tencent industrial empirical study (ICSE-SEIP 2026; arXiv 2601.18844)

- **Citation.** Xueying Du et al. (Fudan University and Tencent). "Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry." ICSE 2026 SEIP; arXiv:2601.18844 (Jan 2026); DOI 10.1145/3786583.3786910. Artifact: https://github.com/LLM4SFPR/static-bug-false-positives-reduction-in-practice
- **Problem.** Does LLM FP reduction hold up on proprietary industrial code, as opposed to academic benchmarks?
- **Setup.** Tencent's enterprise analyzer (BPcheck) run on the Advertising and Marketing Services codebase. **433 alarms: 328 FP and 105 TP**, covering NPD, OOB and DBZ, the three most frequent BPcheck types. The study compares basic LLMs, advanced prompting, hybrid static+LLM methods (LLM4PFA highlighted), and traditional learning-based methods. There are 4 DL baselines and 5 LLM baselines, and the LLM4PFA backbones are GPT, DeepSeek, Claude and Qwen. [R][S]
- **Results.** **Over 76% of alarms are FPs**, and each costs developers **about 10–20 minutes** of manual review. The hybrid LLM4PFA **eliminates 94%–98% of FPs across backbones "while maintaining high recall"**. Cost is **2.1–109.5 s and $0.0011–$0.12 per alarm** across techniques. Most techniques do best on DBZ and worst on NPD. [R]
- **Failure analysis.** The bad cases come from **long code contexts**, **complex cascaded constraints**, and **limited semantic understanding**. [R]
- **Limitations.** One company, one business line and three C/C++ bug types. The dataset is not released (results JSON have code stripped). There are only 105 TPs, so "high recall" rests on few positives.
- **Design implication.** (a) The FP base rate is high enough that even a moderately accurate filter pays for itself at cents per alarm. (b) Hybrid methods dominate pure prompting in industry too. (c) The failure modes tell us where the agent must **abstain or escalate to symbolic reasoning**: long contexts and deep constraint chains. We should log those features and route on them.

### 1.5 ZeroFalse (arXiv 2510.02534, Oct 2025)

- **Citation.** Mohsen Iranmanesh, Sina Moradi Sabet, Sina Marefat, Ali Javidi Ghasr, Allison Wilson, Iman Sharafaldin, Mohammad A. Tayebi. "ZeroFalse: Improving Precision in Static Analysis with LLMs." arXiv:2510.02534, 2 Oct 2025. Code: https://github.com/mhsniranmanesh/ZeroFalse
- **Problem.** SAST adoption is undermined by FPs. The paper focuses on CodeQL alerts for Java.
- **Mechanism.** Analyzer output is treated as a **structured contract** (SARIF). Each alert is enriched with **flow-sensitive traces**, reconstructing the code path *between* the dataflow steps the analyzer reported, plus contextual evidence and **CWE-specific knowledge**. The prompts are CWE-specific templates (`prompt_templates/`), and there are "baseline" and "optimized" context extractors and prompts. Ten LLMs were tested via OpenRouter/OpenAI. [R][S]
- **Data.** OWASP Benchmark Java, 1,189 test cases over 10 CWEs as used here (CWE-22: 271, CWE-79: 274, CWE-78: 251, down to 4 each for CWE-330 and CWE-614). **OpenVuln** is 7 real projects, each tied to one CVE: JSPWiki (CVE-2022-46907, CWE-22), HAPI FHIR (CVE-2023-28465, CWE-79), DependencyCheck (CVE-2018-12036, CWE-78), Keycloak (CVE-2022-4361, CWE-89), Spark (CVE-2016-9177, CWE-22), Undertow (CVE-2014-7816, CWE-22), zt-zip (CVE-2018-1002201, CWE-22). [R]
- **Results.** Best **F1 0.912 on OWASP (grok-4)**, with gemini-2.5-pro at 0.910 and gpt-oss-20b having the highest recall at 0.900. On **OpenVuln the best F1 is 0.955 (gpt-5, recall 0.9142)**, followed by grok-4 at 0.923 and gpt-oss-20b at 0.904. **gemini-2.5-pro collapsed to F1 0.372 on OpenVuln.** CWE-specialized prompts beat generic ones, and reasoning-oriented models give the best precision/recall balance. Cost and latency are shown only as a figure. [S]
- **Limitations.** OpenVuln is tiny (7 CVEs, mostly CWE-22) and all the CVEs predate the models' training cutoffs, so leakage is very plausible. OWASP Benchmark is synthetic and public. The gemini collapse shows **model rank does not transfer** from synthetic to real data.
- **Design implication.** (1) **CWE-specific reasoning templates** are a measured win. (2) **Reconstruct the full path between taint steps**, because Semgrep taint traces are sparse in the same way. (3) **Never select a model on OWASP Benchmark scores.** Selection needs an in-house, post-cutoff, real-code eval set.

### 1.6 Sifting the Noise: LLM agents for SAST FP filtering (ISSTA 2026; arXiv 2601.22952)

- **Citation.** Yunpeng Xiong, Ting Zhang (Monash). "Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering." ISSTA 2026; arXiv:2601.22952; DOI 10.1145/3832100.
- **Mechanism.** Compares **agent frameworks (Aider, OpenHands, SWE-agent)** with vanilla prompting, using Claude Sonnet 4, DeepSeek Chat and GPT-5. The alerts come from CodeQL, Semgrep, SonarQube and other open-source SAST tools. Agents explore the repository themselves. [S]
- **Results.** OWASP: the FP rate falls from **over 92% to as low as 6.3%** in the best configuration. Real Java (Vul4J sample, n=50): up to **93.3% FP identification** on CodeQL alerts. In a post-cutoff C/C++ check on OSS-Fuzz, **SWE-agent + Claude Sonnet 4 identified 95.5% of FPs at 95.5% precision, against 36.4% for vanilla prompting**. [S]
- **Limitations (stated).** Agentic gains appear for strong backbones and are limited or negative for weaker ones. **Aggressive FP reduction suppresses true vulnerabilities.** A secondary summary puts this at about 22% of TPs. [unverified] Residual errors cluster in **cryptography- and policy-oriented CWEs**, and cost varies widely across frameworks. [S]
- **Design implication.** Agentic repository exploration is worth it only with frontier models. Even then, **auto-suppression must be gated by evidence**, because the failure mode is silent loss of real bugs. Crypto and policy CWEs (weak algorithm choice, missing authz) should get **no auto-suppression** and should go to rules or humans.

### 1.7 LASAA: LLM adjudication with error reduction (CMU SEI; arXiv 2607.09979, Jul 2026)

- **Citation.** William Klieber, David Svoboda, Lori Flynn, Ruben Martins. "Using LLMs to Adjudicate Static-Analysis Alerts with Error Reduction Techniques." arXiv:2607.09979, 2026. Tool: https://github.com/cmu-sei/lasaa
- **Mechanism.** [R] The verdict is one of **{true, false, dependent, uncertain}**, always with a justification. The context is the alert fields plus the enclosing function (found via ctags). The LLM can **request struct or macro definitions**, which are looked up and the query is reissued. Cross-file flows add the functions named in the SARIF CodeFlow. There are two error-reduction methods:
  - **Consistency check (CC):** run N=10 times. A verdict stands only if at least 80% of runs agree, otherwise the result is `uncertain`.
  - **LLM reasoning evaluation (LRE):** when runs disagree, the LLM reads the discordant rationales and adjudicates, so a well-argued minority can win.
  - The filter **only clears alerts judged false**. True, dependent and uncertain alerts all go to humans. [S]
- **Results.** With mitigation, o4-mini, gpt-oss-120b and gpt-oss-20b reach **≥98% recall and ≥94.8% specificity on every suite** (Juliet, FormAI, SV-COMP). [R][S]
- **Memorization finding.** The authors show that **o4-mini can often reconstruct the original identities of sanitized Juliet test cases**, so they rest their generalization claims mainly on FormAI. [S]
- **Design implication.** This is the most directly reusable *protocol*: a four-way verdict with an explicit `uncertain` value, self-consistency voting with a threshold, adjudication of disagreements, and "only suppress on confident-false". A stricter threshold trades wrong verdicts for more `uncertain` results, and that trade is a knob we can tune per CWE.

### 1.8 IRIS + CWE-Bench-Java (ICLR 2025; arXiv 2405.17238)

- **Citation.** Ziyang Li, Saikat Dutta, Mayur Naik. "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities." ICLR 2025. Code and data: https://github.com/iris-sast/iris
- **Mechanism.** The LLM **infers CWE-specific taint source and sink specs** for CodeQL, which is a neurosymbolic extension of a Datalog-family engine. It then performs **contextual analysis on each reported path to filter FPs**. [S][R]
- **Results.** In the ICLR version, GPT-4 IRIS detects **55 vulnerabilities, against 27 for CodeQL**, with an **average false discovery rate of 84.82%, 5.21 points lower than CodeQL**. The v1 preprint claimed 69 detections and over 80% FP reduction; those numbers were revised away. [S]
- **CWE-Bench-Java (current repo).** **213 CVEs across 49 CWEs**, including buggy and fixed code and build scripts. Largest classes are CWE-22 (60), CWE-79 (38) and CWE-94 (23). Manual CodeQL-format source/sink annotations exist for 50 CVEs. [R] (The original paper used 120 CVEs.) [S]
- **Limitations.** Even after LLM filtering, **about 85% of alerts are still false**, so contextual filtering on whole-repo Java taint is far from solved. The v1 to ICLR revision shows how fragile headline numbers are. CVEs that predate the model cutoff mean leakage is possible.
- **Design implication.** (a) Spec inference, meaning LLM-proposed sources, sinks and sanitizers, is a **flywheel target**: agent proposals become Semgrep or Datalog spec entries after validation. (b) Real-repo taint FDR stays high, so the LLM verifier is necessary but not sufficient. Rule and spec quality still dominate.

### 1.9 BugLens (ASE 2025; arXiv 2504.11711)

- **Citation.** Haonan Li, Hang Zhang, Kexin Pei, Zhiyun Qian. "Towards More Accurate Static Analysis for Taint-style Bug Detection in Linux Kernel" (arXiv title: "The Hitchhiker's Guide to Program Analysis, Part II: Deep Thoughts by LLMs"). ASE 2025.
- **Mechanism.** LLM post-refinement of static taint reports in the Linux kernel. The LLM reasons about whether taint reaches the sink and whether constraints prevent the bug. [S]
- **Results.** **Precision rises from 0.10 (raw) and 0.50 (semi-automated refinement) to 0.72**, and the work found 4 previously unreported vulnerabilities. Performance varies with how well the backbone follows complex instructions; models tested include o3-mini, o1, GPT-4.1, Gemini 2.5 Pro, Claude 3.7 Sonnet and DeepSeek R1. [S] "Without sacrificing recall" appears only in secondary summaries. [unverified]
- **Design implication.** A structured, multi-step reasoning protocol (taint reachability, then constraint analysis) beats a single "is this a bug?" prompt. Even then, 28% of surviving reports are still false. That is better than humans get from raw output, but it is not "zero FP".

### 1.10 AdaTaint (arXiv 2511.04023, Nov 2025)

- **Citation.** Shiyin Lin. "LLM-Driven Adaptive Source-Sink Identification and False Positive Mitigation for Static Analysis." arXiv:2511.04023; ACM DOI 10.1145/3773365.3773410.
- **Mechanism.** The LLM infers source/sink specs, and alerts are filtered by grounding LLM suggestions in **program facts and constraint validation**, a neurosymbolic design. [S]
- **Results.** On Juliet 1.3, SV-COMP-style C and 3 real projects, **43.7% average FP reduction and +11.2% recall** against CodeQL, Joern and LLM-only pipelines. A user study with 12 professionals found **triage time per alert fell from 42.3 s to 29.1 s and trust rose from 2.7 to 4.1 out of 5**. [S]
- **Limitations.** Single-author preprint, and the benchmarks are leakage-prone. The user study is small.
- **Design implication.** It supports "LLM proposes, symbolic validates". The user study also suggests **explanations grounded in program facts raise trust**, which matters for the human triage half of the flywheel.

### 1.11 LLMSA / NESA: Datalog-style neurosymbolic analysis (arXiv 2412.14399; FSE 2026)

- **Citation.** Chengpeng Wang, Yifei Gao, Wuqi Zhang, Xiangyu Zhang, et al. "LLMSA: A Compositional Neuro-Symbolic Approach to Compilation-free and Customizable Static Analysis" (arXiv 2412.14399), published as "NESA: Relational Neuro-Symbolic Static Program Analysis," FSE 2026.
- **Mechanism.** A **restricted Datalog policy language** mixes *symbolic relations* (from AST parsing) with *neural relations* (filled by few-shot LLM prompts). Evaluation is lazy and incremental, so the LLM is only queried for the facts a rule actually needs. [S]
- **Results.** TaintBench: **precision 66.27%, recall 78.57%**, an F1 0.20 higher than an industrial baseline. Juliet bug detection: **P 86.84%, R 87.69%**. Program slicing: **P 91.50%, R 84.61%**. [S]
- **Design implication.** This is the closest published architecture to our "Datalog + LLM" layer. Its key idea is to **make the LLM a fact provider for specific relations** (for example `is_sanitizer(f, CWE)` or `validates(call, arg)`), invoked lazily from rule bodies, with the facts cached and reusable. Those cached facts are exactly what a flywheel can accumulate and human-review.

### 1.12 LLMDFA (NeurIPS 2024; arXiv 2402.10754)

- **Citation.** Chengpeng Wang et al. "LLMDFA: Analyzing Dataflow in Code with Large Language Models." NeurIPS 2024.
- **Mechanism.** The LLM **writes code** (extractor scripts and Z3 constraints) instead of reasoning about parsing and path feasibility in free text. This offloads the hallucination-prone steps to tools. [S]
- **Results.** Average **precision 87.10% and recall 80.77%**, with F1 up to 0.35 better than baselines, on Juliet DBZ, XSS and OS command injection plus Android apps. [S]
- **Design implication.** Same lesson as LLM4PFA: route the LLM's output through a checkable artifact.

### 1.13 Interleaving static analysis and LLM prompting (SOAP 2024; STTT 2025)

- **Citation.** Patrick J. Chapman, Cindy Rubio-González, Aditya V. Thakur. "Interleaving Static Analysis and LLM Prompting." SOAP@PLDI 2024, pp. 9–17. Extended in *STTT* 27(2), 2025.
- **Mechanism.** The analyzer and the LLM alternate. Prompts are built from the analysis's intermediate results, and the LLM's answers feed back into later analysis. The application is error-specification inference (EESI). [S]
- **Results.** Recall **52.55% → 77.83%**, F1 **0.612 → 0.804**, and precision roughly flat (**86.67% → 85.12%**) on MbedTLS and zlib. [S]
- **Design implication.** The LLM can fill *missing specifications* (what counts as an error return, a sanitizer or a validator) inside the fixed-point loop, not only post-filter. In our system the Datalog layer can query the LLM for unknown library summaries during evaluation, as in NESA.

### 1.14 Other relevant 2025–2026 work (shorter notes)

- **SAST-Genius** (arXiv 2509.15433, 2025): Semgrep, then source-to-sink IR extraction, then LLM triage. FPs fell from **225 to 20 (about 91%) compared with Semgrep alone**. [S] Secondary reports cite 25 projects, 170 ground-truth vulnerabilities, and **precision 89.5% against 35.7% for Semgrep and 65.5% for pure GPT-4**. [unverified] The architecture is almost identical to ours, but it is not independently replicated.
- **CodeCureAgent** (Joos, Bouzenia, Pradel; arXiv 2509.11787; DOI 10.1145/3808140): an agent classifies SonarQube warnings, suppresses FPs and repairs TPs. Patches are validated by build, warning disappearance and the test suite. On 1,000 warnings from 106 Java projects, it produced **plausible fixes for 96.8%**; manual review of 291 cases found **86.3% correct**. [S] The lesson is that a verdict can be backed by an executable check, such as a fix that removes the warning and passes tests.
- **KNighter** (SOSP 2025; arXiv 2503.09002): the LLM *synthesizes static checkers* from historical bug patches and refines them for FPs with **triage agents**. Later versions report 92 new kernel bugs, 77 confirmed. [S] This is the clearest precedent for the "teach the engine" half of our flywheel: agent triage drives **rule refinement**, not per-alert suppression. LLM scanning per call site is impractical at scale (for example, `devm_kzalloc` has more than 7K call sites), while compiled checkers are cheap. [S]
- **Empirical analysis of CodeQL FPs on Java** (arXiv 2609.04535, 2026): on CWE-Bench-Java, FPs concentrate heavily in a few queries: log-injection has **11,613** FP findings, sensitive-log 2,987, path-injection 1,195, against 334 for concatenated-SQL. [S] The study also tests targeted query refinements and coding agents adapting them. Lesson: **FP mass is rule-skewed**, so fixing a handful of rules is worth more than per-alert LLM calls.
- **MoCQ, "Neuro-symbolic Static Analysis with LLM-generated Vulnerability Patterns"** (arXiv 2504.16057): LLM-generated CodeQL queries found 172 TP / 319 FP, against 236 TP / 147 FP for Joern queries. [S] LLM-written rules need an FP-refinement loop.
- **Code representation and FP dynamics** (arXiv 2604.27714, 2026): fine-tuned detectors key on surface cues such as API names. Switching inference to AST input lowered Qwen3-8B FPR from 0.866 to 0.583 but cut recall from 0.948 to 0.723. [S] This is a warning against pure-LLM detectors and is consistent with using the LLM only as a *verifier over a symbolic candidate*.
- **Calibration Without Comprehension** (arXiv 2606.20502, 2026): a three-way vulnerable / non-vulnerable / abstain setup with coverage reported. Some fine-tuned setups collapse to near-total abstention (for example, 11.9% overall coverage). [S] Abstention has to be measured as coverage, or a system can look "safe" while doing nothing.
- **FSE 2023 IVR pilot** ("Assisting Static Analysis with LLMs: A ChatGPT Experiment"): on 20 FPs, GPT-3.5 pruned 8 and GPT-4 pruned 16. [S] Historical baseline only.
- **SecLLMHolmes** (Ullah et al., IEEE S&P 2024; arXiv 2312.12575): **all models changed answers across runs**, and the reasoning was often wrong even when the verdict was right. Renaming functions or variables or adding library functions caused **wrong answers in 26% (PaLM2) and 17% (GPT-4)** of cases. 228 scenarios, 8 LLMs, C and Python. [S] This is the empirical basis for self-consistency voting and for not trusting rationales unchecked.

---

## 2. Vendor products: claims and mechanisms

Every number in this section is vendor-reported, and none has an independent audit. Agreement rates are **not** recall on true positives.

### 2.1 Semgrep Assistant (auto-triage, noise filtering, Memories) and Semgrep Multimodal

- **Sources.** "How we built an AppSec AI that security researchers agree with 96% of the time" (semgrep.dev/blog/2025/building-an-appsec-ai-...). "Announcing an AI AppSec engineer that users agree with 95% of the time" (semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories/). "Our AI Assistant is handling 60% of incoming triage work..." (semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-...). "Imagine zero false positive SAST" (12 Jun 2025, Memories GA). "Inside the AI Memories Security Teams Are Writing" (6 May 2026). Semgrep Multimodal launch (19 Mar 2026; BusinessWire, semgrep.dev/blog/2026/...). Docs: docs.semgrep.dev/semgrep-assistant/overview and /customize. [S]
- **Mechanism.** The verdict is binary ("likely TP" / "likely FP"), produced by an LLM with retrieval-augmented context and a rationale. **Noise filtering** hides likely FPs from PR/MR comments but **keeps them visible on a backlog page**, and comments still appear for rules in Block mode. **Memories** are natural-language, scoped context (by project, rule or vuln class). They are suggested automatically from triage notes and developer feedback, users activate, edit or delete them, and they apply to future scans. [S]
- **Claims.** Assistant matches internal researchers' TP/FP triage in **96%** of cases. Reported **user agreement is 92%, 95% or above 96%** depending on post and date; one post cites a basis of **over 250,000 findings across 45+ enterprises**. The README variant says 97%. Out of the box Assistant filters **about 20%** of SAST findings, and with Memories and time it handled **about 60%** of new findings. One Fortune 500 customer reportedly saw **a 2.8× improvement** after adding two memories. [S/unverified] In the Memories corpus analysis, the largest categories are **non-production environment (25.6%)** and **framework protection (21.9%)**. [S] Multimodal claims **"up to 8× more TPs, 50% less noise vs foundation models alone"**, **over 95% accuracy categorizing FPs**, and a 54% FP-rate reduction compared with Claude in an in-house table. [S]
- **Critical notes.** (1) Methodology conflicts: one post describes benchmarking against the research team, while a later post says the 96% "isn't derived from an internal benchmark… it's the real-world agreement rate". (2) **No published false-negative or TP-suppression rate**; "rarely misses a TP" is not quantified. (3) Agreement on audited history is biased, because users audit a sample and anchoring on the AI's verdict inflates agreement.
- **Design implication.** Three ideas are worth copying. **Filtered ≠ deleted:** suppressed findings stay reviewable. **Blocking rules bypass the filter.** **Scoped natural-language memories** turn triage into reusable context. The Memories category data tells us which context matters most in practice: *is this code reachable in production?* and *does the framework already protect this?* Those should be **first-class, symbolic facts** in our Datalog layer (`non_prod_path(file)`, `framework_autoescape(template_engine)`), not free text. Where Semgrep keeps Memories as prompt text, we should compile validated memories into rules or facts. That gives determinism and auditability, and it saves LLM cost.

### 2.2 GitHub Copilot Autofix (CodeQL) and the GitHub Security Lab Taskflow Agent

- **Sources.** GitHub blog "Found means fixed: Secure code more than three times faster with Copilot Autofix". GitHub changelogs (2025-06-16 MTTR metric; 2025-12-16 recalculated Autofix usage metrics). docs.github.com "Responsible use of Copilot Autofix for code scanning". GitHub blog "AI-supported vulnerability triage with the GitHub Security Lab Taskflow Agent". [S]
- **Mechanism.** Autofix is *remediation*, not triage. An LLM (the docs name GPT-5.1 in one version and GPT-5.3-Codex in another) generates a patch for a CodeQL alert. Agentic autofix validates the fix by **re-running CodeQL's code-scanning suite**, so it cannot validate fixes for custom queries. Quality is measured on a harness of **over 1,400 alerts** (a later docs version says over 1,870) from public repos with test coverage, by how much editing a fix needs and whether it passes CI. [S]
- **Claims.** The public beta claimed developers fixed vulnerabilities **"more than 3× faster"**. A June 2025 changelog reported time to close of **15.6 h with Autofix against 17.4 h without**, a modest gap. No published acceptance or accuracy percentage was found. [S]
- **Taskflow Agent.** YAML-defined, multi-stage triage of CodeQL alerts (GitHub Actions, JS/TS) with deliberately minimal tools: file fetch and search, and **no extra static or dynamic analysis**. The audit stage encodes **per-alert-class FP checklists**, for example "can an attacker trigger this workflow? does it run privileged? is it maintainer-only or disabled?". It found **about 30 real vulnerabilities**, and a later Android campaign reported 24 CVEs. GitHub itself warns that the agents may misjudge severity, overlook mitigations, or produce FPs. [S]
- **Design implication.** **Per-alert-class audit checklists**, written by security experts, are the core asset. That matches ZeroFalse's CWE-specific prompts. Validating a patch by re-running the analyzer is a cheap, generic verifier, and we can reuse it: "does the suggested sanitizer or fix make the Semgrep or Datalog finding disappear without new findings?"

### 2.3 Snyk DeepCode AI

- **Sources.** Snyk blog "Snyk safe adoption of AI" (snyk.io/blog/snyk-safe-adoption-of-ai/). Berabi et al., "DeepCode AI Fix: Fixing Security Vulnerabilities with Large Language Models," arXiv:2402.13291 (2024). [S]
- **Mechanism.** A hybrid: a symbolic rule engine runs over code event graphs, and generative ML proposes fixes. **Each fix is re-scanned by the symbolic engine before it is suggested.** DeepCode AI Fix uses static-analysis-based **code reduction** to give the model small inputs. [S]
- **Claims.** **72% OWASP Benchmark accuracy against 53% for an unnamed competitor** (no methodology given). One review says the Mixtral-based fixer removes over 80% of reported defects and exactly matches human fixes in 10–50% of cases. [unverified]
- **Design implication.** **Symbolic re-verification of every LLM output** (the fix, or in our case the suppression rationale) is an established industrial pattern. Snyk uses the LLM for fixes rather than triage, which tells us vendors with strong symbolic engines still keep the *decision* symbolic.

### 2.4 Corgea, ZeroPath, Amplify, Datadog, CyberArk Vulnhalla

- **Corgea** (corgea.com/scanning, "Whitepaper: BLAST"): claims **about 30% of tickets/findings auto-triaged as FP**; third-party listings say FP rate under 5%. [S/unverified] One review says Corgea relies on upstream scanners, while others describe BLAST as its own scanner. Unresolved.
- **ZeroPath** (zeropath.com/blog/benchmarking-zeropath): an in-house fork of the **XBOW benchmark**, not OWASP. It reports **a 25.0% FP rate on 31 technical-vuln benchmarks and 0% on 8 business-logic/auth benchmarks**. Marketing also says "up to 75% fewer FPs". [S] The sample sizes are tiny.
- **Amplify Security:** a customer review (AWS Marketplace) says it layers LLM analysis on Semgrep alerts for relevance and de-duplication. **No metrics found.** [unverified]
- **Datadog Bits AI SAST** (Oct 2025 "Using LLMs to filter out false positives from static code analysis"; Jul 2026 "Reduce SAST false positives with agentic evaluation and Bits Memories"): it labels findings likely TP/FP with an explanation, but only for a **curated CWE set (OWASP Benchmark / Top Ten)**. Agentic evaluation gives **read-only repository access** to check callers and validators, currently **only for injection rules**. Bits Memories draws on past FP reports and per-rule notes. Evaluations pass through **AI Guard against prompt injection**. **No accuracy numbers published.** [S]
- **CyberArk Vulnhalla** (CyberArk threat-research blog, 10 Dec 2025; https://github.com/cyberark/Vulnhalla): CodeQL followed by LLM "guided questioning" with tool calls that let the LLM request more code. The verdict codes include **"needs more info"**, and the README recommends temperature and top-p around 0.2 for consistency. [R] It claims **"up to 96% FP reduction"** (97% in an earlier BSides abstract) and several CVEs found for under $80. [S]
- **Design implications.** (1) Vendors **restrict LLM triage to CWE classes where it is validated** (Datadog: injection only). We should too. (2) **Prompt-injection defence** is mandatory, because the verifier reads attacker-controllable code and comments. (3) A **"needs more info" verdict** exists in practice (Vulnhalla, LASAA).

---

## 3. Head-to-head summary table

| Work | Analyzer / lang | LLM context | Decision maker | Headline result | Tag |
|---|---|---|---|---|---|
| LLM4SA (TKDD'24) | C/C++ tools, Juliet + 11 projects | dependence slice + bug-type Qs + few-shot | LLM | P 81.13%, R 94.64% (9,547 warnings) | S |
| LLM4FPM ('24) | C, Juliet/D2A | eCPG line-level slice + cross-file (FARF) | LLM (small open model) | Juliet F1 >99%; D2A acc 86%; 4.7 s/warn | S |
| LLM4PFA ('25) | C (kernel/OSS) | per-function path conditions, agents | **Z3** | 72–96% FP filtered; 3/45 TPs missed | S |
| Tencent SEIP'26 | BPcheck C/C++ industrial | compares many | hybrid best | 94–98% FP removed; $0.001–0.12/alarm | R |
| ZeroFalse ('25) | CodeQL Java | SARIF + reconstructed flow + CWE prompt | LLM | F1 0.912 OWASP; 0.955 OpenVuln; gemini 0.372 | R/S |
| Sifting the Noise (ISSTA'26) | CodeQL/Semgrep/Sonar, Java + C | agent repo exploration | LLM agent | OWASP FPR 92%→6.3%; OSS-Fuzz 95.5%/95.5%; TP suppression | S |
| LASAA ('26) | any SARIF; C suites | function + on-demand defs + CodeFlow; N=10 votes | LLM + CC/LRE | ≥98% recall, ≥94.8% specificity | R/S |
| IRIS (ICLR'25) | CodeQL Java | LLM specs + path context | CodeQL + LLM | 55 vs 27 vulns; FDR 84.82% | S |
| BugLens (ASE'25) | kernel taint | structured reasoning steps | LLM | precision 0.10→0.72 | S |
| NESA/LLMSA (FSE'26) | compilation-free | Datalog rules w/ neural relations | Datalog | TaintBench P 66.27%/R 78.57% | S |
| SAST-Genius ('25) | **Semgrep** | source→sink IR | LLM | FPs 225→20 | S |

---

## 4. Benchmarks: suitability for FP-filter evaluation, and leakage

The key requirement for evaluating an FP filter is **(analyzer alert, ground-truth TP/FP label)** pairs on **realistic code the model has not memorized**, with enough **true positives** to measure recall loss. Most vulnerability-detection datasets are function-level classification sets. They are not alert-level datasets.

| Benchmark | What it is | Good for FP-filter eval? | Leakage / validity issues |
|---|---|---|---|
| **OWASP Benchmark (Java) v1.2** | 2,740 servlet test cases, 11 categories; about 1,415 true vulns and 1,325 "false positive" traps; score = TPR − FPR (Youden). [S] | Yes for *mechanics* (it has explicit FP traps, and any SAST can be scored). Weak for *claims*. | Synthetic and simplistic (2016). Public for 10 years, so near-certain training contamination. Benchmark-specific tuning is common. ZeroFalse's gemini result (0.91 → 0.37 on real code) shows ranks don't transfer. |
| **Juliet (NIST SARD) C/C++/Java** | Huge synthetic per-CWE good/bad variants. | Mechanics and regression only. | **Demonstrated memorization**: o4-mini reconstructs sanitized Juliet case identities (LASAA). [S] `good`/`bad` naming leaks labels unless renamed. LLM4FPM's F1 above 99% is what memorization predicts. |
| **CASTLE (TASE 2025)** | 250 hand-written C micro-benchmarks, 25 CWEs, about 11 KLOC; CASTLE Score (max 1250, FPs subtract without bound); 13 SAST + 2 FV + 10 LLMs; about 7,500 findings manually reviewed. [R][S] | Useful as a *post-2024, small, uncontaminated-at-release* C set that explicitly penalizes FPs. | Micro-benchmarks favour LLMs: the top LLM (o3-mini) scored 977 against ESBMC 661 and CodeQL 634, and the authors note **LLM accuracy declines and hallucinations rise with code size**. [S] Now public, so contamination will grow. Single-file C only. |
| **CWE-Bench-Java (IRIS)** | 213 CVEs / 49 CWEs (repo), real projects (~300 KLOC avg in the paper), buildable, buggy and fixed versions. [R][S] | **Good**: real repos at realistic scale, buildable, so it can produce real alerts. Recall is measured on the CVE; other alerts need labelling (arXiv 2609.04535 did this). | CVEs predate model cutoffs, so fix commits may be memorized. Only one labelled vulnerability per project; other alerts are unlabelled. |
| **Vul4J (MSR 2022)** | 79 reproducible Java vulns, 51 projects, 25 CWEs, with PoV tests (later releases differ; v1.1 is cited as 27). [S] | **Good for TP-retention checks**: PoV tests give executable ground truth. Used by Sifting the Noise (n=50). | Small. Old CVEs, so likely memorized. |
| **OpenVuln (ZeroFalse)** | 7 Java CVE projects + CodeQL SARIF. [R] | Tiny; illustrative only. | Old CVEs; dominated by CWE-22. |
| **SecLLMHolmes** | 228 scenarios, 8 CWEs, C/Python, plus a framework for determinism, robustness and reasoning faithfulness. [S] | Not alert-level. Its **robustness and determinism protocol** is valuable to reuse. | Public since 2023. |
| **PrimeVul (Ding et al., ICSE 2025; arXiv 2403.18624)** | Function-level C/C++ with improved labels, de-duplication and a chronological split. [S] | Not alert-level, but the best evidence on **inflation**: a 7B model fell from 68.26% F1 on BigVul to 3.09% on PrimeVul, and GPT-3.5/4 were near random in the strictest setting. [S] | Prior datasets had 20–71% inaccurate labels and 17–99% duplicates (cited via a secondary source). [S] |
| **RealVul (EMNLP 2024; arXiv 2410.07573)** | PHP, LLM-based detection, CWE-79/89, 180 projects. [S] | Detection-oriented; limited for alert triage. | Not reviewed in depth. |
| **RealVuln (arXiv 2604.13764, Apr 2026)** | 26 intentionally vulnerable Python projects; 796 labels (676 vulns, **120 FP traps**); 15 scanners; F3 primary metric. [S] | Useful because it has **explicit FP traps on realistic code** and includes Semgrep. Semgrep F3 17.7, Claude Sonnet 4.6 51.7, Kolega.Dev 73.0 (F1: Sonnet 60.9). [S] | Built by a vendor (Kolega) that wins its own benchmark. Intentionally vulnerable apps (CTF/edu) are likely in training data. |
| **SastBench (arXiv 2601.02941, Jan 2026)** | Agentic SAST triage benchmark: **real CVEs as TPs + filtered SAST findings as approximate FPs**, at a realistic (imbalanced) distribution. [S] | **Designed for exactly our task.** | "Approximate FP" labels mean some real bugs may be labelled FP. One aggregator's score (precision 0.1, MCC −0.02 for simple ReAct) is [unverified]. |
| **SV-COMP / FormAI** | Verification tasks (SV-COMP) and AI-generated C programs labelled by ESBMC (FormAI). | LASAA rests its generalization on FormAI because it is less memorized. | FormAI labels come from a bounded model checker (incomplete). SV-COMP is public. |
| **D2A** | Labels from differential analysis of Infer alerts. | Alert-level, which is rare. | Labels are noisy, so "accuracy" means agreement with noise. |

**Benchmark conclusions for us.**
1. **No public benchmark is sufficient.** Use OWASP/Juliet only as smoke tests, after renaming identifiers and stripping comments.
2. Build an **in-house, alert-level gold set**: our Semgrep+Datalog alerts on real repositories, labelled by humans, with a **chronological split** (code or CVEs after the model's training cutoff) and **perturbation variants** (renamed identifiers, moved code) to detect memorization (the SecLLMHolmes and LASAA protocols).
3. Seed the TP side with **post-cutoff CVEs** (CWE-Bench-Java style, buildable, PoV where possible, as in Vul4J) and keep enough TPs (hundreds) to measure recall loss with tight confidence intervals. The Tencent study (105 TPs) and LLM4PFA (45 TPs) show how thin recall evidence usually is.
4. Report **per-CWE** results. Crypto, policy and authz CWEs behave differently (Sifting the Noise).

---

## 5. Cross-cutting failure modes (what goes wrong)

1. **True-positive suppression.** This is the dominant risk for a "very low FP" goal. The evidence: Sifting the Noise warns of it explicitly; LLM4SA's recall is 94.6%; LLM4PFA missed 3 of 45; and no vendor publishes FN rates. A filter at 95% recall run on every alert silently loses 1 in 20 real bugs.
2. **Non-determinism.** All models changed answers across runs (SecLLMHolmes), which is why LASAA needs N=10 voting.
3. **Unfaithful rationales.** Correct verdicts often come with wrong reasoning (SecLLMHolmes). Rationales can't be trusted as evidence unless their claims are checked.
4. **Context failures.** Long contexts, cascaded constraints and missing definitions (Tencent bad cases; LLM4FPM motivation; CASTLE's degradation with code size).
5. **Model brittleness across distributions.** gemini-2.5-pro went from 0.91 to 0.37 (ZeroFalse); agent gains vanish for weak backbones (Sifting the Noise).
6. **Benchmark leakage.** Juliet memorization has been shown (LASAA); PrimeVul shows benchmark inflation (68% → 3% F1).
7. **Category blind spots.** Crypto and policy CWEs (Sifting the Noise); business logic (outside what pattern-based tools see, though some vendors claim LLM gains there).
8. **Prompt injection.** The verifier reads attacker-influenced code, comments and strings. Datadog routes evaluations through AI Guard; nobody in academia evaluates this.
9. **Agreement-rate illusions.** Vendor "agreement" numbers measure consistency with audited samples and are subject to anchoring. They are not recall.

---

## 6. Synthesis: design lessons for our scanner

**L1. The LLM proposes and the symbolic layer disposes, wherever a checkable form exists.** The strongest results come from systems where the LLM *translates* and a solver or engine *decides*: LLM4PFA (Z3; best in the Tencent industrial study at 94–98% FP removal), LLMDFA (Z3, generated extractors), NESA (Datalog with neural relations), AdaTaint (constraint validation), and Snyk (symbolic re-scan of every fix). Concretely, the agent's output should be **typed facts with evidence locations**, for example `sanitizes(fn, CWE-89, arg=1) @file:line`, `guard(path, cond)`, `unreachable_in_prod(file)`, `framework_protects(sink, mechanism)`. These facts are fed into the Datalog layer, which re-derives whether the finding survives. A free-text "FP" verdict alone never suppresses anything.

**L2. Context: give the minimal complete slice plus targeted on-demand retrieval, not whole files.** What works, roughly in order of evidence: (a) the full reconstructed source-to-sink path, including steps the analyzer elided (ZeroFalse, SAST-Genius); (b) definitions of sanitizers, guards, validators and callees on the path, resolved across files (LLM4FPM's FARF, LASAA on-demand definitions); (c) path conditions and guards (LLM4PFA, BugLens); (d) deployment and framework context. Semgrep's Memories data puts non-production code (25.6%) and framework protections (21.9%) at the top. An agent loop with read-only repository tools helps only with strong models (Sifting the Noise). Use it as an escalation tier, not as the default.

**L3. Use CWE-specific reasoning templates and audit checklists, and limit auto-triage to validated CWE classes.** CWE-specialized prompts measurably beat generic ones (ZeroFalse). GitHub's Taskflow audit stage and LLM4SA's bug-type questions follow the same pattern. Each template is a checklist of the *specific* ways a finding of that class is benign: parameterized query? allow-listed command? path canonicalized and confined? autoescaped template context? attacker-triggerable workflow? Each checklist answer must cite a code location. As Datadog does (injection rules only), **enable auto-suppression per CWE only after that CWE passes our eval gate**. Crypto, authz and policy classes start as "never auto-suppress".

**L4. Use a four-way verdict with abstention, and suppress only on confident, evidenced "false".** Adopt the LASAA protocol: verdicts {TP, FP, dependent/duplicate, UNCERTAIN/needs-info}, **self-consistency** over N samples with an agreement threshold, LLM adjudication of disagreements, and **only confident-FP-with-verified-evidence leaves the human queue**. Everything else, including every UNCERTAIN, stays visible. Measure **coverage** (the fraction auto-decided) alongside precision and recall, or abstention can quietly do all the work (the coverage collapse in Calibration Without Comprehension).

**L5. Filtered must not mean deleted, and blocking rules bypass the filter.** Following Semgrep: suppressed findings remain in a reviewable backlog with the agent's evidence attached, and rules marked blocking or critical are never LLM-suppressed. Regularly sample suppressed findings for human audit. This is the only way to estimate the false-negative rate the filter introduces, which no vendor publishes.

**L6. The flywheel should improve rules and facts, not only accumulate per-alert verdicts.** FP mass is heavily rule-skewed: in one CodeQL study log-injection alone had 11,613 FPs. KNighter shows triage agents driving checker refinement, and IRIS and AdaTaint show LLM-proposed source/sink specs. Semgrep's Memories show that human triage converts naturally into scoped context. Our flywheel should cluster agent and human verdicts by (rule, CWE, pattern), propose **rule patches, sanitizer and source/sink spec entries, or Datalog facts**, validate them against the gold set (with no TP regressions, as CodeCureAgent's and Copilot Autofix's "re-run the analyzer" checks do), and then ship them as deterministic engine changes. Validated knowledge thus moves from expensive, non-deterministic LLM calls into cheap, auditable rules, which keeps cost and variance falling over time. Natural-language memories are a staging area, not the end state.

**L7. Calibrate, and treat model choice as an empirical, per-CWE, recurring decision.** Model rank does not transfer (ZeroFalse gemini collapse; weak backbones gain nothing from agents). Reasoning models give the best precision/recall balance (ZeroFalse, LASAA's mid-tier reasoning models). Pick the model per CWE tier on the in-house eval set, re-run that choice whenever models change, and map vote agreement to empirical precision per CWE (reliability curves) so that thresholds come from data, not from verbalized confidence. Use low temperature plus voting (Vulnhalla recommends about 0.2; SecLLMHolmes documents non-determinism).

**L8. Evaluate on our own alerts, after the training cutoff, with perturbations, and report recall loss first.** Primary metrics should be: TP-retention (recall of the filter) with confidence intervals; FP reduction at fixed recall of at least 99% on critical CWEs; coverage; cost and latency per alert; and per-CWE breakdowns. Also run a memorization check that compares original and identifier-renamed or restructured variants (LASAA, SecLLMHolmes). OWASP, Juliet and CASTLE are smoke tests. SastBench and RealVuln are external sanity checks. Vendor "agreement rates" are not evaluation metrics.

**L9. Treat the verifier as an attack surface.** Code under analysis can contain instructions aimed at the verifier, such as "// security reviewed: this is safe". Strip or quarantine comments and string literals in the prompt where possible. Never let the LLM's *rationale text* count as evidence; only cited code locations re-checked by the engine count. Run the agent with read-only, sandboxed tools (Datadog's read-only access plus AI Guard is the only industrial precedent found).

**L10. The economics favour verification, but verification is not the main lever.** At $0.001–$0.12 per alarm against 10–20 developer-minutes (Tencent), LLM verification pays for itself even at moderate accuracy. But IRIS still has an FDR of about 85% after LLM filtering on real Java taint, and BugLens still leaves 28% FPs. So the cheapest FP is one the rules and Datalog layer never emit. Spend most effort on precise rules and specs, use the LLM verifier on the residue, and use the flywheel to push verifier knowledge back into the rules.

---

## 7. Open questions / gaps found

- No published, audited **false-negative (TP-suppression) rate** exists for any commercial auto-triage product.
- No academic study measures **prompt-injection robustness** of SAST LLM verifiers.
- Few studies target **Semgrep taint-mode output** specifically (SAST-Genius and Sifting the Noise include Semgrep). Most target CodeQL or C bug finders.
- **Longitudinal flywheel evidence** (does learning from triage keep improving precision without eroding recall?) exists only as vendor anecdotes, such as Semgrep's 20% → 60% triage handled and the "2.8×" memory claim.
- Items to re-verify from full PDFs: ZeroFalse per-model table and cost; the LLM4PFA dataset composition; Tencent limitations section; the Sifting the Noise TP-suppression figure; the SastBench results table; Semgrep's 96% methodology.
