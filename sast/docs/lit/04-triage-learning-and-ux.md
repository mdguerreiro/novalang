# 04 — Learning from Triage Feedback, Industrial Adoption Lessons, and Triage UX

Cluster: (a) learning from developer/analyst feedback and actionable-alert ranking; (b) industrial lessons on static-analysis adoption; (c) triage UX, vendor survey, pain points, and opportunities.
Ends with (1) a flywheel design synthesis and (2) a prioritized triage-UI feature list.

## Method and evidence quality (read first)

- Research date: 2026-10-24.
- **Access limits.** In this session, every `WebFetch` call failed with DNS `ENOTFOUND`. That covered cacm.acm.org, research.google, arxiv.org, docs.github.com, wikipedia, and university hosts. Shell `curl` got a 403 from the egress proxy for the same hosts. So no primary PDF was read end to end.
- **What we used instead.** Evidence comes from ~30 `WebSearch` queries, many in "extended" mode. They returned quoted extracts from the primary pages: author PDFs (Tricorder ICSE'15, Christakis & Bird ASE'16, Koc MAPL'17, Bingo PLDI'18, Kharkar ICSE'22, Kang ICSE'22, Yang/Menzies ESWA'21), CACM articles, the OASIS SARIF 2.1.0 spec, and vendor docs (Checkmarx, Veracode, SonarQube, Snyk, Semgrep, GitHub).
- **How to read the numbers.** A number below is given only when a search extract quoted it from the primary source or a named secondary source.
  - **[unverified]**: a claim from memory or from a weak secondary source.
  - **[vendor-reported]**: a vendor's marketing figure that no one has checked independently.
  - Re-check every number against the PDFs before quoting it externally.
- About 30 distinct sources were consulted through extracts (listed in each section).

---

## Part A — Learning from feedback and actionable-alert ranking

### A1. Kremenek & Engler, "Z-Ranking: Using Statistical Analysis to Counter the Impact of Static Analysis Approximations", SAS 2003, LNCS pp. 295–315
- Source: dblp record and Engler's slides ("System-specific static bug finding: tricks, bitter experience, open problems", sos-vo.org); the full paper was not retrieved.
- **Key idea.** A checker's approximations are treated as "MAY beliefs" and checked as if they were MUST beliefs. For each belief or grouping, the method counts successful checks S and failed checks F.
  - A real error is a rare violation of a pattern that is usually obeyed: high S, low F.
  - The ranking uses a statistical test (a z-test for proportions; each check is treated as a coin toss), not a raw percentage. The slides give the example that 1/1 = 100% is weaker evidence than 990/1000 = 99%, so population size has to count.
  - Reports are ranked by confidence, most credible first.
- The paper's own experimental numbers were not verified. Recalled from memory: Z-ranking puts real bugs near the top far better than random order on Linux/xgcc checkers **[unverified]**.
- **Design implication for us:**
  - Do a "belief statistics" pass over the Datalog facts. For each (rule, sink API, candidate sanitizer, guard pattern), count how often the pattern is obeyed versus violated across the repo, the org, and globally.
  - A finding where the code *usually* sanitizes before this sink but not here is high-confidence.
  - A rule that "violates" 400 times in one repo with no fixes is probably modeling the codebase wrong. That should drive rule or sanitizer-model learning, not 400 findings.
  - Use proper small-sample statistics (Wilson / Beta-Binomial lower bounds), never raw ratios.

### A2. Kremenek, Ashcraft, Yang, Engler, "Correlation Exploitation in Error Ranking", FSE 2004 (SIGSOFT FSE-12)
- Source: abstract and bib from Columbia (junfeng/papers/ranking-fse).
- **Findings:**
  - Static rankings ignore correlations between reports and do not adapt as reports are inspected.
  - Both bugs and false positives cluster by code locality.
  - The paper uses a probabilistic model (a Bayesian network over reports, correlated by locality) that updates with every user label.
  - Result: a **2–8x improvement over randomized ranking**, on both intra- and inter-procedural tools.
- **Design implication for us:**
  - Every triage action should immediately re-rank the rest of the queue. A "Not exploitable" on finding X lowers the score of correlated findings: same function or file, same source/sink pair, same flow-through helper, same missing-sanitizer hypothesis. A "Confirmed" raises them.
  - The modern version swaps code locality for richer correlation keys our engine already has, such as shared Datalog derivation sub-trees and shared taint path segments (see Bingo).
  - The UI should show the effect: "This verdict lowered 37 related findings; review them?"

### A3. Heckman & Williams, "A systematic literature review of actionable alert identification techniques for automated static code analysis", Information and Software Technology 53(4):363–387, 2011
- Source: dblp, ResearchGate and Semantic Scholar records, and citations in the 2023 survey "Machine Learning for Actionable Warning Identification" (arXiv 2312.00324). The SLR text itself was not retrieved.
- **Findings, as cited secondhand:**
  - Techniques split into *ranking* versus *classification* (actionable or not).
  - Most use alert characteristics (type, priority, tool) plus code characteristics (metrics, churn, history).
  - Learning-based methods cut manual review effort.
  - The exact study count (about 21 studies **[unverified]**) was not confirmed.
- **Companion paper.** Heckman & Williams' comparative evaluation (PROMISE 2013, dl.acm.org/doi/10.1145/2499393.2499399) compared 6 AAIT techniques on 3 projects. The systematic AAIT averaged **82.5% accuracy**.
- **Related.** A 2009 study used 15 ML algorithms and 51 warning characteristics and reported 83–99% recall (cited in the same sources).
- **Design implication for us:**
  - The classic feature families (alert type, code location, file churn, alert history and lifetime, developer) are cheap and useful *priors*.
  - They must be combined with semantic evidence from the Datalog proof and the LLM verdict. Alone, they mostly learn "which rules are noisy in which directories".

### A4. Critical correction: Kang, Aw, Lo, "Detecting False Alarms from Automatic Static Analysis Tools: How Far are We?", ICSE 2022, pp. 698–709 (Distinguished Paper nominee)
- Source: arXiv 2202.05982 abstract via ar5iv.
- **Findings:**
  - The near-perfect "Golden Features" results in the literature were inflated.
  - **Data leakage**: features that count the actionable warnings in a context leaked ground-truth labels.
  - **Data duplication**: test warnings also appeared in training.
  - The automatic oracle (a warning that disappears in a future revision counts as "actionable") is sensitive to which revision is chosen, and it often disagrees with human judgment.
  - The authors call the prior results over-optimistic.
- **Related.** Yang, Menzies et al., "Learning to recognize actionable static code warnings (is intrinsically easy)" (EMSE 2021), found that many learners do well on the same data. Kang et al. explain why: leakage.
- **Design implication for us:**
  - Evaluate every learned suppressor or ranker with **time-split, repo-grouped** validation. Train on the past, test on later scans; never mix the same fingerprint across splits.
  - Never use "the alert disappeared" as a label for "it was a true positive". Code deletion, refactoring, and rule changes also make alerts disappear.
  - Our ground truth should be explicit human verdicts plus fix commits that touch the flagged path. LLM verdicts are weak labels with their own calibration.

### A5. Koc, Saadatpanah, Foster, Porter, "Learning a Classifier for False Positive Error Reports Emitted by Static Code Analysis Tools", MAPL 2017, pp. 35–42, doi:10.1145/3088525.3088675
- Source: author PDF (cs.tufts.edu/~jfoster/papers/mapl17.pdf) via extract.
- **Findings:**
  - The classifier learns program structures that correlate with false-positive reports. The study used FindSecBugs-style security warnings (Java), from memory **[unverified detail]**.
  - Input representations compared: the method body versus a **backward program slice** from the report location.
  - Models: Naive Bayes baselines versus **LSTM**.
  - LSTM accuracy was about **89.6% on method bodies** and **85% on backward slices**.
- **Design implication for us:**
  - Code-only classifiers are workable, but they are opaque and brittle across codebases.
  - Slicing still matters: hand the LLM verifier the *slice* (the Datalog derivation path and the relevant definitions), not the whole file. That cuts tokens and focuses attention.
  - We prefer LLM-plus-proof verification to a bespoke LSTM. A cheap learned model is still useful as a *pre-filter* or ranker that decides which findings get the expensive agent.

### A6. Kharkar, Moghaddam, Jin, Liu, Shi, Clement, Sundaresan, "Learning to Reduce False Positives in Analytic Bug Detectors", ICSE 2022, pp. 1307–1316, arXiv 2203.09907 (Microsoft)
- Source: arXiv abstract and the Microsoft Research page via extract.
- **Findings:**
  - A Transformer-based model classifies the warnings of an "analytic" (static) bug detector as true or false positives.
  - **Precision improved by 17.5%.**
  - It generalized across **null dereference and resource leak** bug types.
  - The detector used was Infer, from memory **[unverified]**.
- **Design implication for us:**
  - Learned FP filters give real precision gains but cap out. 17.5% is far from "very low FP".
  - That is why we stack them: Datalog refinement, then a learned prior, then LLM verification with tool use, then human feedback.

### A7. Raghothaman, Kulkarni, Heo, Naik, "User-Guided Program Reasoning using Bayesian Inference" (Bingo), PLDI 2018
- Sources: author PDF via extract; github.com/difflog-project/bingo; the follow-up "Continuously Reasoning about Programs using Differential Bayesian Inference" (PLDI 2019).
- **Findings:**
  - Bingo targets analyses written in **Datalog**. It attaches conditional probabilities to the nodes of the derivation graph, which turns the graph into a Bayesian network.
  - It computes the probability of each alarm and shows the most likely one first.
  - Each user label (true or false) becomes evidence, and belief propagates to every alarm that shares derivations.
  - Evaluated on a Java datarace analysis and an **Android taint analysis**, with real users. Reported extract: "**44.2% fewer alarms** [inspected] compared to Base-C".
  - The PLDI 2019 follow-up, "Drake", does the same thing differentially across program versions.
- **Design implication for us:**
  - This is the most directly reusable idea for our architecture.
  - Because our reasoning layer is Datalog, we can keep provenance (derivation trees). Each verdict, from a human or the LLM, then becomes evidence on *intermediate tuples*: "this flow-through edge is spurious", "this function is a sanitizer for SQLi".
  - Propagation does the bulk suppression in a principled way. The UI can show "marking this edge spurious resolves 23 findings".
  - Drake suggests a diff-time mode that ranks only *new* derivations.

### A8. Active learning: Yang, Yu, Wang, Menzies, "Understanding Static Code Warnings: an Incremental AI Approach", Expert Systems with Applications 167:114134, 2021, arXiv 1911.01387
- **Findings:**
  - A human-in-the-loop incremental SVM watches the triager and re-ranks the queue.
  - Across 9 OSS projects it found **over 90% of actionable warnings while humans ignored 70–80% of warnings**.
  - Caveat: these projects use the same FindBugs-style data whose oracle Kang et al. criticized.
- **Design implication for us:**
  - Use uncertainty sampling for human time. Show reviewers the findings whose verdict would most change the model: high-uncertainty LLM verdicts, findings that sit on high-fanout derivation nodes, and new rule×sanitizer combinations.
  - Spend the human budget where information gain is highest, not in FIFO order.
  - Pair this with a stopping rule: "estimated remaining actionable findings ≤ N".

### A9. LLM-era false-positive reduction (industrial evidence)
- **Du et al. (Fudan/Tencent), "Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry"**, ICSE-SEIP 2026, arXiv 2601.18844.
  - 433 alarms (328 false, 105 true) from Tencent's ads platform.
  - **LLM + static-analysis hybrids removed 94–98% of FPs with high recall.**
  - Cost: **2.1–109.5 s and $0.0011–$0.12 per alarm**, against an estimated **10–20 min of manual inspection per alarm**.
- **LLM4PFA** (arXiv 2506.10322): filters 72–96% of FPs on its benchmark.
- **Agent frameworks.** A 2026 study of agent frameworks for FP filtering (arXiv 2601.22952, via a Promptfoo summary) found agents can **suppress real vulnerabilities**. The worst reported case was 84.5% suppression of CWE-328 true positives in one crypto category.
- **Design implication for us:**
  - LLM verification is the right core, and cheap enough to run on every finding.
  - It also fails silently on some vulnerability classes. We need per-class calibration, holdout audits, and *never auto-close without an evidence trail* (see guardrails).

### A10. Adversarial manipulation of LLM verifiers
- **Thornton, arXiv 2602.16741.** 9,366 trials, 8 models: adversarial comments had **no statistically significant effect**.
- **ALIBI, arXiv 2607.24964.** Adaptive agentic comment attacks reportedly reach **over 90% success** against four detectors. This is **[unverified]**: seen only through a secondary write-up.
- **Design implication for us:**
  - Treat repo text (comments, docstrings, commit messages, PR descriptions, and *developer triage justifications*) as untrusted input to the agent.
  - Strip comments or show them separately for the verdict. Require code-level evidence for a "not exploitable" call.
  - Flag findings where removing comments flips the verdict.
  - This matters doubly for the flywheel: a poisoned justification could become a *memory* that suppresses findings at scale.

### A11. Transfer and federated learning across customers
- **Source.** Hu et al., "An Empirical Study of Vulnerability Detection using Federated Learning", arXiv 2411.16099 (VulFL framework).
- **Findings:**
  - Organizations rarely share vulnerability data because of privacy and IP concerns, and FL lets them train jointly without sharing raw code.
  - Results depend heavily on the model, the preprocessing, and the aggregation method.
  - Other work: FedVuln for smart contracts across mutually distrustful parties.
- **Gaps:** nothing found on FL specifically over SAST triage labels. Gradient-leakage defenses (secure aggregation, DP) were not covered by the found sources. Their need is well established in the general ML literature **[unverified here]**.
- **Design implication for us (tenant-boundary policy):**

| Knowledge type | Cross-tenant shareable? | Rationale / guardrail |
|---|---|---|
| Sanitizer/source/sink models for **public** libraries and frameworks (e.g., "`django.utils.html.escape` sanitizes XSS-HTML-body") | **Yes**, after aggregation and review | It is about public code. Promote only when confirmed by ≥k independent tenants plus internal security-research review. |
| Rule-precision statistics (rule R has X% FP in framework F) | **Yes**, aggregated with k-anonymity / DP noise | No code leaves the tenant. Use it to tune default rule severity and confidence priors. |
| Rule improvements (new pattern-not clauses) derived from FP clusters | **Yes, if** the patch only references public APIs | A human writes or reviews it. Never auto-generate from a single tenant's code. |
| Learned model weights / embeddings trained on customer code | **Default no**; opt-in FL with secure aggregation and DP | Risk of memorization or leakage of proprietary code. |
| Memories / justifications naming internal functions, paths, business logic | **Never** | Tenant-private by construction. |
| Internal sanitizer models (`acme.security.clean()`) | **Never** across orgs; yes across repos within an org | Org-scoped. |

---

## Part B — Industrial lessons on adoption

### B1. Sadowski, van Gogh, Jaspan, Söderberg, Winter, "Tricorder: Building a Program Analysis Ecosystem", ICSE 2015 (Google)
- Source: author PDF (research.google.com/pubs/archive/43322.pdf; also a cs.umd.edu mirror) via extracts.
- **Findings:**
  - Analysis results appear as **code-review comments**.
  - Reviewers and authors get **"Please fix"** and **"Not useful"** buttons. "Not useful" files a bug against the analyzer's owners.
  - **Not-useful rate** = NotUseful / (NotUseful + PleaseFix + ApplyFix).
  - Policy: **≥10% puts an analyzer on probation**. Above about 25%, the Tricorder team typically works with the author rather than disabling it immediately (per extract).
  - The paper says it enforces a very low *effective* false-positive rate, **under 10%**: developers should see a real issue at least 90% of the time.
- **Reported volumes (2015):** about **93K findings/day across ~30 categories**; reviewers click "Please fix" about **716/day** (416 from linters) versus about **48 "Not useful"/day**.
  - A later talk summary gives about 5,000 "Please fix" and 250 "Not useful" per day. Different period; not reconciled **[unverified]**.
- **Other principles (from the paper, recalled):** **[unverified wording]**
  - Analyzers must be understandable, actionable, and produce ≤10% effective FPs.
  - They must have significant impact.
  - Suggested fixes are strongly preferred.
  - Analyzers are written by domain experts ("crowdsourcing").
- **Design implication for us:**
  - Build in a per-rule (and per-rule×repo) **not-useful rate** with automatic probation, from day one.
  - The feedback button lives *where the finding is consumed* (PR comment, IDE, triage UI), takes one click, and is mandatory to instrument.
  - Feedback routes to the rule owner (our rule-learning pipeline), not into a void.

### B2. Sadowski, Aftandilian, Eagle, Miller-Cushon, Jaspan, "Lessons from Building Static Analysis Tools at Google", CACM 61(4):58–66, 2018, doi:10.1145/3188720
- Source: CACM page and abstract extracts, plus the companion book chapter "Software Engineering at Google", ch. 20 "Static Analysis" (abseil.io).
- **Findings:**
  - **Effective false positive**: an issue where the developer took no positive action, whether or not it is technically correct. *Perceived* FPs count.
  - FPs are reduced by turning off misbehaving analyzers, flagged through user feedback.
  - Tools detect "thousands of issues per day that engineers fix by their own choice before check-in".
  - The SWE book says the overall effective FP rate is **just below 5%**.
  - Google deploys only low-FP analyzers and "actively solicits and acts on developer feedback in real time".
  - A section is titled "Focus on Developer Happiness".
  - Reasons developers ignore warnings include results they don't trust because of FPs.
  - From memory: early FindBugs dashboards and batch bug-filing were ignored, which motivated the move to compile-time and code-review integration **[unverified]**.
- **Design implication for us:**
  - Optimize **effective** FP: a finding the user does not act on counts against us, even if "technically true".
  - So low-value true positives (dead code, test code, non-reachable paths) should be demoted or grouped, not just high-FP rules.
  - The dashboard is not the primary surface. The PR/diff is.

### B3. Distefano, Fähndrich, Logozzo, O'Hearn, "Scaling Static Analyses at Facebook", CACM 62(8), 2019, doi:10.1145/3338112
- Source: CACM, UCL and UCSD author copies via extracts; HN discussion 20834125.
- **Findings:**
  - Infer on Android ran first as a nightly batch over the whole codebase and produced issue lists. The FP rate was **under 20%**, yet the **fix rate was near 0%**.
  - The same analysis at **diff time** (a bot comments on the code change under review) reached a **fix rate above 70%**.
  - Reasons: the context is fresh and the developer owns the change, so there is no context-switch cost.
  - Caveat: this is a single case study, and HN commenters questioned the framing.
  - Zoncolan (the security taint analysis) is triaged by security engineers as well as developers, from memory **[unverified]**.
- **Design implication for us:**
  - **Diff-time first.** New findings introduced by a PR go to the PR author with the highest-precision subset.
  - Backlog (baseline) findings go to AppSec triage with ranking, and are never dumped on developers as a list.
  - Track fix rate by surface (PR versus dashboard) as a north-star metric.

### B4. Johnson, Song, Murphy-Hill, Bowdidge, "Why Don't Software Developers Use Static Analysis Tools to Find Bugs?", ICSE 2013, pp. 672–681
- Source: ICSE page, Google Research page, author PDF (cs.gmu.edu/~johnsonb/docs/icse2013.pdf) via extracts.
- **Findings:**
  - Based on interviews with **20 developers**. All agreed the tools help.
  - **False positives and warning presentation** are the main barriers, along with poor workflow integration and weak fix support.
  - Developers want interactive help to fix defects, and they spend a lot of time working out the defect's context.
  - Recalled: they want quick fixes, customization, and explanations of *why* something is a problem **[unverified detail]**.
- **Design implication for us:** every finding must carry an explanation, the context (the path), and a fix suggestion. Configuration must be easy and team-shareable.

### B5. Christakis & Bird, "What Developers Want and Need from Program Analysis: An Empirical Study", ASE 2016, pp. 332–343, doi:10.1145/2970276.2970347 (Microsoft)
- Source: author preprint (mariachris.github.io/Pubs/ASE-2016.pdf) and MSR copy via extracts.
- **Top pain points, most to least annoying:**
  1. Irrelevant checks on by default
  2. Bad phrasing of warnings
  3. Too many false positives
  4. Too slow
  5. No suggested fixes
  6. Hard to integrate into the workflow
- **FP tolerance:** "aim for a false positive rate no higher than **15–20%**". 47% accept up to 15%; only 24% accept 20%. Coverity designers cite less than 20% for stable checkers.
- **Speed versus precision:** 57% prefer a slower, more precise analysis.
- **Precision versus recall:** almost an even split: **49.3%** prefer fewer FPs even if bugs are missed, **50.7%** prefer finding more.
- **Design implication for us:**
  - "Irrelevant checks on by default" ranks *above* FPs. Default rule packs must be context-aware (framework, language, exposure), and learned per repo.
  - Warning text quality is a first-class engineering problem. Use LLM-generated, finding-specific explanations, anchored to the proof.
  - The 50/50 recall split argues for **user-selectable operating points** ("high-confidence only" versus "audit mode") rather than one global threshold.

### B6. Imtiaz, Murphy, Williams, "How Do Developers Act on Static Analysis Alerts? An Empirical Study of Coverity Usage", ISSRE 2019
- Source: Semantic Scholar and ResearchGate extracts.
- **Findings:**
  - Data: 5 OSS projects (Linux, Firefox, Samba, Kodi, oVirt-engine), each with 5+ years of Coverity use.
  - **27.4–49.5% of alerts were actionable (median 36.7%)**, higher than prior reports.
  - **Fixes are small: 2–7 lines (median 4)**.
  - Even so, **fix latency is 36–245 days (median 96)**.
- **Design implication for us:**
  - The bottleneck is not fix difficulty. It is prioritization, ownership, and getting the fix in front of someone.
  - Since fixes are small, **autofix PRs** are high-leverage (cf. the Copilot Autofix numbers).
  - Measure and show time-to-fix and alert age in the UI. Route each finding to its code owner.

### B7. Imtiaz, Rahman, Farhana, Williams, "Challenges with Responding to Static Analysis Tool Alerts", MSR 2019 (Mining Challenge), pp. 245–249
- **Findings:**
  - Based on 280 Stack Overflow questions.
  - The most common question is **how to ignore or filter alerts**, followed by **validating false positives**.
  - 44.6% of questions show communication challenges: developers don't understand what the alert means.
- **Design implication for us:** suppression must be easy, scoped, and auditable (people will do it anyway). Explanations must answer "is this real?" directly.

### B8. Suppression studies
- **Hu, Wang, Rubin, Pradel, "An Empirical Study of Suppressed Static Analysis Warnings"**, FSE 2025, doi:10.1145/3715729.
  - Data: 7,357 suppressions in 46 Python projects, across 4 analyzers.
  - **50.8% of suppressions affect no warning at all (useless, stale)**.
  - Reasons: FPs, suboptimal analyzer configuration, misleading warning messages.
- **"Quieting the Static: A Study of Static Analysis Alert Suppressions"**, arXiv 2311.07482 (Java, FindBugs/SpotBugs).
  - FPs were only a *minor* share of suppressions.
  - Many suppressions add technical debt or come from misleading tool suggestions and wrong assumptions.
  - Configuration-level suppressions cover large groups of warnings.
- **Design implication for us:**
  - Suppressions rot. Every suppression or learned rule needs: a scope, an owner, a reason class, an expiry or revalidation trigger, and a "still matches anything?" liveness check.
  - "Suppressed" is not the same as "false positive". The reason taxonomy has to tell apart FP, accepted risk, test-only, won't-fix, and tool misconfiguration, because each one teaches the engine something different.

### B9. Usability and explanation studies
- **Smith, Nguyen Quang Do, Murphy-Hill, "Why Can't Johnny Fix Vulnerabilities: A Usability Evaluation of Static Analysis Tools for Security"**, SOUPS 2020, pp. 221–238.
  - Method: a heuristic walkthrough plus a user study of 4 security SAST tools (3 OSS, 1 commercial).
  - Found **17 categories of developer information needs**.
  - Problems: workflows that don't support developers, interface features that don't scale, poor warning explainability, missing code examples and fix suggestions.
- **Nachtigall, Nguyen Quang Do, Bodden, "Explaining Static Analysis — A Perspective"** (ASE Workshops 2019; bodden.de/pubs/nachtigall19explaining.pdf).
  - Argues that the main design challenges for usable SA tools reduce to **explainability**.
  - Ill-explained warnings are a decade-long recurring complaint.
- **Gap:** no user study was found specifically on comprehension of taint-path traces. This is an opportunity (see Part D).
- **Design implication for us:**
  - Explanations are the product. Each finding needs: *why it is a finding* (source, propagation, sink, missing sanitizer), *why our verifier believes or doubts it* (evidence), *what would make it safe* (counterfactual), and *how to fix it* (patch).
  - Interfaces must scale to 10k findings, which means grouping and bulk actions, not one-at-a-time pages.

---

## Part C — Standards and vendor UX survey

### C1. SARIF 2.1.0 (OASIS; docs.oasis-open.org/sarif/sarif/v2.1.0)
Sources: spec extracts, microsoft/sarif-tutorials samples, oasis-tcs/sarif-spec issues #348 and #371, GitHub's SARIF support docs.
- **`result.suppressions[]`:**
  - `kind`: `inSource` | `external`.
  - `status`: `accepted` | `underReview` | `rejected`, plus justification and location.
  - Gate semantics used in practice: suppressed only when status is absent or `accepted`. `underReview` and `rejected` still fail.
- **`baselineState`:** `new` | `unchanged` | `updated` | `absent`. Diff-aware state is portable through SARIF. Per one implementer, `updated` is rarely used.
- **`partialFingerprints` / `fingerprints`:**
  - Keys are versioned. A new algorithm gets a new key, and old keys should not be removed.
  - GitHub uses `partialFingerprints` (e.g., `primaryLocationLineHash`) to deduplicate alerts across runs. Without them, users see duplicates.
- **`codeFlows` → `threadFlows` → `locations[]`:**
  - Each location has an `importance` (`essential` / `important` / `unimportant`), per the samples. The full enum was not seen in the extract.
  - GitHub keeps only the top 1,000 thread-flow locations per result.
- **Design implication for us:**
  - Use SARIF as the interchange and export format, but keep a richer internal model.
  - Emit `suppressions` with our triage state mapped onto `status`: Proposed Not Exploitable maps to `underReview`.
  - Emit `baselineState` for diff views.
  - Emit **stable semantic fingerprints**: a hash of rule + source/sink signature + normalized path skeleton, versioned. Line hashes are too weak, since triage must survive refactors.
  - Mark sanitizer-check points and `essential` steps in codeFlows so external viewers show the compact path.

### C2. Checkmarx One
Sources: docs.checkmarx.com (Managing/Triaging Vulnerabilities, SCA Results Viewer, Navigating Scan Results, Eclipse/VS plugin docs), checkmarx.com "Triage & Remediation Assist".
- **States:**
  - **To Verify**: default.
  - **Not Exploitable**: final FP. It hides the finding from later scans and reports, and needs the `update-result-not-exploitable` admin role.
  - **Proposed Not Exploitable**: tentative, still counted in reports.
  - **Confirmed**: real risk.
  - **Urgent**: imminent threat.
  - The two-step propose→approve flow is a governance pattern worth copying.
- **Attack Vector pane and Best Fix Location (BFL):**
  - The graph shows the paths of all instances. Intersections show where several results share a node.
  - Securing the BFL node fixes several instances "in one shot".
  - The BFL is labeled in the Attack Vector pane and highlighted by default in View Code.
- **AI "Triage & Remediation Assist":** separate Info (reachability/exploitability) and Remediation tabs.
- **User pain points** (G2 summaries, n≈36 reviews; competitor blogs, so biased):
  - High FP volume (Kotlin and Apex cited) and a long triage time.
  - Slow scans (mixed reports).
  - The UI itself is mostly praised.
  - A competitor blog claims an FP rate of about 36% **[unverified]**.
- **Design implication for us:**
  - BFL is the right primitive. We generalize it to **"best triage location" and "best fix location"** computed over Datalog derivations: the minimal cut set of nodes whose verdict or fix resolves the most findings.
  - Copy propose/approve, but make approval fast: a batch approval queue showing the evidence diff.

### C3. Semgrep AppSec Platform (Assistant, Memories, noise filtering)
Sources: semgrep.dev blogs (Jan 2025 "96% agreement", "AI noise filtering & triage memories", Sep 2025 "60% of triage"), docs (Customize Assistant, Best practices for Memories, May 2025 release notes, Memories API "create-memory-from-triage").
- **Auto-triage:**
  - Users agree with verdicts **95%** of the time; security researchers **96%**. Base: 250k+ findings, 45+ enterprises.
  - Assistant handled about **60% of new SAST findings**, up from about **20%** without memories (the latter figure is secondary).
  - One customer saw **2.8x more FP detection with 2 memories**: an anecdote.
  - All figures **[vendor-reported]**. Agreement is not precision or recall, and no FN rate was published.
- **Noise filter:** filtered findings are hidden from developers and PR comments. AppSec can review them all in one view and bulk-triage.
- **Memories:**
  - Free-text org knowledge, scoped by project, rule, or vuln class, or global to the org.
  - **Suggested from triage**: ignore with a reason, Assistant drafts a memory, an admin accepts or declines.
  - The UI shows each memory's scope and impact (number of findings affected).
  - Assistant sees the rule, the matched code, surrounding lines, the KB, memories, and prior fixes. It does **not** see whole-program analysis.
- **Design implication for us:**
  - Semgrep is the closest competitor, and it validates the direction.
  - Our edge has to come from:
    - (1) **structured** learned knowledge (sanitizer models, Datalog facts) rather than free-text memories alone, so a learned fact changes *analysis results*, not just LLM prompts;
    - (2) whole-program provenance shown to the verifier;
    - (3) published, calibrated precision and FN metrics per class;
    - (4) impact preview *before* a memory is accepted, including a sample of what it would hide.

### C4. GitHub code scanning (CodeQL) and Copilot Autofix
Sources: GitHub docs (resolve alerts; triaging alerts in PRs; about autofix), github.blog (GA post), changelog 2026-07-10 (agentic autofix), CData and community REST references.
- **States:** open / fixed / dismissed.
  - Dismissal reasons: **false positive**, **won't fix**, **used in tests**, plus an optional comment.
  - A dismissal applies across branches.
  - The reason taxonomy is minimal and does not feed back into the analysis.
- **Copilot Autofix (beta data, GitHub-reported):**
  - Median time to commit a fix for PR-time alerts: **28 min versus 1.5 h manually**.
  - XSS: **22 min versus ~3 h**. SQLi: **18 min versus 3.7 h**.
  - A secondary source says more than two-thirds of addressed alerts were resolved with little or no editing.
  - When no fix is produced, Copilot may say the alert "could be a false positive". A practitioner warns this is evidence, not grounds for auto-dismissal.
- **Agentic autofix** (public preview, July 2026): validates fixes by re-running CodeQL. Generation takes about 2–4 min.
- **Design implication for us:**
  - The fix is the best triage action. A verified fix (re-scan proves the path is gone and tests pass) is the strongest TP label.
  - Fix-attempt failure is a weak FP signal. Feed it to the verifier; never auto-dismiss on it.

### C5. Veracode
Sources: docs.veracode.com (Propose mitigations; Mitigate vulnerabilities; Update multiple mitigations), Veracode community "Mitigations" series.
- **Mitigation types:** **Potential False Positive** and **Mitigated by Design** (the default when unsure), plus others (by network environment, by OS environment, accept risk) **[unverified list]**.
  - A proposal shows "(proposed)" until a **Mitigation Approver** approves or rejects it.
  - Approving a PFP removes it from the report, and the org accepts the risk.
- **Common rejections:** arguing that remediation is impossible instead of describing a compensating control, and choosing PFP for valid findings.
- **Other:** bulk "update multiple mitigations" exists. Veracode markets a 1.1% FP rate **[vendor-reported]**. Competitors note 30–60 min binary scan cycles.
- **Design implication for us:**
  - The mitigation *type* taxonomy is valuable for learning. "Mitigated by design" (a compensating control outside the code) differs from "the analyzer is wrong".
  - Approver guidance ("describe the compensating control") is something an LLM can check automatically, pre-screening proposals before a human approver sees them.

### C6. SonarQube Security Hotspots
Source: docs.sonarsource.com security-hotspots (10.x–2026.x).
- **States:** **To review** → **Acknowledged** (risk recognized, resolution pending) / **Fixed** / **Safe**.
- A hotspot is "security-sensitive code that needs human review". It is separated from vulnerabilities, which carry high confidence.
- SonarSource states it prefers false negatives to false positives, for credibility.
- **Design implication for us:**
  - The two-tier split (confident findings versus review-needed hotspots) maps onto our confidence calibration.
  - Low-confidence findings should not be shown as "vulnerabilities" to developers. They belong in an AppSec review lane.

### C7. Snyk Code
Sources: docs.snyk.io (ignore issues; CLI `snyk ignore`), G2 and PeerSpot review summaries.
- **Ignores:**
  - `.snyk` ignores do **not** work for Snyk Code. You need `snyk ignore create` with "Consistent Ignores".
  - The default expiry is 30 days.
  - A malformed expiry date makes the ignore **persist indefinitely** (a footgun).
  - `--reason` is not supported for Snyk Code.
  - In the UI, an ignore records who set it, and an ignore can end on expiry or when a fix becomes available.
- **Complaints:** FPs appearing months after import, and unreachable or irrelevant findings. Users want reachability and context-aware scanning.
- **Design implication for us:**
  - Expiring ignores are good. Malformed or implicit permanence is bad.
  - Every suppression must carry a required reason (structured, not free text only) and an explicit expiry or revalidation policy.

### C8. Market pain points (consolidated)
Sources: Christakis & Bird; Johnson et al.; Imtiaz MSR'19; G2/Capterra/PeerSpot summaries; vendor and competitor blogs (Pixee, ZeroPath, Corgea, appsecsanta); no direct Reddit/HN thread retrieved.
1. **Noise / FPs** and the resulting tune-out ("noise generators"). This is universal.
2. **Irrelevant checks on by default**; generic rules that miss framework semantics (e.g., Django auto-escaping).
3. **Bad explanations**: "why is this a finding?" goes unanswered.
4. **Suppressions are awkward, unscoped, and rot** (50.8% useless).
5. **Approval workflows are slow**: propose/approve with no batch and no evidence.
6. **Triage doesn't propagate**: each finding is handled alone, with no "fix the 40 like this".
7. **Dashboards dumped on developers** produce about a 0% fix rate (Facebook).
8. **Slow scans** (minutes to hours for binary or full scans).
9. **Opaque AI triage**: agreement rates with no FN disclosure, and AI verdicts that hide findings without an audit trail.
10. **Triage doesn't survive** branch, refactor, or tool upgrades (fingerprint instability, duplicates).

---

## Part D — UX opportunities nobody does well yet

| Opportunity | Status in market (as observed) |
|---|---|
| Impact preview *before* committing a verdict ("this will auto-resolve 37 findings in 9 repos; 3 are Confirmed elsewhere — conflict") | Semgrep shows memory impact counts. Nobody previews conflicts or shows samples. |
| Bulk triage by **root cause**: by sanitizer, by flow-through helper, by source, by BFL node | Checkmarx BFL is fix-oriented and graph-based, not a triage grouping. Nobody groups by "missing-sanitizer hypothesis". |
| "Why is this a finding / why not" with **counterfactual evidence** ("would be safe if `escape()` were applied at line 42; the verifier checked 3 candidate sanitizers on the path: none applies to HTML-attribute context") | Not done. Explanations are static rule docs or LLM prose. |
| **Calibrated confidence** shown as a probability with a reliability guarantee ("among findings scored 0.9, 91% were confirmed in your org") | Not done. Vendors show severity, not calibrated confidence. |
| **Keyboard-driven inbox-zero** triage (j/k, `x` not-exploitable with reason picker, `c` confirm, `s` snooze, `.` apply to group) | Not done in any SAST UI found. Common in email and code review tools. |
| **Diff-aware** views: "new in this PR / since last release / since last triage session" | Partly (GitHub PR alerts, SARIF baselineState). Not as a first-class triage lens. |
| **Uncertainty-ordered queue** (active learning), with a progress estimate of remaining TPs | Not done in products. Academic only (Yang/Menzies, Bingo). |
| **Suppression health**: stale, never-matching, expired, conflicting suppressions | Not done (cf. FSE'25: 50.8% useless). |
| LLM pre-screening of human justifications ("This justification claims input validation but the validator at L88 allows `'`") | Not done. |
| Learned knowledge as **inspectable, editable, versioned artifacts** (sanitizer models, rule patches), with provenance back to the triage decisions that created them | Partly (Semgrep Memories are text). Not structured, not versioned with rollback. |

---

## Synthesis 1 — Flywheel design: what to learn, at which scope, with which guardrails

### Signals (weakest to strongest) and their learning targets

| # | Signal | Label strength | What it teaches | Default scope |
|---|---|---|---|---|
| S1 | Finding ignored, no action (Google's "effective FP") | Very weak | Rule usefulness prior; surface choice (stop showing on PR) | rule×repo stats only |
| S2 | LLM agent verdict (TP/FP + rationale + evidence pointers) | Weak–medium; calibrated per class | Candidate sanitizer/guard facts; candidate rule refinements; ranking feature | finding (applied), proposals for higher scopes |
| S3 | Developer PR reaction ("Not useful", "Please fix", thumbs) | Medium, noisy (incentive to dismiss) | Rule×repo not-useful rate → probation; explanation quality | rule×repo; rule (aggregated) |
| S4 | Autofix attempted, no fix possible | Weak FP hint | Route to verifier and human; never auto-close | finding |
| S5 | AppSec triage verdict with **structured reason** (sanitized-by X / unreachable / test-only / mitigated-by-design / accepted risk / tool misconfigured) | Strong | Reason-specific (below) | finding → proposed sanitizer/rule/repo knowledge |
| S6 | Approved mitigation (two-person) | Strong | Same as S5, eligible for automatic propagation | org |
| S7 | Verified fix (re-scan shows path gone, tests pass, fix touches path) | Strongest TP | Rule is valuable here; fix template learning; sanitizer used in fix becomes a confirmed sanitizer | rule, org (fix templates), global (public-lib sanitizer) |
| S8 | Reopen / regression / pentest or bug-bounty hit on a suppressed finding | Strongest negative on a suppression | Revoke the suppression and its derived knowledge; audit everything it touched | everywhere the knowledge propagated |

### Reason → knowledge mapping (structured reasons are what make the flywheel work)
- **"Sanitized by `f`"** → a sanitizer-model candidate `(f, vuln-class, context, arg-position)`.
  - It is validated by the agent (does `f` actually neutralize the payload class?), optionally by a micro-fuzz or unit harness, and by the Z-ranking statistic (does `f` precede this sink elsewhere?).
  - Scope ladder: finding → repo → org (if `f` is internal) → global (if `f` is a public library API and confirmed by ≥k orgs plus internal research review).
- **"Unreachable / dead / not exposed"** → a repo-level **entrypoint / exposure model** (which routes are internet-facing). It never becomes a rule change.
- **"Test-only"** → path-classification learning (test globs, fixtures) at repo or org level. Low risk.
- **"Mitigated by design"** (WAF, network isolation) → a repo/org **environment fact** with an expiry and an owner. It never propagates globally and never changes the rule.
- **"Rule is wrong"** (the pattern misfires) → a **rule-refinement proposal** (pattern-not, type constraint) generated from the FP cluster, plus a regression test from the FP and from known TPs. Global only after human rule-owner review and replay on a TP benchmark.
- **"Accepted risk / won't fix"** → **no learning about correctness**. Governance only: owner, expiry, risk register.
- **Bingo-style propagation:** each verdict is also evidence on Datalog intermediate tuples (flow edges, sanitizer facts). Beliefs propagate to findings with shared derivations, and the ranking updates immediately (Kremenek 2004).

### Scopes
`finding` (fingerprint) ⊂ `rule×file/function` ⊂ `rule×repo` ⊂ `sanitizer-model (org)` ⊂ `org` ⊂ `global (public-API facts and rule-precision priors only)`.

### Guardrails against poisoning and over-suppression
1. **Recall-protecting holdout ("canaries").**
   - Keep a labeled set of known-TP findings per vuln class: seeded vulnerable fixtures plus historically confirmed TPs.
   - Every learned artifact (suppression, sanitizer model, rule patch, memory) is replayed against it before activation. Any TP loss blocks activation unless explicitly overridden.
2. **Impact budget and staged rollout.** A new piece of knowledge that would suppress more than N findings, or more than X% of a rule's findings, needs a second approver. It first runs in **shadow mode**: findings are labeled "would be suppressed by K#123", not hidden.
3. **Two-person rule for scope escalation.** Finding-level verdicts take one triager. Repo/org knowledge needs an approver. Global knowledge needs internal security research plus k-of-n tenant corroboration (no single tenant can push global knowledge).
4. **Evidence-required suppressions.** A "Not exploitable" verdict, whether from the LLM or a human, must cite code evidence (the sanitizer call site, the guard condition, the unreachability proof). Free-text-only justifications are allowed, but they are not learned from.
5. **Untrusted-text hygiene.** Comments, commit messages, and triage justifications are untrusted inputs (A10). The agent's verdict is recomputed with comments stripped. Disagreement routes to a human. Memory text is screened for instructions ("ignore all SQLi") before acceptance.
6. **Calibration monitoring per (vuln class × language × rule).**
   - Keep reliability diagrams of agent confidence against human verdicts.
   - Auto-hide only in classes where measured precision of FP-calls is at least the target (e.g., ≥98%) with a CI lower bound. Elsewhere, the agent only re-ranks.
   - This answers the A9 finding that agents suppress whole TP classes.
7. **Random audit sampling.** A fixed percentage of auto-suppressed findings goes back to humans each week. Measured FN rates are published in-product (beating "96% agreement").
8. **Expiry, liveness, and revalidation.** All knowledge has a TTL or a revalidation trigger: code change on the cited sanitizer, library version bump, rule version bump. Never-matching suppressions are flagged (FSE'25 50.8%).
9. **Provenance and rollback.**
   - Every piece of knowledge links to the verdicts that created it. Every suppressed finding links to the knowledge that suppressed it.
   - A single click revokes a piece of knowledge and un-suppresses everything downstream (an S8 response).
10. **Tenant isolation** per the A11 table. Cross-tenant sharing is limited to public-API models and aggregated statistics, with k-anonymity and optional DP. No customer code, identifiers, or free-text memories cross tenants.
11. **Evaluation discipline** (A4): time-split, repo-grouped evaluation. No "alert disappeared" labels. Dashboard metrics include effective FP rate, fix rate by surface, FN rate from audits, and time-to-triage.

---

## Synthesis 2 — Prioritized UX feature list for a market-beating triage UI

**P0: must have at launch (each answers a documented top pain point)**
1. **Diff-time PR surface with a high-precision tier only** (Facebook >70% vs ~0%; Google Tricorder).
   - Only new, high-confidence findings appear, as a PR comment carrying the explanation and an autofix.
   - One-click "Not useful" / "Please fix" feeds the per-rule not-useful rate, with automatic probation at ≥10%.
2. **Evidence-first finding view: "Why this is a finding / why it might not be".**
   - A compact source→sink path with only the `essential` steps.
   - The candidate sanitizers and guards that were checked, with why each was rejected.
   - The agent's verdict with code citations and a **counterfactual**: "safe if X at L42".
   - Rationale: bad warnings ranked #2 (Christakis & Bird); 44.6% of SO questions were communication problems; explainability is *the* usability problem (Nachtigall et al.).
3. **Calibrated confidence + two lanes.**
   - "Verified" findings (calibrated ≥ target precision) go to developers. "Needs review" findings (hotspot-like) go to AppSec.
   - Users choose the operating point, which fits the 49/51 precision-recall split.
4. **Root-cause grouping and bulk triage.**
   - Group by Datalog cut nodes (missing sanitizer hypothesis, shared flow-through helper, shared source, best-fix location).
   - One verdict on the group, with per-member exceptions.
   - Rationale: generalizes Checkmarx BFL; Bingo/Kremenek propagation; the 2–8x and 44% inspection savings.
5. **Impact preview before commit.**
   - Every verdict or suppression shows "affects N findings across M repos" with a sample and conflicts (e.g., some were Confirmed or fixed elsewhere).
   - Shadow mode by default for large-impact knowledge.
6. **Structured reasons with required evidence** (sanitized-by / unreachable / test-only / mitigated-by-design / accepted-risk / rule-wrong) plus expiry.
   - Map them to SARIF `suppressions.status` (Proposed → `underReview`).
   - Rationale: reasons are the flywheel's input; Snyk's implicit-permanent ignore and GitHub's three-reason taxonomy are too thin.
7. **Stable semantic fingerprints**, so triage survives refactors, branches, and rule upgrades. Export SARIF with `partialFingerprints` and `baselineState`.

**P1: differentiators**

8. **Keyboard-driven inbox-zero triage.**
   - j/k navigation, single-key verdicts, a reason picker, `.` apply-to-group, `u` undo, `s` snooze-until-event.
   - A progress bar shows an "estimated true positives remaining" (from the ranking model).
   - Nobody offers this. Analysts triage hundreds of findings per session.
9. **Active-learning queue order.** Highest information gain first, not severity or FIFO (Yang/Menzies: 90% of actionable findings while ignoring 70–80%). A "why is this next?" tooltip.
10. **Live re-ranking after each verdict** (Kremenek 2004). A toast reads: "Marked N related findings as likely FP; review group?"
11. **Learned-knowledge workbench.**
    - Sanitizer models, environment facts, and rule patches appear as versioned, diffable artifacts with provenance (which verdicts created them) and the canary-replay result.
    - Approve, reject, or edit; one-click rollback.
    - This is structured, unlike free-text memories.
12. **Mitigation approval queue with LLM pre-screen.**
    - The approver sees the justification, the agent's check of it ("validator at L88 allows `'`"), and the evidence diff. Batch approve.
    - Rationale: fixes Veracode/Checkmarx propose→approve latency and the common rejection causes.
13. **Fix-as-triage.**
    - Autofix PR with verified re-scan; the fix is the TP label.
    - Show "fix at best-fix location resolves K findings" (GitHub 28 min vs 1.5 h; Coverity fixes median 4 LOC but 96 days to fix).
14. **Diff lenses:** new in this PR / since last release / since my last session / newly suppressed by knowledge K / reopened.

**P2: trust and governance**

15. **Suppression health dashboard:** stale, never-matching, expiring, conflicting, and suppressions whose cited sanitizer changed.
16. **Transparency metrics in-product:** per-class measured precision of auto-suppression, audited FN rate, effective FP rate (Google definition), fix rate per surface, and median time-to-triage and time-to-fix. Publish what Semgrep does not (FN rates).
17. **Audit trail and attribution** on every hidden finding: who or what hid it (human / agent / knowledge K#), when, the evidence, and a one-click restore.
18. **Ownership routing** (CODEOWNERS / blame) and SLA aging, since latency is driven by routing, not fix complexity (Imtiaz ISSRE'19).
19. **Context-aware default rule packs** that learn per repo which checks are irrelevant. This targets the #1 pain point, "irrelevant checks on by default".

---

## Source list (consulted via search extracts; WebFetch unavailable this session)
- Kremenek & Engler, SAS 2003, via dblp and Engler slides: https://www.sos-vo.org/system/files/sos_files/System-specific_static_bug_finding_tricks_bitter_experience_open_problem.pdf
- Kremenek et al., FSE 2004: https://www.cs.columbia.edu/~junfeng/papers/ranking-fse.pdf
- Heckman & Williams, IST 2011: https://dblp.org/rec/journals/infsof/HeckmanW11.html ; comparative eval: https://dl.acm.org/doi/10.1145/2499393.2499399
- ML-AWI survey: https://arxiv.org/abs/2312.00324
- Kang, Aw, Lo, ICSE 2022: https://arxiv.org/abs/2202.05982
- Koc et al., MAPL 2017: https://www.cs.tufts.edu/~jfoster/papers/mapl17.pdf
- Kharkar et al., ICSE 2022: https://arxiv.org/abs/2203.09907
- Raghothaman et al., PLDI 2018: https://www.cis.upenn.edu/~mhnaik/papers/pldi18a.pdf ; https://github.com/difflog-project/bingo
- Yang, Yu, Wang, Menzies, ESWA 2021: https://arxiv.org/abs/1911.01387
- Du et al., ICSE-SEIP 2026: https://arxiv.org/abs/2601.18844 ; LLM4PFA: https://arxiv.org/abs/2506.10322
- Thornton 2026: https://arxiv.org/abs/2602.16741 ; ALIBI: https://arxiv.org/pdf/2607.24964
- Hu et al., FL for vulnerability detection: https://arxiv.org/abs/2411.16099
- Sadowski et al., Tricorder ICSE 2015: https://research.google.com/pubs/archive/43322.pdf
- Sadowski et al., CACM 2018: https://cacm.acm.org/research/lessons-from-building-static-analysis-tools-at-google/ ; SWE book ch. 20: https://abseil.io/resources/swe-book/html/ch20.html
- Distefano et al., CACM 2019: https://cacm.acm.org/research/scaling-static-analyses-at-facebook/ ; HN: https://news.ycombinator.com/item?id=20834125
- Johnson et al., ICSE 2013: https://cs.gmu.edu/~johnsonb/docs/icse2013.pdf
- Christakis & Bird, ASE 2016: https://mariachris.github.io/Pubs/ASE-2016.pdf
- Imtiaz, Murphy, Williams, ISSRE 2019: https://www.semanticscholar.org/paper/41e9db2a9c2d96fbeedccef95700048726efddb8
- Imtiaz et al., MSR 2019: https://2019.msrconf.org/details/msr-2019-Mining-Challenge/16/Challenges-with-Responding-to-Static-Analysis-Tool-Alerts
- Hu, Wang, Rubin, Pradel, FSE 2025: https://people.ece.ubc.ca/mjulia/publications/Suppressed_Static_Analysis_Warnings_FSE2025.pdf ; Quieting the Static: https://arxiv.org/abs/2311.07482
- Smith et al., SOUPS 2020: https://www.usenix.org/conference/soups2020/presentation/smith ; Nachtigall et al.: https://www.bodden.de/pubs/nachtigall19explaining.pdf
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html ; https://github.com/microsoft/sarif-tutorials ; https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- Checkmarx: https://docs.checkmarx.com/en/34965-68516-managing--triaging--vulnerabilities.html ; https://docs.checkmarx.com/en/34965-253661-sca-results.html ; https://docs.checkmarx.com/en/34965-8115-understanding-eclipse-scan-results.html ; https://checkmarx.com/inside-checkmarx-triage-remediation-assist/ ; G2: https://g2.com/products/checkmarx/reviews
- Semgrep: https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/ ; https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories/ ; https://semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-of-all-triage-for-users-without-reducing-coverage ; https://semgrep.dev/docs/semgrep-assistant/customize ; https://semgrep.dev/docs/semgrep-assistant/best-practices-for-memories
- GitHub: https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/resolve-alerts ; https://github.blog/news-insights/product-news/secure-code-more-than-three-times-faster-with-copilot-autofix/ ; https://github.blog/changelog/2026-07-10-agentic-autofix-for-code-scanning-alerts-in-public-preview/
- Veracode: https://docs.veracode.com/r/Propose_mitigations_for_flaws ; https://docs.veracode.com/r/Propose_Mitigating_Factors_for_a_Flaw
- SonarQube: https://docs.sonarsource.com/sonarqube-server/user-guide/security-hotspots
- Snyk: https://docs.snyk.io/developer-tools/snyk-cli/commands/ignore ; https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/ignore-issues
