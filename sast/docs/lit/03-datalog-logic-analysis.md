# 03 — Logic-based program analysis and learning analysis rules

Scope: Datalog and logic engines for static analysis (Doop, Soufflé and its provenance, CodeQL/QL, Flix, IncA, DDlog), learning from user feedback on derivations (Bingo, Drake, BayeSmith and follow-ups), synthesizing Datalog rules (ALPS, Difflog, ProSynth), probabilistic and differentiable logic (Scallop, ProbLog), Semgrep taint internals and output, Joern/CPG, and 2023–2026 work that combines LLMs with Datalog or QL. It ends with a recommendation for the logic engine of the Python POC and a schema sketch.

Date of review: 2026-10-24.

## Method and caveats (read first)

- **Sources.** Web search plus hands-on checks in a scratch environment. Most paper PDF hosts (arxiv.org, cis.upenn.edu, kaist.ac.kr, semgrep.dev, docs.semgrep.dev, souffle-lang.github.io) **could not be reached** from this session (DNS failure or proxy denial), so I could not read full PDFs. Paper numbers below come from abstracts and search-result extracts of those papers. Where a number appears only in a secondary source, or comes from memory, it is marked **[unverified]**. The session's web-search budget ran out before I could look up NeuroLog, NESA/LLMSA and Scallop follow-up work in detail, so those entries are thinner. A follow-up pass should read the PDFs.
- **Hands-on checks (done in this session):**
  1. Checked which Python logic packages pip can install (on Python 3.13, x86_64 Linux) and what apt offers on Ubuntu 24.04. See §6.1.
  2. Installed Semgrep 1.182.1 (OSS) in a scratch venv. Ran a taint rule on a small Flask file, and read the bundled `semgrep_output_v1.py` and `rule_schema_v1.yaml`. See §4.
  3. Installed ProbLog 2.3.0, clingo 5.8.0 and pyDatalog 0.22.4 in a scratch venv. Ran a Bingo-style conditioning example and some micro-benchmarks. See §6.2.

---

## 1. Datalog engines for program analysis

### 1.1 Doop
- **Citation.** M. Bravenboer, Y. Smaragdakis. *Strictly Declarative Specification of Sophisticated Points-to Analyses.* OOPSLA 2009. https://developer.logicblox.com/2009/07/strictly-declarative-specification-of-sophisticated-points-to-analyses/ ; follow-up: Smaragdakis & Bravenboer, *Using Datalog for Fast and Easy Program Analysis*, Datalog 2.0 (2010/11), https://link.springer.com/chapter/10.1007/978-3-642-24206-9_14
- **Mechanism.** The whole Java points-to analysis (context-sensitive variants, call-graph construction on the fly, reflection and exception handling) is written in Datalog over relations extracted from bytecode. The analysis was originally run on LogicBlox. Doop was later ported to Soufflé ("Porting Doop to Soufflé", SOAP 2017, https://dl.acm.org/doi/10.1145/3088515.3088522).
- **Results.** The abstract reports that Doop runs **more than 15x faster than Paddle** for a 1-call-site-sensitive analysis on DaCapo, at identical precision, with smaller gains for other analyses. The authors say the gap comes mostly from explicit representation versus BDDs, and that the declarative specification made optimisation easier. The Soufflé port reports up to 4x from parallelism [secondary source].
- **Limitations.** Whole-program and batch only. Precision and scalability depend on hand-tuned rule order and indices (in LogicBlox and Soufflé). The front end (fact extraction) is a large engineering effort per language. Doop has no Python front end.
- **Design implication for us.** This is the key existence proof that a serious analysis can be "facts + rules". The lesson is the *architecture*: a front end emits flat relations, and every piece of analysis logic is a rule. That makes rules inspectable, diffable and learnable. We do not need Doop's points-to depth. Semgrep already gives us intra- and inter-procedural taint, so our Datalog layer works at a coarser level: findings, guards, config and framework facts.

### 1.2 Soufflé
- **Citation.** H. Jordan, B. Scholz, P. Subotić. *Soufflé: On Synthesis of Program Analyzers.* CAV 2016 (Part II, LNCS 9780, pp. 422–430). PDF: https://static.aminer.org/pdf/20170130/pdfs/cav/i5oalygn1b0zj7m3ku9iwrc62ubpwtt8.pdf ; repo: https://github.com/souffle-lang/souffle
- **Mechanism.** Futamura-style specialisation compiles a Datalog program to parallel C++ (semi-naive evaluation, specialised B-tree and trie indices, automatic index selection). There is also an interpreter mode. Souffle supports stratified negation, aggregates, ADTs, components, user-defined functors and subsumption.
- **Results.** The abstract reports a points-to analysis of OpenJDK7 (1.4M variables, 350K objects, 160K methods) in **under a minute**, and Java security analyses in use at Oracle Labs. Talk abstracts also mention analysis of AWS VPC networks with 10,000 instances in under 15 minutes [secondary source].
- **Packaging (checked).** The latest release is **2.5**. Its release notes list packages for "Fedora 39/40/41, Ubuntu 22/24, Oracle Linux 9" (GitHub releases page). Soufflé is **not** in Ubuntu 24.04 apt (checked: `apt-cache policy souffle` gives no candidate). It has **no official Python bindings**. The README lists C++ and SWIG interfaces only. The PyPI package `souffle` is an unrelated project ("A light and fluffy serving of Cheese"). From Python you would call it as a subprocess, passing facts as TSV in and out, or use the SWIG wrapper.
- **Limitations.** You must compile for speed. Without compilation the interpreter is still fast. It has no incremental evaluation and no probabilistic semantics. Provenance is a separate mode (next section).
- **Design implication for us.** Soufflé is the obvious **scale-up target** if our rule base and fact volume grow, for example whole-monorepo call graphs. Keep our rule dialect a subset that translates mechanically to Soufflé: `.decl`-style typed relations, stratified negation and simple aggregates, with no ASP choice rules or Prolog cuts.

### 1.3 Soufflé provenance (Zhao, Subotić, Scholz)
- **Citation.** D. Zhao, P. Subotić, B. Scholz. *Debugging Large-scale Datalog: A Scalable Provenance Evaluation Strategy.* ACM TOPLAS 42(2), 2020 (arXiv title: *Provenance for Large-scale Datalog*, 1907.05045). https://souffle-lang.github.io/pdf/toplas20.pdf ; https://arxiv.org/abs/1907.05045 . Related: D. Zhao PhD thesis, *Provenance, Incremental Evaluation, and Debugging in Datalog* (Sydney), https://ses.library.usyd.edu.au/bitstream/handle/2123/29493/Zhao_David_thesis.pdf
- **Mechanism.** Storing full provenance is too expensive. Instead, each tuple is annotated during evaluation with cheap metadata: the rule that first derived it and its proof height. Afterwards, a proof tree of **minimal height** is rebuilt lazily, on demand and top-down, by a "subproof search": for each rule, a generated subroutine finds body tuples of lower height. "Why not" questions about a missing tuple get *failed* subproofs, which show which body atom or constraint is missing. The feature is exposed interactively (Soufflé `-t explain` / `explore`, with commands such as `explain`, `explainnegation` and `setdepth`) [command names from memory and secondary sources, not checked against the docs].
- **Results.** Runtime overhead is about **1.31x** on average in TOPLAS (1.27x runtime and 1.45x memory in the arXiv version). Minimal-height proof trees for Doop analyses of medium-sized programs have heights **over 200**. The number of nodes grows exponentially with height, which is why the method shows one minimal proof rather than all proofs.
- **Limitations.** You get *one* proof, of minimal height, not the set of all derivations. Bingo-style inference needs the **whole derivation hypergraph** (every rule instance that could have produced a tuple). The interactive interface is designed for people, not as a library API. Support for negation, aggregates and subsumption in explanations is limited [unverified detail].
- **Design implication for us.** (a) For *human and LLM explanations* of a finding, a single short proof tree is exactly the right product. (b) For *feedback propagation* (Bingo), we need all rule instances, so we must record provenance ourselves through rule instrumentation (§6.3). (c) Proof height matters for usability: keep our rule layers shallow (findings → evidence → verdict), so explanations stay short.

### 1.4 CodeQL / QL
- **Citation.** P. Avgustinov, O. de Moor, M. Peyton Jones, M. Schäfer. *QL: Object-oriented Queries on Relational Data.* ECOOP 2016, LIPIcs 56, 2:1–2:25. https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ECOOP.2016.2 (the paper notes that the Semmle-hosted version is the canonical, corrected one). Also *QL for source code analysis* (Semmle), https://codeql.github.com/publications/ql-for-source-code-analysis.pdf
- **Mechanism.** QL is an object-oriented surface language that compiles to Datalog. A class is a unary predicate (its *characteristic predicate*). A subclass is implication. A method is a predicate with `this` and `result` parameters. Virtual dispatch resolves to the most specific class containing the receiver. Types are *prescriptive*: they constrain evaluation instead of only describing it. The language runs on a relational extraction of the program, which is a database per snapshot. The security libraries implement global data flow with a configuration of `isSource`, `isSink`, `isBarrier` (sanitiser) and `isAdditionalFlowStep` (propagator), and path queries produce source-to-sink paths [config API from memory, current naming may differ: `DataFlow::ConfigSig`].
- **Results.** The paper reports analyses of several languages on code bases of millions of lines. CodeQL is now the engine behind GitHub code scanning.
- **Limitations.** It is proprietary, and its licence restricts use on non-OSS code without GitHub Advanced Security. A database must be extracted per build, and for compiled languages that needs a working build. The QL toolchain is not embeddable in Python. In IRIS (§5) CodeQL alone found only 27 of 120 real Java CVEs, which shows that **spec coverage, not engine power, limits recall**.
- **Design implication for us.** (a) The source / sink / barrier / additional-flow-step vocabulary maps one-to-one onto Semgrep's sources / sinks / sanitizers / propagators. We should use the same four concepts as relation names, so LLM-inferred specs can feed either engine. (b) QL's "class = predicate" view is a good pattern for our rule base, for example `class UserInput extends Source`, which becomes `user_input(L) :- source(L, K), K in {...}`. (c) The LLM-writes-QL line of work (QLPro, QLCoder; §5) shows that LLMs *can* write analysis rules but need compile / repair / execute loops. We should apply the same pattern to Datalog rules.

### 1.5 Flix
- **Citation.** M. Madsen, M.-H. Yee, O. Lhoták. *From Datalog to Flix: A Declarative Language for Fixed Points on Lattices.* PLDI 2016. https://plg.uwaterloo.ca/~olhotak/pubs/pldi16.pdf ; DOI 10.1145/2908080.2908096
- **Mechanism.** Datalog extended with user-defined lattices and monotone functions. Its model-theoretic semantics generalise Datalog's, and it uses an adapted semi-naive evaluation. The paper expresses IFDS and IDE in it. Flix has since grown into a general functional language on the JVM with first-class Datalog constraints.
- **Results.** A prototype ran IFDS/IDE-style analyses. A secondary summary says it was 2.5–3.1x slower than optimised hand-written baselines [secondary source].
- **Limitations.** JVM-only, with no Python embedding. The paper motivates Flix by the pain of the "write facts to file, run solver, read back" interop pattern, which is exactly what we would face with Soufflé.
- **Design implication for us.** Lattice-valued relations are the principled way to carry **confidence or severity as a lattice**, for example `max` over evidence, and Soufflé subsumption and Scallop provenance semirings generalise the same idea. In a Python POC we can approximate with "max-confidence" aggregation in a post-pass, so a lattice engine is not required.

### 1.6 IncA / incremental lattice Datalog (Szabó et al.)
- **Citation.** T. Szabó, G. Bergmann, S. Erdweg, M. Voelter. *Incrementalizing Lattice-Based Program Analyses in Datalog.* OOPSLA 2018 (PACMPL 2, Article 139). https://voelter.de/data/pub/inca-oopsla2018.pdf ; DOI 10.1145/3276509. Earlier: Szabó, Erdweg, Voelter, *IncA: A DSL for the Definition of Incremental Program Analyses*, ASE 2016 [from memory].
- **Mechanism.** DRedL, an extension of Delete-and-Rederive to *lattice-valued* recursive aggregation, so that results can be updated incrementally after code edits even with non-monotonic changes. It is built on the IncQuery/VIATRA graph-pattern engine inside MPS.
- **Results.** Strong-update points-to and string analyses for Java update within **milliseconds** after a code change (abstract). I could not get the exact figures.
- **Limitations.** JVM/MPS ecosystem. A research artifact, not a maintained library.
- **Design implication for us.** For the IDE / PR-diff use case, incrementality matters at the *fact* level: re-run Semgrep on changed files, retract their facts, re-derive. At POC scale (thousands of tuples), re-evaluating from scratch in under a second is cheaper than an incremental engine (§6.2). Defer incrementality. Do design fact IDs to be **file-scoped**, so retraction is easy later.

### 1.7 Differential Datalog (DDlog)
- **Citation.** L. Ryzhyk, M. Budiu. *Differential Datalog.* Datalog 2.0 workshop, 2019. https://research.vmware.com/publications/differential-datalog ; repo: https://github.com/vmware-archive/differential-datalog
- **Mechanism.** Compiles ordinary (non-incremental) Datalog with a rich type system into Rust programs on Differential Dataflow. All evaluation is incremental over insert and delete deltas.
- **Status (checked).** The GitHub repo is **archived (read-only) since 13 Jul 2026**. Its last push was in 2023. It has **no Python bindings** (Java, C, Go and Rust only). The FlowLog paper (2025, arXiv 2511.00865) reports that DDlog "incurs significant memory overhead, often orders of magnitude higher" than alternatives [secondary source].
- **Design implication for us.** **Do not adopt.** It is a dead project with no Python path. The idea (write batch rules, get incremental evaluation) remains the goal if we ever need it. Watch FlowLog and similar newer engines.

---

## 2. Learning from user feedback on derivations (the Bingo line)

### 2.1 Bingo — very relevant
- **Citation.** M. Raghothaman, S. Kulkarni, K. Heo, M. Naik. *User-Guided Program Reasoning using Bayesian Inference.* PLDI 2018. https://www.cis.upenn.edu/~mhnaik/papers/pldi18a.pdf ; event page https://pldi18.sigplan.org/details/pldi-2018-papers/47/User-Guided-Program-Reasoning-using-Bayesian-Inference
- **Mechanism.** 
  1. Run a Datalog analysis and collect the **derivation graph**: every grounded rule instance (*clause*) linking body tuples to a head tuple.
  2. Treat each grounded rule instance as firing correctly with probability `p_r` (the rule's "trust"). Each tuple is the OR of its incoming clauses, and each clause is the AND of its body tuples plus its own Bernoulli. This turns the graph into a **Bayesian network**, after cycles from recursion are removed. Each alarm is a node in the network.
  3. Compute the marginal `P(alarm)` with **loopy belief propagation** [inference method from memory and secondary sources, not checked against the PDF].
  4. Show the user the highest-probability alarm. The user labels it true or false. Condition on that label (`evidence`) and recompute the posterior for all other alarms. A "false" label lowers the probability of shared intermediate tuples, so every alarm that depends on the same suspicious derivation drops. That is how one label **generalises** to many alarms.
- **Results.** Evaluated on a static datarace analysis (Java) and a static taint analysis (8 Android apps, 40–98 KLOC each). Users inspect **58.5% fewer alarms than a random ranker (Base-R)** and **44.2% fewer than Base-C** (a ranker based on alarm classification) before finding all true bugs. A user study with 21 Java programmers found that small amounts of incorrect feedback did not hurt ranking much (search-result extracts of the paper).
- **Limitations.** (a) It needs the full derivation graph, which can be large, plus cycle elimination. (b) Rule probabilities are hand-set or uniform in the base paper, so the model structure is fixed. BayeSmith shows that over-generalisation can **suppress real bugs**. (c) Feedback stays within one program and one run. It does not transfer across programs. (d) It assumes a single analysis, run as a batch.
- **Design implication for us.** This is the **core template for our data flywheel**:
  - Each LLM verdict or human triage label is evidence on an `alarm` node.
  - Propagation through shared derivation nodes means one confirmed FP (for example "this custom `escape()` is a real sanitiser") automatically lowers the confidence of every finding that flows through the same sanitiser, guard or config fact.
  - Concrete requirements for the engine:
    1. Emit **all** rule instances. A single proof is not enough.
    2. Give every rule a stable rule ID and a weight stored as data.
    3. Reach an inference backend (our own loopy BP, or exact ProbLog on small slices; §6.2).
  - Treat LLM verdicts as *noisy* evidence, for example a soft-evidence likelihood of 0.8 rather than a hard 0/1, because Bingo's robustness result covers only small amounts of wrong feedback.

### 2.2 Drake — differential (diff-aware) Bayesian ranking
- **Citation.** K. Heo, M. Raghothaman, X. Si, M. Naik. *Continuously Reasoning about Programs using Differential Bayesian Inference.* PLDI 2019 (Distinguished Paper). https://www.cis.upenn.edu/~mhnaik/papers/pldi19.pdf
- **Mechanism.** Builds a graph that captures the *difference* between alarm derivations on the old and new versions of a program, then runs Bayesian inference on it to rank alarms by how likely they are to relate to the change.
- **Results.** Using the Sparrow analyser on 10 C programs, it found all true bugs after inspecting about **30 alarms per benchmark** on average, versus 85 for batch-mode ranking and 118 for syntactic masking. Syntactic masking also missed 4 of the 26 bugs.
- **Design implication for us.** In PR/CI mode, rank by "new derivation" rather than by "new finding fingerprint". Semgrep's syntactic fingerprints are basically the masking baseline, and Drake shows that baseline misses real bugs. Key derivation nodes by content hashes, so we can diff derivation graphs across commits.

### 2.3 BayeSmith — learn the model structure and weights across programs
- **Citation.** H. Kim, M. Raghothaman, K. Heo. *Learning Probabilistic Models for Static Analysis Alarms.* ICSE 2022, pp. 1282–1293 (Best Artifact Award). https://prosys.kaist.ac.kr/publications/icse22.pdf ; artifact https://zenodo.org/records/6300874
- **Mechanism.** Starts from an initial model and training programs with bug labels, and **learns both the structure and the weights** of the Bayesian model, so knowledge transfers across programs. This targets Bingo's fixed structure and its over-generalisation from feedback.
- **Results.** On two static analyses over C programs, the learned models improved three existing probabilistic reasoning systems (abstract). I did not get the numbers.
- **Design implication for us.** This is the **cross-repo flywheel**. Triage labels from many repos train the per-rule weights (and possibly rule refinements) used as priors on a new repo. So rule weights must be **data in a table**, versioned and learned, not constants in rule text.

### 2.4 Abstraction selection and refinement for Bayesian program analysis
- **Citation.** Y. Zhang, Y. Shi, X. Zhang. *Learning Abstraction Selection for Bayesian Program Analysis.* OOPSLA 2024. https://2024.splashcon.org/details/splash-2024-oopsla/35/Learning-Abstraction-Selection-for-Bayesian-Program-Analysis ; Y. Shi, Y. Zhang, X. Zhang. *On Abstraction Refinement for Bayesian Program Analysis.* OOPSLA 2025, DOI 10.1145/3763166. https://2025.splashcon.org/details/OOPSLA/189/On-Abstraction-Refinement-for-Bayesian-Program-Analysis
- **Mechanism.** The Bayesian network's quality depends on which derivation nodes are merged (the abstraction). The 2024 paper learns that choice offline. The 2025 paper refines it on the fly, CEGAR-style, and uses conditional independence to *remove incorrect generalisations*. Evaluated on thread-escape and datarace analyses.
- **Design implication for us.** Over-generalisation is the main failure mode of feedback propagation: one FP label wrongly suppresses a true positive. Guardrails to build in from day one:
  - Never let propagation alone suppress a finding with high severity. Require LLM or human verification for that.
  - Keep node granularity at the level of program location × rule. Avoid nodes that are too coarse, such as a whole function.

---

## 3. Synthesising Datalog analysis rules from examples

### 3.1 ALPS
- **Citation.** X. Si, W. Lee, R. Zhang, A. Albarghouthi, P. Koutris, M. Naik. *Syntax-Guided Synthesis of Datalog Programs.* ESEC/FSE 2018. https://pages.cs.wisc.edu/~aws/papers/fse18b.pdf ; DOI 10.1145/3236024.3236034
- **Mechanism.** Programming by example. Given input relations and desired and undesired output tuples, it searches over rules built from **templates / meta-rules** (syntax guidance), exploiting the fact that practical Datalog rules share a few shapes.
- **Results.** Solved **33 of 34** benchmarks across knowledge discovery, program analysis and database queries. Metagol and Zaatar solved at most 10. The ProSynth paper reports ALPS timing out (1 h) on 6 tasks of its suite and averaging 142 s on the rest.
- **Design implication for us.** Template-guided search is a realistic way to *refine* rules from triage labels. Example: from FP examples, learn an extra body literal `not guarded(L, isalnum)` on an existing rule. Constrain the LLM to fill templates rather than write free-form rules.

### 3.2 Difflog
- **Citation.** X. Si, M. Raghothaman, K. Heo, M. Naik. *Synthesizing Datalog Programs using Numerical Relaxation.* IJCAI 2019, pp. 6117–6124. https://www.ijcai.org/proceedings/2019/847 ; arXiv 1906.00163
- **Mechanism.** Attach a real-valued weight to every candidate rule. Evaluate tuples with a max-product style semantics. Optimise the weights to match the labelled output (Newton root-finding plus simulated annealing, per a summary). Then round to a discrete program.
- **Results.** 34 benchmarks spanning knowledge discovery, formal verification and query-by-example, including recursive rules and invented predicates (abstract).
- **Design implication for us.** This is the bridge between "rules" and "weights": a candidate-rule pool with learned weights *is* the data-flywheel model. Rules whose weight goes to about 0 get pruned, and rules near 1 get promoted. Implement it as weight learning over our derivation graph (§6.3), not as a separate system.

### 3.3 ProSynth
- **Citation.** M. Raghothaman, J. Mendelson, D. Zhao, M. Naik, B. Scholz. *Provenance-Guided Synthesis of Datalog Programs.* POPL 2020. https://www.cis.upenn.edu/~mhnaik/papers/popl20.pdf
- **Mechanism.** CEGIS: a SAT solver picks a subset of candidate rules, Soufflé evaluates it, and **why / why-not provenance** of wrong or missing tuples becomes new SAT constraints.
- **Results.** 40 tasks from three domains, solved in **10 s on average per task**, an order of magnitude faster than baselines, and in under 1 s for 28 tasks (abstract).
- **Design implication for us.** Provenance is used here for *learning*, not only for explanation. When the LLM or a human says "FP", the why-provenance of that alarm names exactly which candidate rules or facts to blame. That is the signal to send to an LLM rule-repair step: "here is the proof tree; which link is wrong?". This is the strongest argument for making provenance a first-class requirement.

---

## 4. Semgrep internals relevant to us

### 4.1 Taint mode
- **Citation.** Semgrep docs: *Taint analysis overview* (https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview) and *Advanced taint techniques* (https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced). These pages could not be fetched from this session, so the content comes from search extracts plus the rule schema bundled with Semgrep 1.182.1, which I inspected locally.
- **Mechanism (checked against `rule_schema_v1.yaml` in 1.182.1).**
  - New-style syntax: `taint: {sources, sinks, propagators, sanitizers}`. `sources` and `sinks` are required.
  - Old style: `mode: taint` with `pattern-sources/-sinks/-sanitizers/-propagators`.
  - Sources take `label` and `requires`.
  - Sinks take `requires`, either a boolean label formula or a per-metavariable list.
  - Sanitizers take `not-conflicting`.
  - Propagators require `from` and `to` metavariables.
  - Other strings in the `semgrep-core` binary: `by-side-effect`, `exact`, `control`, `replace-labels`, and the options `taint_assume_safe_functions`, `taint_assume_safe_indexes`, `taint_assume_safe_booleans`, `taint_assume_safe_numbers`, `taint_assume_safe_comparisons`.
- **Semantics (from search extracts of the docs and release notes).**
  - `by-side-effect` defaults to **true for propagators**, unlike sources and sanitizers. A sanitizer with `by-side-effect: true` sanitises the l-value for later uses, and the docs advise `focus-metavariable`. A value `only` also exists [behaviour unverified].
  - `exact: true` on sanitizers stops sub-expressions from being sanitised too.
  - Taint labels are experimental. They support Python-style boolean `requires` (`A and not B`). A propagator without `requires` places no label requirement.
  - `taint_assume_safe_functions` treats calls as not passing taint from arguments to the return value. `taint_assume_safe_indexes` ignores a tainted index into a clean array. The docs recommend these for high-signal rules.
  - Taint is tracked **per variable, not per heap object**, and there is **no alias tracking**. Pro Java has basic getter/setter field sensitivity (March 2023 release notes).
  - Propagators are **intraprocedural only**.
- **Observed behaviour (my run, Semgrep 1.182.1 OSS, Python).** On:
  ```python
  def helper(x): return "ls " + x
  def view():  cmd = request.args.get("q"); c2 = helper(cmd); os.system(c2)
  def view2(): cmd = request.args.get("q")
               if cmd.isalnum(): os.system(cmd)
  ```
  Both sinks were reported:
  - The `view` flow is caught. Without `taint_assume_safe_functions`, OSS assumes an unknown call propagates taint from argument to return. That is a heuristic, not interprocedural analysis.
  - `view2` is a **false positive caused by a guard**. The `isalnum()` check is not understood.

  This is exactly the class of FP our logic layer should remove with `guard`/`validated` facts, and it is a good unit test for the POC.
- **Design implication for us.** Semgrep gives us *path-insensitive, alias-unaware, intraprocedural (OSS)* source→sink pairs. Our Datalog layer should add what is missing, using cheap extra facts:
  - guards and dominance (validation before the sink)
  - framework-level sanitisation (ORM parameterisation, autoescape on)
  - reachability from entry points (is the handler routed?)
  - type facts (an int-typed parameter cannot carry SQL injection)
  - known-safe wrappers

  Use labels to encode kinds (`USER_INPUT`, `PATH`, `SQL`). These map directly to the `Kind` argument in our relations.

### 4.2 Semgrep Pro interfile / interprocedural
- **Citation.** *Cross-file analysis taint traces* https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-data-flow ; *Pro engine examples* https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-examples ; blog *How We Cut Semgrep's Taint Analysis Time by 75%* (2026) https://semgrep.dev/blog/2026/how-we-cut-semgreps-taint-analysis-time-by-75-percent
- **Mechanism.** Three levels (checked in `semgrep scan --help`, 1.182.1):
  - `--pro-intrafile`: intra-file inter-procedural taint.
  - `--pro`: inter-file analysis, which rules opt into with `options: interfile: true`.
  - `--pro-path-sensitive`: path sensitivity, which implies intrafile.

  All three need the proprietary Pro engine. Per the blog, the 2023 design builds a naming environment that resolves cross-file calls, collects source/sink/propagator/sanitiser matches into a per-rule taint config, and computes **taint signatures** (function summaries). Pro Engine 1.158.0 shipped a redesign with up to 75% faster scans (P95 from 10 min to 7.5 min). The binary contains symbols such as `taint_effects` and `taint_call_trace`, consistent with summaries.
- **Limitations.** Proprietary, so it cannot be our base if we stay OSS. Inter-file analysis is supported only for a subset of languages.
- **Design implication for us.** With OSS Semgrep we must supply our own coarse **call graph** to stitch flows across functions. Practical approach:
  - Run Semgrep taint rules that treat *function parameters as sources* and *returns or calls as sinks*. This yields per-function summaries `param_flows_to_return(F, I)` and `param_flows_to_sink(F, I, Kind)`.
  - Compose those summaries in Datalog over `call(Caller, Callee, Site)` edges. This is a classic summary-based interprocedural analysis done in the logic layer.
  - Interface the engine so that, if a Pro licence is present, Pro findings simply arrive as more `flow` facts.

### 4.3 Output formats and `dataflow_trace`
- **Schema (checked in `semgrep_output_v1.py`, 1.182.1).**
  - `CliMatch{check_id, path, start, end, extra}`.
  - `extra.dataflow_trace: MatchDataflowTrace{taint_source: MatchCallTrace?, intermediate_vars: [MatchIntermediateVar{location, content}]?, taint_sink: MatchCallTrace?}`.
  - `MatchCallTrace = CliLoc(LocAndContent) | CliCall((LocAndContent, [MatchIntermediateVar], MatchCallTrace))`. This nested call case is how interprocedural ("deep", since 0.123.0) traces are shown.
  - Release notes: 0.109.0 dropped record-field auxiliary vars from traces, and 0.123.0 added deep traces, keeping only the shortest trace from each source.
- **Observed (important practical caveat).** With 1.182.1 OSS, not logged in:
  - `--json --dataflow-traces` returned results **without** `extra.dataflow_trace`.
  - `--sarif --dataflow-traces` returned no `codeFlows`.
  - The **text** output did print "Taint comes from / intermediate variables / how taint reaches the sink".

  The JSON formatter's source says filtering of fields "depending on context ctx" is implemented on the OCaml side. I infer, without confirming, that the trace is stripped unless you are logged in or in a certain context. SARIF fingerprints also said "requires login".
- **Design implication for us.** Do not assume `dataflow_trace` will be in JSON. Options, in order of preference:
  1. Check whether `semgrep login` (free account) restores it.
  2. Call Semgrep's Python internals and read `rule_match.match.extra.dataflow_trace` before formatting (it is populated, because the text formatter prints it).
  3. Parse text output (fragile).
  4. Reconstruct flows ourselves: run a second set of Semgrep rules that emit def-use facts.

  In any case, normalise traces into `flow_step(FindingId, I, Loc, Var)` facts.

---

## 5. Code Property Graph / Joern, and LLM + logic work (2023–2026)

### 5.1 Code Property Graph / Joern
- **Citation.** F. Yamaguchi, N. Golde, D. Arp, K. Rieck. *Modeling and Discovering Vulnerabilities with Code Property Graphs.* IEEE S&P 2014. https://mlsec.tu-berlin.de/docs/2014-ieeesp.pdf ; Joern: https://github.com/joernio/joern
- **Mechanism.** Merges the AST, CFG and PDG into one property graph. Vulnerability templates (buffer overflow, format string and other taint-style bugs) are written as graph traversals.
- **Results.** Found **18 previously unknown vulnerabilities in the Linux kernel** (abstract). A blog says 88 known vulnerabilities were covered by the traversals [secondary source].
- **Current Joern (checked on GitHub).** Apache-2.0. Frontends for C/C++, Java, JS, Python, Kotlin and binaries. Scala-based query DSL. Requires JDK 21. Has a server mode and `joern-export`. The README mentions no Python client.
- **Limitations.** Heavy JVM dependency. Python front-end precision is unclear [unverified]. Taint is limited to "taint-style" bugs and needs sinks as input.
- **Design implication for us.** The CPG is the *richer fact source* option. If Semgrep facts are not enough (for example for dominance or guards), we could export CFG/PDG edges from Joern as Datalog facts (`cfg_edge`, `reaching_def`). For a Python POC, start with Python's own `ast` module plus a small CFG builder for guards and dominance. That is cheaper than running a JVM. Keep a `cfg_edge/dominates` relation interface so Joern can back it later.

### 5.2 IRIS (LLM-inferred specs + CodeQL)
- **Citation.** Z. Li, S. Dutta, M. Naik. *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities.* ICLR 2025. https://proceedings.iclr.cc/paper_files/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html ; code https://github.com/iris-sast/iris
- **Mechanism.** An LLM labels candidate external APIs as sources and sinks per CWE. These become CodeQL taint specs. CodeQL computes paths, and the LLM then does *contextual analysis* of each path to filter FPs.
- **Results.** On CWE-Bench-Java (120 validated vulnerabilities): CodeQL finds **27**, IRIS + GPT-4 finds **55**, with a 5-point improvement in average false discovery rate, plus 4 new vulnerabilities (ICLR version; arXiv v1 reported 69 and v2 reported 6 new). The README now lists 213 CVEs across 49 CWEs.
- **Design implication for us.** This is our architecture with CodeQL in place of Semgrep and Datalog. Our addition is the *learning loop*: IRIS does not feed verdicts back into specs or rules. Covered in depth in doc 01/02.

### 5.3 LLM-written analysis queries: QLPro, QLCoder, CQLLM, Vulnhalla
- **QLPro** (arXiv 2506.23644, 2025): extracts taint specs with CodeQL, classifies them by LLM triple-voting, and generates project-specific QL with Writer/Repair/Execute roles. https://arxiv.org/html/2506.23644v3
- **QLCoder** (arXiv 2511.08462): an agent on Claude Code synthesises CodeQL queries from CVE metadata. On CWE-Bench-Java it reports 100% compilation, 53.4% success and F1 0.7, versus 0.073 for CodeQL alone (abstract). https://arxiv.org/html/2511.08462v4
- **CQLLM** (MDPI Applied Sciences 16:517) targets syntactically wrong queries and hallucinated modules. **Vulnhalla** (CyberArk, Dec 2025) is LLM triage on top of CodeQL.
- **Design implication for us.** LLMs can write analysis rules, but only inside a **compile → run on examples → repair** loop. LLM-written Datalog needs the same harness:
  - parse and safety check (range restriction, stratification)
  - run on positive and negative fixtures
  - a measured diff in alarms on a held-out corpus before promotion

### 5.4 LLM + Datalog (2024–2026) — thinner coverage, search budget exhausted
- **NeuroLog: Reasoning You Can Audit — Neuro-Symbolic Vulnerability Discovery via LLM Facts, Datalog, and SMT** (arXiv 2606.00669, 2026). The LLM sits *below* the rules: it fills in facts, and a small Soufflé rule base of about 30 rules plus SMT does the reasoning. https://arxiv.org/html/2606.00669 [only the abstract-level description was verified]
- **NESA: Relational Neuro-Symbolic Static Program Analysis** (arXiv 2412.14399). Datalog-style relational rules whose primitive relations are answered by LLM prompts ("compilation-free, customisable"), with lazy and incremental prompting against hallucination. https://arxiv.org/pdf/2412.14399 [I believe this is by the LLMDFA/LLMSA authors, C. Wang et al.; unverified]
- **LogicLoc: Neurosymbolic Repo-level Code Localization** (arXiv 2604.16021, 2026). An LLM translates questions into Soufflé Datalog over extracted code facts, with parser-gated validation and mutation-based diagnostics. It notes that LLMs often invert argument order in Soufflé's `contains`. https://arxiv.org/html/2604.16021v2
- **Design implication for us.** The literature is converging on two patterns:
  1. **The LLM supplies facts** (source/sink/sanitiser/guard semantics of unknown APIs) and Datalog reasons. NeuroLog, NESA, IRIS.
  2. **The LLM supplies rules** under validation. LogicLoc, QLPro/QLCoder.

  We should do both, but with strict typing:
  - LLM-supplied facts carry a confidence and a provenance tag (`by_llm(model, prompt_hash)`).
  - LLM-supplied rules are drafts until validated.
  - LogicLoc's argument-order observation argues for **named, typed relation signatures**, plus a schema checker that rejects ill-typed atoms.

---

## 6. Probabilistic and differentiable logic, and Python engine availability

### 6.0 Scallop
- **Citation.** Z. Li, J. Huang, M. Naik. *Scallop: A Language for Neurosymbolic Programming.* PLDI 2023, PACMPL 7, Article 166, DOI 10.1145/3591280. arXiv 2304.04812. Repo https://github.com/scallop-lang/scallop ; artifact https://zenodo.org/records/7830130
- **Mechanism.** Datalog (recursion, stratified negation, aggregation) with a generalised **provenance semiring** framework:
  - discrete (unit), `minmaxprob`
  - probabilistic top-k proofs
  - differentiable variants (`difftopkproofs`) that integrate with PyTorch

  The Python binding `scallopy` exposes a `ScallopContext` and foreign functions and predicates.
- **Results.** On eight neurosymbolic applications, accuracy is comparable to or better than state-of-the-art models, with advantages in runtime, data efficiency, interpretability and generalisation (abstract).
- **Availability (checked).** PyPI `scallopy` has a single release, **0.1.0 (2021-12-27), with only a macOS arm64 / CPython 3.9 wheel**. Neither `pip download` nor `pip index` finds a usable distribution for Linux and Python 3.13. The README says to build from source with **Rust nightly** + maturin (`make install-scallopy`), on Python 3.8 in the documented setup. This box has only stable Rust 1.97, so I did not install a nightly toolchain, because that would be a persistent system change. The GitHub page shows no releases (MIT licence).
- **Design implication for us.** Conceptually Scallop is the **ideal** engine for us: top-k-proof provenance gives explanations *and* probabilities in one evaluation, and differentiable semirings let us learn rule weights from labels (Difflog-style) end to end. Practically, it is a build-from-source, nightly-Rust, low-release-cadence dependency, which is a poor base for a POC. **Recommendation:** keep the rule dialect and weight tables Scallop-compatible, and consider Scallop for the "learn rule weights" stage later, in its own container.

### 6.1 Python package availability (checked 2026-10-24, Python 3.13, x86_64, Ubuntu 24.04)

| Package | PyPI status | Notes |
|---|---|---|
| `clingo` | 5.8.2 (2026-08-14), manylinux wheel, downloaded OK | ASP/Datalog grounder+solver, actively maintained (Potassco). Installed 5.8.0 in the venv |
| `problog` | 2.3.0 (2026-09-09), wheel, downloaded OK | Exact inference via knowledge compilation; evidence/conditioning; `lfi` parameter learning (EM) |
| `pyDatalog` | 0.22.4 (2026-06-13), cp313 wheel | Pure Python plus a C extension; slow (§6.2) |
| `pyswip` | 0.3.3 (2025-06-23), wheel | Needs a system SWI-Prolog. **apt: `swi-prolog-nox` 9.0.4 available** on Ubuntu 24.04 |
| `janus-swi` | 1.5.3 sdist | **Build failed** without SWI-Prolog dev install. Needs swipl present; version requirement vs 9.0.4 unknown [unverified] |
| `scallopy` | 0.1.0 macOS-arm64-cp39 only | Not installable here; build from source with Rust nightly |
| `souffle` (PyPI) | 0.1 | **Unrelated package**, and its metadata build fails. Soufflé itself: GitHub release 2.5 lists Ubuntu 22/24 packages; **not in apt** |
| `egglog` | 14.0.0 (2026-09-20), wheel | E-graphs + Datalog (Rust core); interesting but not designed for provenance |
| `xclingo` | 2.0b24 installed | Explanation layer for clingo. I could not get the trace-annotation syntax right in a quick try; untested |
| `datalog` (PyPI) | unrelated (PicoLog ADC hardware) | — |
| `ddlog` | none | DDlog archived; no Python bindings |
| CodeQL | CLI only, licence-restricted | Not embeddable |

### 6.2 Hands-on micro-experiments (scratch venv, one core)
1. **Bingo-style conditioning in ProbLog works out of the box.** Graph: sources n1 and n5, n1→n2→n3, n5→n3, n3→n4 (sink) and n3→n6 (sink). The rules had probabilities 0.9 and 0.95 (`0.9::flows(X,Y) :- source(X), edge(X,Y).`). Prior: P(alarm@n4) = P(alarm@n6) = 0.973. After `evidence(a4,false)` (the user marks the n4 alarm as FP), **P(alarm@n6) drops to 0.447**, because both alarms share the derivation through n3. ProbLog attaches the Bernoulli choice to each *grounded rule instance*, which matches Bingo's model.
2. **Exact ProbLog does not scale to whole-program graphs.** On random DAG-like flow graphs (one source, about 30% extra cross edges, 10 sinks, one evidence atom):

   | Nodes | ProbLog time |
   |---|---|
   | 20 | 0.1 s |
   | 40 | 0.13 s |
   | 80 | 0.28 s |
   | **200** | **146 s** |
   | 400 | timeout (>180 s) |

   The blow-up comes from knowledge compilation over many overlapping proofs. ⇒ Use ProbLog only for **small slices** (one finding's neighbourhood). Otherwise use loopy BP as Bingo does, or bounded top-k proofs as Scallop does.
3. **Plain Datalog evaluation is not a bottleneck at POC scale.** Multi-source reachability: 3,000 nodes and 60 sources gave 1,830 alarm tuples. **clingo 0.07 s** solve time versus **pyDatalog 1.2 s**. For one source over 20k nodes: clingo about 0.09 s, pyDatalog about 1.25 s. Soufflé was not tested, because it is not installable from apt.

### 6.3 Prolog vs Datalog (vs ASP) — critical comparison for our use

| Criterion | Datalog (Soufflé / clingo-as-Datalog / custom) | Prolog (SWI + tabling) | ProbLog | Scallop |
|---|---|---|---|---|
| Termination on any rule set | **Guaranteed** (finite domain, no function symbols) | Not guaranteed. Needs `:- table` and discipline; LLM-written rules can loop | Guaranteed for Datalog-shaped programs; tabled | Guaranteed (Datalog) |
| Order independence (safe for LLM/learned rules) | **Yes** (set semantics) | No (clause/goal order, cuts) | Mostly | Yes |
| Proof trees for explanations | Soufflé: minimal-height proof built in; clingo/custom: through rule instrumentation | **Trivial** with a meta-interpreter | `explain` mode; proofs available | **Native** (top-k proofs) |
| All derivations (Bingo graph) | Instrumentation (`fire_r(...)` heads); one extra rule per rule | Meta-interpreter with tabling (complex) | Implicit in the compiled circuit, but costly | Top-k only (bounded) |
| Probabilities / conditioning | External (our BP) | External | **Native**, exact, slow at scale | Native, approximate (top-k), differentiable |
| Weight learning | External | External | `lfi` (EM) | Gradient-based (PyTorch) |
| Incremental | Soufflé no; clingo multi-shot (`#external`, program parts) | `assert/retract` + incremental tabling (SWI) | No | No [unverified] |
| Python embedding | clingo: excellent (pip wheel, Python API); Soufflé: subprocess; custom: native | pyswip/janus + apt swipl | Pure Python pip | Build from source |
| Scale | Soufflé best; clingo fine to about 10^6 ground atoms [unverified]; custom pure Python worst | Good with tabling | Poor (exact) | Good for discrete; probabilistic depends on k |

**Verdict.** Datalog semantics (stratified, set-based, terminating) is the right *contract* for a rule base that LLMs and learning algorithms will edit. Prolog's main advantage, easy meta-interpreted proofs, can be replicated in Datalog by rule instrumentation, and Prolog's order sensitivity and non-termination are liabilities for machine-written rules. ProbLog is the right *semantics* for Bingo-style feedback but the wrong *engine* at scale. Scallop is the right *idea* but the wrong *dependency* for now.

---

## 7. Recommendation for the Python POC

### 7.1 Engine choice
**Primary:** **clingo (pip `clingo`) used strictly as a stratified Datalog engine, behind our own thin "rule IR".** Provenance is recorded by automatic rule instrumentation. Bingo-style inference runs in Python over the instrumented derivation graph.

Why:
1. It is a pip wheel, actively maintained, with a mature Python API (facts can be added programmatically, and models are read back as Python symbols). It was by far the fastest of the embeddable options measured (§6.2).
2. It has stratified negation and aggregates (`#count`, `#max`), which cover guards, "no sanitiser on path" and counting.
3. **Multi-shot solving** (`#external` atoms, program parts) gives cheap "what-if" re-evaluation: toggle a suspected-sanitiser fact and see which alarms disappear. This is ideal for the agent's counterfactual questions ("if `escape()` is a sanitiser, which findings go away?").
4. If we later want *abductive* explanations ("which minimal set of facts would make this a false positive?"), ASP choice rules are available. That is beyond what Datalog engines offer.

Constraints we impose so that we can **port to Soufflé or Scallop later**:
- No choice rules, disjunction or weak constraints in the *analysis* rule base. Allow them only in separately tagged "abduction" programs.
- Typed relation signatures declared in the IR, as Soufflé `.decl` does. Generate both clingo text and Soufflé `.dl` from the IR.
- Every rule has a stable `rule_id`, and its weight lives in a table (`rule_weight(RuleId, P)`), never in the rule text.

**Provenance by instrumentation (how).** For each rule `r: H :- B1, …, Bn, not N1, …`, the IR compiler also emits `fire(r, tuple(H), tuple(B1), …, tuple(Bn)) :- B1, …, Bn, not N1, …`. (In clingo this is a function-term atom. In Soufflé, use an ADT or a per-rule `fire_r(...)` relation.) This yields **every grounded rule instance**, which is the full Bingo hypergraph, not just one minimal proof. Minimal-height explanations for the LLM or a human come from a BFS over this graph, which reproduces Soufflé's minimal-height proof trees cheaply. Negated body atoms are recorded as `absent(N)` premises, so an explanation can say "no sanitizer matched on this path". Cost: the number of `fire` atoms equals the number of rule instances. That is fine at per-repo POC scale. For large transitive closures, restrict instrumentation to the "decision" strata (the alarm and verdict layers), and summarise `flows*` closure edges as single steps.

**Bayesian layer (Python).** Build a factor graph from `fire` atoms:
- Each clause node is AND(body) ∧ Bernoulli(`rule_weight`).
- Each tuple node is a noisy-OR of its clauses.
- Each base fact gets a prior: 1.0 for Semgrep structural facts, and the LLM confidence for LLM-asserted facts.

Then:
1. Break cycles as Bingo does, for example by keeping only edges that respect the derivation order or proof height.
2. Run **loopy belief propagation**, either hand-rolled (a few hundred lines with numpy) or with `pgmpy`.
3. Add LLM and human verdicts as (soft) evidence on alarm nodes, and recompute.
4. For high-stakes single findings, cross-check with **exact ProbLog on the finding's k-hop slice**. The slice is small, which §6.2 shows is fast.

**Learning (the flywheel).**
- *Weights:* EM over labelled alarms (ProbLog-`lfi`-style or BP-based), giving per-`rule_id` weights, pooled across repos with per-repo deviations (BayeSmith direction). The guardrail from §2.4 applies: propagation can only *downrank*, and suppression of high-severity findings requires direct verification.
- *Rules:* the LLM proposes rule edits only as **template fills** (ALPS-style meta-rules such as "add negative guard literal", "add sanitiser fact", "specialise source kind"). It is given the why-provenance of the misclassified alarms (ProSynth-style blame). Every proposal passes:
  1. parse plus type check against the relation signatures
  2. safety (range restriction) and stratification check
  3. regression on fixture suites
  4. the alarm delta on the labelled corpus

  Only then is it promoted. Promoted rules and facts are rows in a DB (`rule(id, text, version, author={human|llm:model}, status)`), not code.

**Fallbacks and alternatives considered.**
- *Soufflé via subprocess:* the scale-up path. Not first, because it has no Python bindings, is not in apt, and needs a compile step. Use it when facts exceed what clingo grounds comfortably.
- *SWI-Prolog (apt 9.0.4 + pyswip):* rejected as the core. Non-termination and order sensitivity are bad for LLM-edited rules, and it adds a system dependency. Possibly useful for ad-hoc meta-reasoning.
- *ProbLog:* keep as an **oracle for slices** and for prototyping the Bayesian model, not as the main engine (scaling cliff at about 200 nodes in our test).
- *Scallop:* revisit for differentiable weight learning once the schema is stable. Requires a nightly Rust build.
- *Custom pure-Python semi-naive engine:* a viable alternative if clingo grounding or instrumentation becomes awkward. It takes about 300–500 lines with native provenance, but is 10–20x slower than clingo (pyDatalog as a proxy).
- *DDlog:* rejected (archived). *CodeQL:* licence and embedding issues. Keep its vocabulary.

### 7.2 Schema sketch

Conventions:
- `Loc` = `"path:line:col"` or an interned ID.
- `F` = finding ID (Semgrep fingerprint plus rule plus location).
- `Fn` = fully qualified function name.
- `Kind` = vulnerability or taint label (`sqli`, `cmdi`, `path`, `xss`, `ssrf`, `deser`…).
- `Src` = provenance tag of a fact (`semgrep:<rule>`, `ast`, `llm:<model>:<hash>`, `human:<user>`).
- Every base fact also has a `fact_conf(FactId, P, Src)` row.

**Base relations (EDB)**

From Semgrep taint findings and `dataflow_trace`:
```
finding(F, RuleId, Kind, SinkLoc, Severity)
finding_source(F, SrcLoc, SrcKind)          % taint_source
flow_step(F, I, Loc, Var)                   % intermediate_vars, ordered
finding_in_fn(F, Fn)
```
Spec facts (from Semgrep rule YAML, curated libraries, and LLM-inferred specs à la IRIS):
```
source(Loc, Kind)              source_api(ApiName, Kind)
sink(Loc, Kind)                sink_api(ApiName, ArgIdx, Kind)
sanitizer(Loc, Kind)           sanitizer_api(ApiName, Kind)      % Kind-specific!
propagator_api(ApiName, FromArg, ToArg)
```
Program structure (from Python `ast` and a lightweight CFG; Joern later):
```
func(Fn, File)                      call(CallSite, CallerFn, CalleeName)
resolves(CallSite, CalleeFn)        % best-effort name resolution
param(Fn, Idx, Var)                 returns_var(Fn, Var)
entrypoint(Fn, How)                 % route decorator, CLI main, celery task, ...
guard(Loc, Var, Pred)               % if-test at Loc on Var, Pred ∈ {isalnum, isdigit, in_allowlist, re_fullmatch, isinstance_int, len_lt, ...}
dominates(GuardLoc, SinkLoc)        % guard's true-branch dominates sink
type_of(Var, Fn, Type)              % from annotations / inference (int, bool, UUID...)
config(Key, Value)                  % e.g. jinja autoescape=True, DEBUG
in_test_code(File)                  generated_code(File)
```
Interprocedural summaries (from parameter-as-source Semgrep rules):
```
summ_param_to_ret(Fn, Idx)          summ_param_to_sink(Fn, Idx, Kind, SinkLoc)
summ_sanitizes(Fn, Idx, Kind)
```
Feedback (written by the agent or UI; these act as evidence, not inputs to the rules):
```
verdict(F, Label, Who, Conf)        % Label ∈ {tp, fp, unsure}; Who ∈ {llm:model, human:user}
fp_reason(F, ReasonCode, Loc)       % structured reason → candidate fact/rule edits
```
Learned and meta data:
```
rule_weight(RuleId, P)              rule_meta(RuleId, Version, Author, Status)
```

**Derived relations (IDB), sketch.**
```
% kind-aware sanitisation (a sanitizer for xss does not sanitise sqli)
sanitized(F) :- finding(F,_,K,_,_), flow_step(F,_,L,_), sanitizer(L,K).

% guard-based validation (fixes the view2 isalnum FP)
safe_pred(isalnum, K) :- kind(K), K != path_traversal_dotdot.   % per-kind table, curated/learned
validated(F) :- finding(F,_,K,S,_), flow_step(F,_,_,V), guard(G,V,P), dominates(G,S), safe_pred(P,K).

% type-based impossibility
type_safe(F) :- finding(F,_,K,_,_), flow_step(F,_,_,V), finding_in_fn(F,Fn), type_of(V,Fn,T), safe_type(T,K).

% reachability from an entry point (call graph closure)
reach(Fn) :- entrypoint(Fn,_).
reach(G)  :- reach(Fn), call(C,Fn,_), resolves(C,G).
unreachable(F) :- finding_in_fn(F,Fn), not reach(Fn), not public_api(Fn).

% interprocedural stitching with summaries (beyond OSS Semgrep)
tainted_arg(Fn,I,K) :- call(C,Caller,_), resolves(C,Fn), arg_tainted(C,I,K).
inter_flow(Fn,K,S)  :- tainted_arg(Fn,I,K), summ_param_to_sink(Fn,I,K,S), not summ_sanitizes(Fn,I,K).

% decision layer (instrumented for provenance + Bingo)
mitigated(F) :- sanitized(F).
mitigated(F) :- validated(F).
mitigated(F) :- type_safe(F).
mitigated(F) :- config_mitigates(F).
alarm(F)     :- finding(F,_,_,_,_), not mitigated(F), not in_test(F).
alarm(F)     :- inter_flow_finding(F).            % new findings from stitching
suppressed(F, Why) :- finding(F,_,_,_,_), mitigated_by(F, Why).   % kept for audit, never silently dropped
needs_llm(F) :- alarm(F), severity(F,S), S >= medium, not verified(F).
```
Each of these rules gets a `rule_id` and an instrumented `fire(...)` twin. The probability of `alarm(F)` and the posterior after `verdict` evidence come from the Python BP layer. The agent receives `alarm(F)` plus its minimal proof tree (BFS over `fire`) as structured context. Its `fp_reason` output maps to candidate edits, for example a new `sanitizer_api` fact, a new `safe_pred` row, or a new template-filled rule. These edits are validated as in §7.1.

### 7.3 Critical risks and open questions
1. **Fact quality dominates.** The Datalog layer can only remove FPs whose reasons it can *see*. Guards, types and config need a Python AST/CFG extractor that we build ourselves. Budget for it; it is the real work.
2. **Missing `dataflow_trace` in OSS JSON (observed).** Resolve this first (§4.3), because the trace is our main fact source for `flow_step`.
3. **Over-generalisation from feedback** (BayeSmith, the OOPSLA'24/'25 papers). Propagation must only rerank. Suppression needs direct evidence. Track the per-rule calibration of LLM verdicts against human labels.
4. **LLM-asserted facts are a poisoning surface.** A wrong `sanitizer_api` fact silently suppresses a class of TPs. Require a confidence, provenance and an expiry for LLM facts. Human-confirmed facts outrank them.
5. **Derivation-graph size.** Instrumenting recursive closures can explode. Instrument the decision strata fully and summarise closures.
6. **Unverified items** that a follow-up pass should check against the full PDFs and docs:
   - Bingo's exact inference algorithm, its cycle handling, and its per-benchmark numbers
   - Soufflé provenance CLI flags
   - Semgrep `by-side-effect: only` semantics, and whether `semgrep login` restores `dataflow_trace` in JSON
   - NeuroLog/NESA specifics and results
   - janus-swi minimum SWI version
