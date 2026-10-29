# HANDOVER — Sentinel (neurosymbolic SAST), state as of 2026-10-29

Repo `mdguerreiro/novalang`, branch `claude/neurosymbolic-sast`, everything under `sast/`. Last commit before this
file: `bd73e53`. Read this first, then `docs/STATUS.md` (running status) and `docs/evaluation.md` (all measurements;
the newest section is "Confidence: precision audits, a second held-out split, and engine-guided review").

## What the user asked for

"Keep working until we are confident that the engine works well." The user wants honest results on code the engine
has never seen, generalizable fixes (no overfitting to CVEs), low cost, and every step committed and pushed.
Conventions: commit trailers `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and the session link; no
model ids in commit messages; no PR unless asked; never commit API keys (`git grep sk-ant-` before every commit).

## What exists

- **Engine** (no model, deterministic): Python fact extractor (`sentinel/extract/python_facts.py`), Semgrep spec
  matching (`specs/python-web.yml`, `sentinel/extract/semgrep_specs.py`), Datalog taint rules
  (`sentinel/engine/rules/taint.lp`, run on Soufflé, or clingo for small inputs), findings + witness paths
  (`sentinel/engine/analyze.py`). Curated pack: `knowledge/packs/python-web-frameworks.yml`.
- **Model tiers** (`sentinel/agent/claude.py`, default model `claude-opus-5-5`, override `SENTINEL_MODEL`): frontier
  oracle (labels unknown APIs/entry points), verifier, rule synthesis, handler reads, and the newest one:
- **Engine-guided review** (`sentinel/review.py`, opt-in `SENTINEL_REVIEW=1`; reader in `sentinel/agent/reader.py`):
  the engine ranks the attack surface, the model reads the top N functions (+ project callees) per repo, cached by a
  hash of the exact code; issues go to the review lane; API-level answers are proposed as gated knowledge
  (`sink_api`, `not_sanitizer`). Budget: `SENTINEL_REVIEW_BUDGET=30` or `auto` (5% of ranked surface, 30..100).
  `SENTINEL_REVIEW_SELECT=naive` = keyword-grep ranking (ablation only).
- Tests: `.venv/bin/python -m pytest -q` from `sast/` (≈195 tests, ~7 min). One Playwright e2e test
  (`tests/e2e/test_triage_flow.py`) times out under heavy CPU load; it passes on an idle machine.

## Results so far (details and caveats in docs/evaluation.md)

| | unseen CVEs | caught | fix tree clean | cost |
|---|---|---|---|---|
| Engine alone, splits rw3+rw4 | 27 | 4 | 3 | $0 |
| Engine + guided review (ranking v2, 30 reads) | 27 | 7 | 5 | $9.38 for 54 trees |
| Same, keyword-grep ranking (ablation) | 27 | 5 | 4 | $11.97 |
| Engine alone, fresh split rw5 | 24 | 5 | 2 | $0 |

Precision (labelled random samples): engine findings FP 87% -> 53% after the audit-driven fixes; guided-review
findings TP 29% / WEAK 54% / FP 17%. Why the engine misses: in 18 of 21 classified held-out misses there is no
source-to-sink flow of the CVE's class (mostly no matching sink in the vulnerable function: framework internals,
bypassable validators). Main limit of the review: the vulnerable function is not among the reads in big repos
(read in 8/27 with 30 reads; Django/litellm have 10-28k functions).

## Where we left off (do this next)

1. **Blocked on API credit.** The rw5 review comparison (budget 30 vs `auto`, engine frozen at `57010db`) stopped
   because the Anthropic account ran out of credit (400 "credit balance too low"). The user was asked to top up or
   provide a new key (the old one was shared in chat: they should revoke it). Cap agreed: ~$40 for this comparison.
   Total live spend so far: $16.89 (early live runs) + $34.48 (confidence evaluation).
   To run: see `bench/realworld/scripts/run_review.py` (usage in its docstring); run budget 30 first, then `auto`
   with the 30-run's cache copied in (the top-30 reads are reused, only extra reads cost).
2. After that: write the rw5 review results into docs/evaluation.md (section "A third, fresh held-out split") and
   STATUS.md; report honestly, including the ablation and false alarms on fixed trees.
3. Next engine work the evidence points to: (a) reach on large repos (budget/ranking); (b) hide or demote
   operator-input findings (CLI/config) in what users see; (c) feed the review's proposed facts through the gate so
   the engine catches those patterns itself; (d) a bigger fresh held-out set (50-100 CVEs), repeated runs, and a
   human-labelled subset to check the model labellers.

## Evaluation protocol (keep it)

- Dev split = `bench/realworld/cases/dev_rw2.json` (16 PySASTBench CVEs): the only split you may read code from and
  tune on. Held-out = `heldout_rw3.json` (12), `heldout_rw4.json` (15), `heldout_rw5.json` (24): never read their code
  while developing; reading for grading after a run is fine (disclose it). Build any new split before testing a
  change on it, and freeze it.
- "Caught" = a finding of the CVE's class (template injection counts as code) in a target function (module- or
  class-qualified match); "fix clean" = the fixed tree is not flagged. Precision = labelled random samples
  (TP/WEAK/FP rubric in docs/evaluation.md).

## Files under bench/realworld/ (copied from the session scratchpad, which is not persisted)

- `cases/`: case lists. Their `trees` paths point to the old scratchpad; rebuild trees by cloning the projects and
  `git archive` of the `vul`/`fix` revisions recorded per case (`scripts/mine_rw4.py`, `mine_rw5.py`,
  `clone_rw5.sh`, `build_rw3.py` show how; set the path variable `S` at the top of each script).
- `scripts/`: `run_engine.py` (engine-only scorer), `run_review.py` (review runs; meters spend via
  `frontier_live.py`, stops at `REVIEW_CAP`), `missdiag.py` (why misses happen, engine output only), `rankpos.py`
  (target position in the ranking), `summary.py`, `audit_dump.py`, `mdtable.py`. All hard-code the old scratchpad
  path in `S`: change it. The API key was read from a file outside the repo (`$S/.akey`); never commit a key.
- `results/`: engine-only and review JSONs per run (`results/review/*.cache.json` are the model's answers per read:
  copy one next to a new run's output as `<out>.cache.json` to reuse them), `missdiag_v6.json`, labels.
- `audit/`: precision-audit samples and labels.

Useful commits: `1f93c22` review tier, `97faa56` ranking v2, `d0a2504` auto budget, `faffe63` billing errors stop the
scan, `57010db` source decoding fix, `f89a73d`/`a23658a` performance on 2M-node graphs, `b4c6d5e`/`b0e76b7`
precision fixes.
