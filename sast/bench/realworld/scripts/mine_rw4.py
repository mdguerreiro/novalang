"""Held-out split 3 (built 2026-10-27 before any further engine change; its code is not read during development).
CVE fix commits mined from the projects' own git history: a non-merge commit whose message names a CVE id and a
vulnerability class (keyword match). vul tree = parent, fix tree = commit, targets = non-test functions the commit
changes (1..6 of them). Seeded order, at most 3 cases per repository, round-robin over classes; CVEs used in
splits 1 and 2 are excluded. Class labels come from commit-message keywords (noisy; disclosed)."""
import ast, json, random, re, subprocess, sys
from pathlib import Path

S = Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad")
OUT = S / "rw4"
REPOS = S / "rw2" / "repos"
SKIP = {"pytorch__pytorch", "odoo__odoo"}  # too large to scan repeatedly
SEED, N, PER_REPO = 20261027, int(sys.argv[1]) if len(sys.argv) > 1 else 36, 3
CLASS_RE = [  # first match wins
    ("deser", r"pickl|deserializ|unsafe (yaml|load)|yaml\.load|marshal|torch\.load|joblib"),
    ("sqli", r"sql injection|\bsqli\b|sql-injection|injection in .*(query|sql)"),
    ("cmdi", r"command injection|shell injection|os\.system|subprocess|argument injection|\brce\b.*(command|shell)"),
    ("code", r"code (injection|execution)|template injection|\bssti\b|\beval\b|\bexec\b|sandbox (escape|bypass)|arbitrary code"),
    ("path", r"path traversal|directory traversal|traversal|zip ?slip|tar ?slip|arbitrary file (read|write|overwrite|deletion)"),
    ("xss", r"\bxss\b|cross[- ]site scripting|html injection|escap(e|ing) .*(html|output)"),
    ("ssrf", r"\bssrf\b|server[- ]side request forgery"),
    ("redirect", r"open redirect"),
]
used = set()
for f in (S / "rw2" / "cases.json", S / "rw3" / "heldout.json"):
    used |= {re.search(r"CVE-\d{4}-\d+", c["cve"]).group(0) for c in json.load(open(f))["cases"]}


def git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, timeout=600)


def is_test(p):
    return bool(re.search(r"(^|/)(tests?|testing|test_utils)/|(^|/)test_[^/]*\.py$|_tests?\.py$|conftest\.py$", p))


def funcs(src):
    """[(qualname, start, end)] for every function, nested ones qualified by their parents."""
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return []
    out = []

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                q = f"{prefix}.{ch.name}" if prefix else ch.name
                if not isinstance(ch, ast.ClassDef):
                    out.append((q, ch.lineno, ch.end_lineno or ch.lineno))
                walk(ch, q)
    walk(tree, "")
    return out


def innermost(fs, line):
    hit = [f for f in fs if f[1] <= line <= f[2]]
    return max(hit, key=lambda f: f[1])[0] if hit else None


def changed_targets(repo, h):
    diff = git(repo, "diff", "-U0", f"{h}^", h, "--", "*.py").stdout
    targets, cur = set(), None
    for ln in diff.splitlines():
        if ln.startswith("diff --git"):
            m = re.match(r"diff --git a/(\S+) b/(\S+)", ln)
            cur = m.group(1) if m else None
            if cur and is_test(cur):
                cur = None
            old_src = git(repo, "show", f"{h}^:{cur}").stdout if cur else ""
            new_src = git(repo, "show", f"{h}:{cur}").stdout if cur else ""
            old_fs, new_fs = funcs(old_src), funcs(new_src)
            old_names = {q for q, _, _ in old_fs}
        elif cur and ln.startswith("@@"):
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", ln)
            a, ac, b, bc = int(m.group(1)), int(m.group(2) or 1), int(m.group(3)), int(m.group(4) or 1)
            for line in range(a, a + max(ac, 1)):
                q = innermost(old_fs, line)
                if q:
                    targets.add(f"{cur}:{q}")
            for line in range(b, b + max(bc, 1)):
                q = innermost(new_fs, line)
                if q and q in old_names:
                    targets.add(f"{cur}:{q}")
    return sorted(targets)


cands = []
for repo in sorted(p for p in REPOS.iterdir() if p.is_dir() and p.name not in SKIP):
    log = git(repo, "log", "--all", "--no-merges", "-i", "-E", "--grep", r"CVE-[0-9]{4}-[0-9]+", "--format=%H%x09%s%x09%b%x1e").stdout
    seen = set()
    for rec in log.split("\x1e"):
        parts = rec.strip().split("\t", 2)
        if len(parts) < 2:
            continue
        h, msg = parts[0], " ".join(parts[1:])
        cves = re.findall(r"CVE-\d{4}-\d+", msg, re.I)
        if not cves:
            continue
        cve = cves[0].upper()
        if cve in used or cve in seen:
            continue
        cls = next((c for c, rx in CLASS_RE if re.search(rx, msg, re.I)), None)
        if not cls:
            continue
        seen.add(cve)
        cands.append({"repo": repo.name, "cve": cve, "cls": cls, "fix": h, "msg": msg[:200]})
print("candidates", len(cands), file=sys.stderr)

rng = random.Random(SEED)
rng.shuffle(cands)
by = {}
for c in cands:
    by.setdefault(c["cls"], []).append(c)
cases, per_repo, log = [], {}, []
while len(cases) < N and any(by.values()):
    for cls in sorted(by):
        if not by[cls] or len(cases) >= N:
            continue
        c = by[cls].pop(0)
        repo = REPOS / c["repo"]
        if per_repo.get(c["repo"], 0) >= PER_REPO:
            log.append((c["cve"], "repo cap")); continue
        targets = changed_targets(repo, c["fix"])
        if not 1 <= len(targets) <= 6:
            log.append((c["cve"], f"{len(targets)} changed functions")); continue
        trees = {}
        for kind, rev in (("vul", c["fix"] + "^"), ("fix", c["fix"])):
            d = OUT / "trees" / f"{c['cve']}-{kind}"
            if not d.exists():
                d.mkdir(parents=True)
                a = subprocess.run(f"git -C {repo} archive {rev} | tar -x -C {d}", shell=True, capture_output=True, timeout=1800)
                if a.returncode:
                    log.append((c["cve"], "archive failed")); break
            trees[kind] = str(d)
        if len(trees) < 2:
            continue
        per_repo[c["repo"]] = per_repo.get(c["repo"], 0) + 1
        cases.append({"cve": c["cve"], "cls": c["cls"], "targets": targets, "project": c["repo"], "vul": c["fix"] + "^",
                      "fix": c["fix"], "how": "commit message names the CVE", "trees": trees, "tools": {}})
        print(c["cve"], c["cls"], c["repo"], len(targets), "targets", flush=True)
json.dump({"seed": SEED, "cases": cases, "skipped": log}, open(OUT / "heldout3.json", "w"), indent=1)
print("cases", len(cases), {k: sum(c["cls"] == k for c in cases) for k, _ in CLASS_RE}, file=sys.stderr)
