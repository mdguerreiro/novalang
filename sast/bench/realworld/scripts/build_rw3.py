"""HELD-OUT split 2 (built 2026-10-27 01:3x, before any engine change from the dev diagnosis; its code is not read
during development). Same seeded order as split 1; skips every CVE split 1 used or skipped; requires the target
function to exist in the vulnerable tree. Pre-registered real-world split from PySASTBench RealworldDataset.csv (never used during development).
Seeded, class-stratified order; first N buildable CVEs; vulnerable tree = release tag of the listed version; fixed tree =
first later tag (within 8) where a target function's source changed. Unbuildable CVEs are logged and skipped."""
import ast, csv, json, random, re, subprocess, sys
from pathlib import Path

S = Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad")
CSV = S / "bench_ext/PySASTBench/RealworldDataset.csv"
OUT = S / "rw3"
DEV = json.load(open(S / "rw2" / "cases.json"))
SEEN = {c["cve"] for c in DEV["cases"]} | {c for c, _ in DEV["skipped"]}
EXCLUDE = ("aimhubio", "stitionai", "onnx", "kizniche", "wagtail", "streamlit")
CLS = {"22": "path", "79": "xss", "94": "code", "95": "code", "502": "deser", "89": "sqli", "78": "cmdi", "77": "cmdi"}
N = int(sys.argv[1]) if len(sys.argv) > 1 else 24
SEED = 20261026

rows = [r for r in csv.DictReader(open(CSV, encoding="utf-8-sig")) if not any(x in r["project"] for x in EXCLUDE)]
for r in rows:
    r["cls"] = CLS.get(r["CWE Type"].split(";")[0].split(",")[0].strip())
rows = [r for r in rows if r["cls"]]
rng = random.Random(SEED)
by = {}
for r in rows:
    by.setdefault(r["cls"], []).append(r)
for v in by.values():
    rng.shuffle(v)
order = []  # round-robin over classes: stratified
while any(by.values()):
    for c in sorted(by):
        if by[c]:
            order.append(by[c].pop())


def git(repo, *a, **kw):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, timeout=900, **kw)


def ver_key(t):
    return tuple(int(x) for x in re.findall(r"\d+", t)[:4])


def fn_src(repo, rev, path, fn):
    p = git(repo, "show", f"{rev}:{path}")
    if p.returncode:
        return None
    try:
        tree = ast.parse(p.stdout)
    except SyntaxError:
        return None
    name = fn.split(".")[-1]
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.unparse(n)
    return None


cases, log = [], []
for r in order:
    if len(cases) >= N:
        break
    cve = r["CVE"].split("name=")[-1]
    if cve in SEEN:
        continue
    m = re.search(r"https://github\.com/[\w.-]+/[\w.-]+?(?=https://|$|/|\s)", r["project"].strip())
    if not m:
        log.append((cve, "no github url")); continue
    url = m.group(0).rstrip("/").removesuffix(".git")
    slug = url.split("github.com/")[-1].replace("/", "__")
    repo = S / "rw2" / "repos" / slug  # shared clones
    if not repo.exists():
        c = subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url + ".git", str(repo)],
                           capture_output=True, text=True, timeout=1800)
        if c.returncode:
            log.append((cve, "clone failed")); continue
    tags = [t for t in git(repo, "tag").stdout.split() if re.search(r"\d", t)]
    text = r["Version"].strip()
    vers = re.findall(r"\d+(?:\.\d+)+", text)
    if not vers:
        log.append((cve, f"no version in {text!r}")); continue
    norm = lambda t: re.sub(r"^[^\d]*", "", t)
    tag_of = lambda v: next((t for t in sorted(tags, key=lambda t: (t not in (v, "v" + v), "/" in t, len(t))) if norm(t) == v), None)
    stable = lambda t: not re.search(r"(rc|a|b|dev|beta|alpha|post)\d*$", t)
    targets = [x.strip() for x in r["vul position"].split(";") if ":" in x]
    changed = lambda a, b: any(fn_src(repo, a, p.split(":")[0], p.split(":")[1]) != fn_src(repo, b, p.split(":")[0], p.split(":")[1])
                               for p in targets)
    fix = vt = None
    if re.search(r"before|prior to|<|fix|address", text, re.I):
        # `X before Y`, `prior to Y`, `fixed in Y`: Y is the fixed release, the vulnerable tree is the release before it.
        kw = re.search(r"(before|prior to|<|fixed (?:in|with)|fixes|addressed in)\D*(\d+(?:\.\d+)+)", text, re.I)
        fv = kw.group(2) if kw else vers[-1]
        ft = tag_of(fv)
        if ft:
            plain = re.fullmatch(r"v?\d[\d.]*", ft) is not None
            prev = sorted([t for t in tags if stable(t) and ver_key(t) < ver_key(ft)
                           and (re.fullmatch(r"v?\d[\d.]*", t) is not None) == plain and "/" not in t], key=ver_key)
            if prev and changed(prev[-1], ft):
                vt, fix = prev[-1], ft
    else:
        vt = tag_of(vers[0])
        if vt:
            later = sorted([t for t in tags if ver_key(t) > ver_key(vt) and stable(t)], key=ver_key)[:8]
            fix = next((t for t in later if changed(vt, t)), None)
    if not vt:
        log.append((cve, f"no tag for {text!r}")); continue
    if not fix:
        log.append((cve, "no later tag changes the target")); continue
    if not any(fn_src(repo, vt, p.split(":")[0], p.split(":")[1]) for p in targets):
        log.append((cve, "target function not in the vulnerable tree")); continue
    trees = {}
    for kind, rev in (("vul", vt), ("fix", fix)):
        d = OUT / "trees" / f"{cve}-{kind}"
        if not d.exists():
            d.mkdir(parents=True)
            a = subprocess.run(f"git -C {repo} archive {rev} | tar -x -C {d}", shell=True, capture_output=True, text=True, timeout=1800)
            if a.returncode:
                log.append((cve, "archive failed")); break
        trees[kind] = str(d)
    if len(trees) < 2:
        continue
    cases.append({"cve": cve, "cls": r["cls"], "targets": targets, "project": url, "vul": vt, "fix": fix, "trees": trees,
                  "tools": {k[:-7]: r[k] for k in r if k.endswith("_reason")}})
    print(cve, r["cls"], slug, vt, "->", fix, flush=True)
json.dump({"seed": SEED, "cases": cases, "skipped": log}, open(OUT / "cases.json", "w"), indent=1)
print("skipped:", log)
