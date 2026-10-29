import json, sys
S = "/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad"
base = {}
for f in ("rw4/base.json", "rw3/base.json"):
    base.update(json.load(open(f"{S}/{f}")))
for name in sys.argv[1:]:
    d = json.load(open(f"{S}/review/{name}.json"))
    cves = sorted({k.rsplit("-", 1)[0] for k in d if k.startswith("CVE")})
    done = [c for c in cves if c + "-vul" in d and c + "-fix" in d]
    def stat(key):
        hit = [c for c in done if d[c + "-vul"].get(key)]
        clean = [c for c in hit if not d[c + "-fix"].get(key)]
        fixflag = [c for c in done if d[c + "-fix"].get(key)]
        return hit, clean, fixflag
    fz = [c for c in done if base.get(c + "-vul", {}).get("flagged")]
    fzc = [c for c in fz if not base.get(c + "-fix", {}).get("flagged")]
    e, ec, ef = stat("engine"); a, ac, af = stat("flagged")
    picked = [c for c in done if d[c + "-vul"].get("target_picked")]
    spend = json.load(open(f"{S}/review/{name}.json.spend.json"))["usd"]
    iss = sum(d[c + "-vul"].get("review_issues", 0) for c in done)
    print(f"{name}: {len(done)} CVEs | frozen engine {len(fz)} ({len(fzc)} clean) | engine v6 {len(e)} ({len(ec)} clean, fix-flagged {len(ef)}) | "
          f"engine+review {len(a)} ({len(ac)} clean, fix-flagged {len(af)}) | target read {len(picked)} | review issues on vul trees {iss} | ${spend}")
    print("   review-only catches:", [c for c in a if c not in e], " fix-flagged:", af)
