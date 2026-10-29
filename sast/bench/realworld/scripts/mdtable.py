import json, sys
runs = [(a.split("=")[0], json.load(open(a.split("=")[1]))) for a in sys.argv[2:]]
title = sys.argv[1]
cases = sorted({k.rsplit("-", 1)[0] for _, r in runs for k in r})
def proj(c):
    for _, r in runs:
        v = r.get(c + "-vul")
        if v: return v.get("cls")
hdr = "| " + title + " | class | " + " | ".join(n for n, _ in runs) + " |"
print(hdr); print("|" + "---|" * (2 + len(runs)))
tot = {n: [0, 0, 0, 0] for n, _ in runs}
for c in cases:
    cells = []
    for n, r in runs:
        v, f = r.get(c + "-vul"), r.get(c + "-fix")
        if not v:
            cells.append("-"); continue
        mark = "caught, fix clean" if v.get("flagged") and not (f or {}).get("flagged") else \
               "caught, fix flagged" if v.get("flagged") else ("missed, fix flagged" if (f or {}).get("flagged") else "missed")
        cells.append(f"{mark} ({v.get('reported')})")
        t = tot[n]; t[0] += bool(v.get("flagged")); t[1] += bool(v.get("flagged") and not (f or {}).get("flagged")); t[2] += bool((f or {}).get("flagged")); t[3] += v.get("reported") or 0
    print(f"| {c.split('id=')[-1]} | {proj(c)} | " + " | ".join(cells) + " |")
print("| **total** | | " + " | ".join(f"**{t[0]} caught, {t[1]} with fix clean; {t[2]} fixed trees flagged; {t[3]} findings**" for n, t in tot.items()) + " |")
