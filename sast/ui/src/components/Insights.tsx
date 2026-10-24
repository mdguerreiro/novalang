import { useEffect, useMemo, useState } from "react";
import { api, type Benchmark, type Insights as I } from "../api";
import { Icon, pct } from "../lib";

interface Pt { x: string; sub: string; values: number[] }

const W = 560, H = 220, PAD = { l: 40, r: 70, t: 14, b: 34 };

function useHover() {
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);
  return { hover, setHover };
}

function LineChart({ pts, series, max = 1, fmt }: { pts: Pt[]; series: { name: string; color: string }[]; max?: number; fmt: (v: number) => string }) {
  const { hover, setHover } = useHover();
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const x = (i: number) => PAD.l + (pts.length <= 1 ? iw / 2 : (i / (pts.length - 1)) * iw);
  const y = (v: number) => PAD.t + ih - (v / max) * ih;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((t) => t * max);
  return (
    <div className="chart-wrap" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={series.map((s) => s.name).join(" and ") + " per scan"}>
        <g className="grid">{ticks.map((t) => <line key={t} x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} />)}</g>
        <g className="axis">
          {ticks.map((t) => <text key={t} x={PAD.l - 8} y={y(t) + 4} textAnchor="end">{fmt(t)}</text>)}
          {pts.map((p, i) => <text key={i} x={x(i)} y={H - PAD.b + 16} textAnchor="middle">{p.x}</text>)}
          {pts.map((p, i) => <text key={`s${i}`} x={x(i)} y={H - PAD.b + 29} textAnchor="middle" style={{ fontSize: 10 }}>{p.sub}</text>)}
        </g>
        {hover && <line x1={x(hover.i)} x2={x(hover.i)} y1={PAD.t} y2={PAD.t + ih} stroke="var(--border-strong)" strokeDasharray="3 3" />}
        {series.map((s, si) => (
          <g key={s.name}>
            <polyline fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round"
              points={pts.map((p, i) => `${x(i)},${y(p.values[si])}`).join(" ")} />
            {pts.map((p, i) => <circle key={i} cx={x(i)} cy={y(p.values[si])} r={hover?.i === i ? 5 : 4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />)}
            {pts.length > 0 && (
              <text x={x(pts.length - 1) + 10} y={y(pts[pts.length - 1].values[si]) + 4 + (si ? 8 : -4)} style={{ fontSize: 11.5, fill: "var(--text-2)", fontWeight: 600 }}>
                {s.name.split(" ")[0]} {fmt(pts[pts.length - 1].values[si])}
              </text>
            )}
          </g>
        ))}
        {pts.map((_, i) => (
          <rect key={i} x={x(i) - (iw / Math.max(pts.length, 2)) / 2} y={PAD.t} width={iw / Math.max(pts.length, 2)} height={ih} fill="transparent"
            onMouseMove={(e) => { const r = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect(); setHover({ i, x: e.clientX - r.left, y: e.clientY - r.top }); }} />
        ))}
      </svg>
      {hover && (
        <div className="tooltip" style={{ left: Math.min(hover.x + 14, 380), top: hover.y - 10 }}>
          <b>{pts[hover.i].x}</b> <span className="muted">{pts[hover.i].sub}</span>
          {series.map((s, si) => <div key={s.name} className="row"><span className="dot" style={{ background: s.color }} />{s.name}<span className="grow" /><b>{fmt(pts[hover.i].values[si])}</b></div>)}
        </div>
      )}
    </div>
  );
}

function StackedBars({ pts, series }: { pts: Pt[]; series: { name: string; color: string }[] }) {
  const { hover, setHover } = useHover();
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const max = Math.max(1, ...pts.map((p) => p.values.reduce((a, b) => a + b, 0)));
  const step = iw / Math.max(pts.length, 1);
  const bw = Math.min(34, step * 0.5);
  const y = (v: number) => (v / max) * ih;
  const ticks = Array.from(new Set([0, Math.ceil(max / 2), max]));
  return (
    <div className="chart-wrap" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="AI calls per scan">
        <g className="grid">{ticks.map((t) => <line key={t} x1={PAD.l} x2={W - PAD.r} y1={PAD.t + ih - y(t)} y2={PAD.t + ih - y(t)} />)}</g>
        <g className="axis">
          {ticks.map((t) => <text key={t} x={PAD.l - 8} y={PAD.t + ih - y(t) + 4} textAnchor="end">{t}</text>)}
          {pts.map((p, i) => <text key={i} x={PAD.l + step * i + step / 2} y={H - PAD.b + 16} textAnchor="middle">{p.x}</text>)}
          {pts.map((p, i) => <text key={`s${i}`} x={PAD.l + step * i + step / 2} y={H - PAD.b + 29} textAnchor="middle" style={{ fontSize: 10 }}>{p.sub}</text>)}
        </g>
        {pts.map((p, i) => {
          let acc = 0;
          const cx = PAD.l + step * i + step / 2 - bw / 2;
          const total = p.values.reduce((a, b) => a + b, 0);
          return (
            <g key={i} onMouseMove={(e) => { const r = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect(); setHover({ i, x: e.clientX - r.left, y: e.clientY - r.top }); }}>
              <rect x={cx - 6} y={PAD.t} width={bw + 12} height={ih} fill="transparent" />
              {p.values.map((v, si) => {
                if (!v) return null;
                const h = y(v);
                const top = PAD.t + ih - acc - h;
                acc += h;
                const isTop = p.values.slice(si + 1).every((x) => !x);
                return <path key={si} fill={series[si].color} opacity={hover && hover.i !== i ? 0.55 : 1}
                  d={roundedTop(cx, top + (si ? 0 : 0), bw, Math.max(h - 2, 1), isTop ? 4 : 0)} />;
              })}
              <text x={cx + bw / 2} y={PAD.t + ih - y(total) - 6} textAnchor="middle" style={{ fontSize: 11, fill: "var(--text-2)", fontWeight: 600 }}>{total}</text>
            </g>
          );
        })}
      </svg>
      {hover && (
        <div className="tooltip" style={{ left: Math.min(hover.x + 14, 380), top: hover.y - 10 }}>
          <b>{pts[hover.i].x}</b> <span className="muted">{pts[hover.i].sub}</span>
          {series.map((s, si) => <div key={s.name} className="row"><span className="dot" style={{ background: s.color }} />{s.name}<span className="grow" /><b>{pts[hover.i].values[si]}</b></div>)}
        </div>
      )}
    </div>
  );
}

function GroupedBars({ groups, series, fmt }: { groups: { label: string; values: number[] }[]; series: { name: string; color: string }[]; fmt: (v: number) => string }) {
  const { hover, setHover } = useHover();
  const iw = W - PAD.l - 20, ih = H - PAD.t - PAD.b;
  const step = iw / Math.max(groups.length, 1);
  const bw = Math.min(26, (step * 0.7) / series.length);
  const y = (v: number) => v * ih;
  return (
    <div className="chart-wrap" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Precision and recall by pipeline stage">
        <g className="grid">{[0, 0.5, 1].map((t) => <line key={t} x1={PAD.l} x2={W - 20} y1={PAD.t + ih - y(t)} y2={PAD.t + ih - y(t)} />)}</g>
        <g className="axis">
          {[0, 0.5, 1].map((t) => <text key={t} x={PAD.l - 8} y={PAD.t + ih - y(t) + 4} textAnchor="end">{fmt(t)}</text>)}
          {groups.map((g, i) => {
            const [a, ...rest] = g.label.split(" ");
            return (
              <g key={i}>
                <text x={PAD.l + step * i + step / 2} y={H - PAD.b + 16} textAnchor="middle" style={{ fontWeight: 600 }}>{a}</text>
                <text x={PAD.l + step * i + step / 2} y={H - PAD.b + 29} textAnchor="middle" style={{ fontSize: 10 }}>{rest.join(" ").replace("(gated)", "").trim()}</text>
              </g>
            );
          })}
        </g>
        {groups.map((g, i) => {
          const x0 = PAD.l + step * i + step / 2 - (bw * series.length + 2 * (series.length - 1)) / 2;
          return (
            <g key={i} onMouseMove={(e) => { const r = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect(); setHover({ i, x: e.clientX - r.left, y: e.clientY - r.top }); }}>
              <rect x={PAD.l + step * i} y={PAD.t} width={step} height={ih} fill="transparent" />
              {g.values.map((v, si) => (
                <g key={si}>
                  <path fill={series[si].color} opacity={hover && hover.i !== i ? 0.55 : 1} d={roundedTop(x0 + si * (bw + 2), PAD.t + ih - y(v), bw, Math.max(y(v), 1), 4)} />
                  <text x={x0 + si * (bw + 2) + bw / 2} y={PAD.t + ih - y(v) - 5} textAnchor="middle" style={{ fontSize: 10.5, fill: "var(--text-2)", fontWeight: 600 }}>{fmt(v)}</text>
                </g>
              ))}
            </g>
          );
        })}
      </svg>
      {hover && (
        <div className="tooltip" style={{ left: Math.min(hover.x + 14, 380), top: hover.y - 10 }}>
          <b>{groups[hover.i].label}</b>
          {series.map((s, si) => <div key={s.name} className="row"><span className="dot" style={{ background: s.color }} />{s.name}<span className="grow" /><b>{fmt(groups[hover.i].values[si])}</b></div>)}
        </div>
      )}
    </div>
  );
}

function roundedTop(x: number, y: number, w: number, h: number, r: number) {
  r = Math.min(r, h, w / 2);
  return `M${x},${y + h} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + h} Z`;
}

export function Insights() {
  const [data, setData] = useState<I | null>(null);
  const [table, setTable] = useState(false);
  const [bench, setBench] = useState<Benchmark | null>(null);
  useEffect(() => { api.insights().then(setData); api.benchmark().then(setBench); }, []);
  const pts = useMemo<Pt[]>(() => (data?.scans ?? []).filter((s) => (s.stats as { trigger?: string }).trigger !== "knowledge").map((s, i) => ({ x: `#${i + 1}`, sub: s.repo_id.replace("acme-", ""), values: [] })), [data]);
  if (!data) return <div className="page"><div className="skeleton" style={{ height: 200 }} /></div>;
  // Re-derivations after a knowledge change are not scans; the charts show real scans only.
  const scans = data.scans.filter((s) => (s.stats as { trigger?: string }).trigger !== "knowledge");
  const last = scans[scans.length - 1]?.stats;
  const decidedPts = scans.map((s, i) => ({ ...pts[i], values: [s.stats.auto_rate, s.stats.tier0_rate] }));
  const callPts = scans.map((s, i) => ({ ...pts[i], values: [s.stats.tier1_calls, s.stats.tier2_calls] }));
  const learned = scans.reduce((a, s) => Math.max(a, s.stats.resolved_by_learned_knowledge), 0);
  const fnRate = data.audit.audited ? data.audit.missed_tps / data.audit.audited : null;
  const effFp = data.effective_fp.shown_triaged ? data.effective_fp.fp / data.effective_fp.shown_triaged : null;
  const kActive = data.knowledge.filter((k) => k.status === "active" && !k.origin.startsWith("curated")).reduce((a, k) => a + k.n, 0);
  const totalCalls = scans.reduce((a, s) => a + s.stats.tier1_calls + s.stats.tier2_calls, 0);
  const perRepo = [...new Set(scans.map((s) => s.repo_id))].map((repo) => {
    const rs = scans.filter((s) => s.repo_id === repo);
    return { repo, first: rs[0].stats, last: rs[rs.length - 1].stats, n: rs.length };
  });
  const improved = perRepo.find((r) => r.n > 1);

  return (
    <div className="page">
      <p className="page-intro">
        The flywheel at work. Each scan sends only what the deterministic engine cannot decide to the AI tiers. Each verdict,
        from AI or human, becomes engine knowledge, so the next scan needs fewer AI calls and fewer human decisions.
      </p>
      <div className="kpis">
        <div className="card kpi">
          <div className="k-label">Decided without a human</div>
          <div className="k-value">{pct(last?.auto_rate)}</div>
          <p>Latest scan. The engine, oracle and agent together; every AI decision re-derived symbolically.</p>
        </div>
        <div className="card kpi">
          <div className="k-label">Decided by the engine alone</div>
          <div className="k-value">{pct(last?.tier0_rate)}</div>
          {improved && <div className="k-delta up">▲ {Math.round((improved.last.tier0_rate - improved.first.tier0_rate) * 100)} pts on {improved.repo} after one review</div>}
          <p>Tier 0: deterministic, free, reproducible.</p>
        </div>
        <div className="card kpi">
          <div className="k-label">Resolved by learned knowledge</div>
          <div className="k-value">{learned}</div>
          <p>Findings decided by facts the engine learned from triage and AI ({kActive} active items).</p>
        </div>
        <div className="card kpi">
          <div className="k-label">Audited AI false-negative rate</div>
          <div className="k-value">{fnRate == null ? "–" : pct(fnRate)}</div>
          <p>{data.audit.audited ? `${data.audit.missed_tps} real issue(s) in ${data.audit.audited} audited AI suppressions.` : "Audit the sampled AI suppressions to measure this."}</p>
        </div>
        <div className="card kpi">
          <div className="k-label">Effective false-positive rate</div>
          <div className="k-value">{effFp == null ? "–" : pct(effFp)}</div>
          <p>{data.effective_fp.shown_triaged ? `Of ${data.effective_fp.shown_triaged} findings shown to people and triaged.` : "Shown findings later marked not exploitable."}</p>
        </div>
        <div className="card kpi">
          <div className="k-label">AI calls, all scans</div>
          <div className="k-value">{totalCalls}</div>
          <p>Oracle questions and agent verifications. Cached and learned answers are free.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <div className="card-h"><Icon name="activity" /> How the flywheel turns</div>
        <div className="flywheel">
          {[["1", "Engine decides", "Datalog proves or refutes each source→sink flow, with named mitigations.", pct(last?.tier0_rate)],
            ["2", "AI resolves the rest", "The oracle labels unknown APIs; the agent verifies with cited evidence.", `${last ? last.decided.tier1 + last.decided.tier2 : 0}`],
            ["3", "Gates check AI", "Hash-checked citations, unanimous votes, symbolic re-derivation.", "100%"],
            ["4", "Humans teach", "A structured triage reason becomes a fact, previewed across repos.", `${data.verdicts.human ?? 0}`],
            ["5", "Engine learns", "Facts pass canary gates, then decide future findings for free.", `${kActive}`]].map(([n, h, p, v]) => (
            <div key={n} className="fw-step"><div className="fw-n">STEP {n}</div><h4>{h}</h4><p>{p}</p><div className="fw-v">{v}</div></div>
          ))}
        </div>
      </div>

      <div className="charts">
        <div className="card">
          <div className="card-h">Share of findings decided without a human<span className="grow" /><span className="muted" style={{ fontWeight: 500, fontSize: 12 }}>per scan</span></div>
          <div className="legend"><span><i style={{ background: "var(--series-1)" }} />All tiers</span><span><i style={{ background: "var(--series-2)" }} />Engine alone</span></div>
          <LineChart pts={decidedPts} series={[{ name: "All tiers", color: "var(--series-1)" }, { name: "Engine alone", color: "var(--series-2)" }]} fmt={(v) => pct(v)} />
        </div>
        <div className="card">
          <div className="card-h">AI calls per scan<span className="grow" /><span className="muted" style={{ fontWeight: 500, fontSize: 12 }}>lower is better</span></div>
          <div className="legend"><span><i style={{ background: "var(--series-1)" }} />Oracle questions</span><span><i style={{ background: "var(--series-2)" }} />Agent verifications</span></div>
          <StackedBars pts={callPts} series={[{ name: "Oracle questions", color: "var(--series-1)" }, { name: "Agent verifications", color: "var(--series-2)" }]} />
        </div>
      </div>

      {bench?.available && bench.stages && (
        <div className="charts">
          <div className="card">
            <div className="card-h">Benchmark vs Semgrep OSS<span className="grow" /><span className="muted" style={{ fontWeight: 500, fontSize: 12 }}>demo corpus · 14 real vulns</span></div>
            <div className="legend"><span><i style={{ background: "var(--series-1)" }} />Precision</span><span><i style={{ background: "var(--series-2)" }} />Recall</span></div>
            <GroupedBars groups={Object.entries(bench.stages).map(([k, v]) => ({ label: k.replace(/^S\d /, "").replace("Semgrep OSS baseline", "Semgrep OSS").replace("Tier 0 engine", "Engine (Tier 0)").replace("+ Tier 1 oracle", "+Oracle (Tier 1)").replace("+ Tier 2 agent (gated)", "+Agent (Tier 2)"), values: [v.precision, v.recall] }))}
              series={[{ name: "Precision", color: "var(--series-1)" }, { name: "Recall", color: "var(--series-2)" }]} fmt={(v) => pct(v)} />
            <div className="muted" style={{ padding: "0 14px 12px", fontSize: 12 }}>
              Semgrep OSS misses every cross-function flow. The agent is a deterministic mock in this POC, so the Tier-2 bar validates the gating machinery, not model quality.
              {bench.ai_suppression && <> AI suppressions that hid a real vulnerability: <b>{bench.ai_suppression.wrongly_suppressed_tps.length}</b> of {bench.ai_suppression.suppressed}.</>}
            </div>
          </div>
          <div className="card">
            <div className="card-h">What one review taught the engine</div>
            <div className="card-b">
              <table className="data">
                <thead><tr><th>Repository</th><th>Engine-decided</th><th>AI calls</th><th>Learned</th></tr></thead>
                <tbody>
                  {perRepo.flatMap((r) => (r.n > 1 ? [
                    <tr key={`${r.repo}-1`}><td>{r.repo} · first scan</td><td>{pct(r.first.tier0_rate)}</td><td>{r.first.tier1_calls + r.first.tier2_calls}</td><td>{r.first.resolved_by_learned_knowledge}</td></tr>,
                    <tr key={`${r.repo}-2`}><td><b>{r.repo} · after review</b></td><td><b>{pct(r.last.tier0_rate)}</b></td><td><b>{r.last.tier1_calls + r.last.tier2_calls}</b></td><td><b>{r.last.resolved_by_learned_knowledge}</b></td></tr>,
                  ] : []))}
                  {bench.flywheel?.["acme-billing cold (no shop knowledge)"] && bench.flywheel?.["acme-billing warm (after shop review)"] && (() => {
                    const c = bench.flywheel!["acme-billing cold (no shop knowledge)"], w = bench.flywheel!["acme-billing warm (after shop review)"];
                    return [
                      <tr key="bc"><td>acme-billing · onboarded cold</td><td>{pct(c.tier0_rate)}</td><td>{(c.tier1_calls ?? 0) + (c.tier2_calls ?? 0)}</td><td>{c.resolved_by_learned_knowledge}</td></tr>,
                      <tr key="bw"><td><b>acme-billing · onboarded with org knowledge</b></td><td><b>{pct(w.tier0_rate)}</b></td><td><b>{(w.tier1_calls ?? 0) + (w.tier2_calls ?? 0)}</b></td><td><b>{w.resolved_by_learned_knowledge}</b></td></tr>,
                    ];
                  })()}
                </tbody>
              </table>
              <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>A new repository in the same organization starts with everything the engine already learned: shared sanitizers, validated guards and library facts. It needs fewer AI calls from its very first scan.</p>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-h">Scan history<span className="grow" /><button className="btn ghost sm table-toggle" onClick={() => setTable((t) => !t)}>{table ? "Hide table" : "Show table"}</button></div>
        {table && (
          <div className="card-b">
            <table className="data">
              <thead><tr><th>Scan</th><th>Repo</th><th>Findings</th><th>Engine</th><th>Oracle</th><th>Agent</th><th>Human queue</th><th>Engine-decided</th><th>Learned</th><th>Seconds</th></tr></thead>
              <tbody>
                {scans.map((s, i) => (
                  <tr key={s.id}><td>#{i + 1}</td><td>{s.repo_id}</td><td>{s.stats.findings}</td><td>{s.stats.decided.engine}</td><td>{s.stats.decided.tier1}</td>
                    <td>{s.stats.decided.tier2}</td><td>{s.stats.decided.human_queue}</td><td>{pct(s.stats.tier0_rate)}</td><td>{s.stats.resolved_by_learned_knowledge}</td><td>{s.stats.seconds}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
