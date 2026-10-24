import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type ImpactRow, type Knowledge as K } from "../api";
import { Icon, ago, knowledgeStatement, originLabel, short } from "../lib";
import type { ToastFn } from "./Inbox";

const STAGES: { id: K["status"]; label: string; text: string }[] = [
  { id: "candidate", label: "Candidate", text: "Proposed, or blocked by a failing gate" },
  { id: "shadow", label: "Shadow", text: "Evaluated on every scan, never applied" },
  { id: "active", label: "Active", text: "Part of the engine; decides findings" },
  { id: "retired", label: "Retired", text: "Withdrawn; its findings were re-opened" },
];

function GatePills({ k }: { k: K }) {
  const g = k.gate ?? {};
  if (!g.canary) return <span className="chip">not gated yet</span>;
  return (
    <span className="gate-pills">
      <span className={`chip ${g.sanity === "pass" ? "good" : "bad"}`}><Icon name={g.sanity === "pass" ? "check" : "x"} size={10} />sanity</span>
      <span className={`chip ${g.canary === "pass" ? "good" : "bad"}`} title={g.canary}><Icon name={g.canary === "pass" ? "check" : "x"} size={10} />canaries</span>
      <span className={`chip ${g.over_budget ? "warn" : ""}`}><Icon name="layers" size={10} />{g.suppresses ?? 0} suppressed</span>
    </span>
  );
}

export function Knowledge({ toast, refreshOverview }: { toast: ToastFn; refreshOverview: () => void }) {
  const [items, setItems] = useState<K[]>([]);
  const [filter, setFilter] = useState<K["status"] | "all">("all");
  const [open, setOpen] = useState<K | null>(null);
  const [impact, setImpact] = useState<ImpactRow[] | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => { const rows = await api.knowledge(); setItems(rows); return rows; }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    setImpact(null);
    if (open && open.status !== "active" && open.status !== "retired") api.previewKnowledge(open.id).then((p) => setImpact(p.impact));
  }, [open?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const counts = useMemo(() => Object.fromEntries(STAGES.map((s) => [s.id, items.filter((k) => k.status === s.id).length])), [items]);
  const shown = items.filter((k) => filter === "all" || k.status === filter);
  const machineShare = items.length ? items.filter((k) => !k.origin.startsWith("human")).length / items.length : 0;

  const act = async (k: K, status: string) => {
    setBusy(true);
    try {
      const res = await api.setKnowledge(k.id, status);
      toast(status === "active" ? `${k.id} is now active. The engine decides these findings itself from now on.` :
        status === "retired" ? `${k.id} retired. Findings it suppressed were re-opened.` : `${k.id} moved to ${status}`,
        { icon: status === "active" ? "brain" : "check" });
      const rows = await load();
      setOpen(rows.find((r) => r.id === res.id) ?? null);
      refreshOverview();
    } catch (e) {
      toast(`Blocked: ${(e as Error).message}`);
    } finally { setBusy(false); }
  };

  return (
    <div className="page">
      <p className="page-intro">
        Everything the engine has learned, from your triage, from the verifier agent and from the spec oracle. Each item is a
        Datalog fact with provenance. It only becomes <b>active</b> after passing its gates: canary replay, no conflicts with
        confirmed findings, and an impact budget. Machine-proposed knowledge waits in <b>shadow</b> until it is independently
        corroborated or you approve it.
      </p>
      <div className="k-pipeline">
        {STAGES.map((s) => (
          <button key={s.id} className="k-stage" style={{ textAlign: "left", cursor: "pointer", outline: filter === s.id ? "2px solid var(--accent)" : undefined }}
            onClick={() => setFilter(filter === s.id ? "all" : s.id)}>
            <div className="k-l">{s.label}</div>
            <div className="k-n">{counts[s.id] ?? 0}</div>
            <p>{s.text}</p>
          </button>
        ))}
      </div>
      <div className="card">
        <div className="card-h">
          <Icon name="brain" /> Knowledge base
          <span className="muted" style={{ fontWeight: 500 }}>· {items.length} items · {Math.round(machineShare * 100)}% proposed by AI tiers</span>
          <span className="grow" />
          {filter !== "all" && <button className="btn ghost sm" onClick={() => setFilter("all")}>Clear filter</button>}
        </div>
        <table className="k-table">
          <thead><tr><th>Knowledge</th><th>Scope</th><th>Origin</th><th>Support</th><th>Gates</th><th>Effect</th><th>Status</th></tr></thead>
          <tbody>
            {shown.map((k) => {
              const o = originLabel(k.origin);
              return (
                <tr key={k.id} className={open?.id === k.id ? "sel" : ""} onClick={() => setOpen(k)} style={{ cursor: "pointer" }}>
                  <td>
                    <div className="k-statement">{knowledgeStatement(k.pred, k.args)}</div>
                    <div className="k-fact">{k.id} · {k.pred}({k.args.join(", ")})</div>
                  </td>
                  <td><span className="chip">{k.scope}</span></td>
                  <td><span className={`chip ${o.kind === "human" ? "accent" : o.kind === "agent" ? "info" : ""}`}><Icon name={o.kind === "human" ? "check" : o.kind === "agent" ? "sparkle" : "book"} size={10} />{o.who}</span></td>
                  <td className="mono">{k.support ?? 0}</td>
                  <td><GatePills k={k} /></td>
                  <td className="text-2" style={{ fontSize: 12 }}>
                    {k.applied_to?.length ? <>decides <b>{k.applied_to.length}</b></> : k.shadowing?.length ? <>would decide <b>{k.shadowing.length}</b></> : <span className="muted">–</span>}
                  </td>
                  <td><span className={`chip ${k.status === "active" ? "good" : k.status === "shadow" ? "accent" : k.status === "retired" ? "" : "warn"}`}>{k.status}</span></td>
                </tr>
              );
            })}
            {shown.length === 0 && <tr><td colSpan={7}><div className="empty">Nothing here yet. Triage findings or run a scan.</div></td></tr>}
          </tbody>
        </table>
      </div>

      {open && (
        <div className="drawer" role="dialog" aria-label={`Knowledge ${open.id}`}>
          <div className="drawer-h">
            <div className="grow">
              <div className="row"><span className="mono muted">{open.id}</span><span className={`chip ${open.status === "active" ? "good" : open.status === "shadow" ? "accent" : ""}`}>{open.status}</span><span className="chip">{open.scope}</span></div>
              <h3 style={{ margin: "6px 0 2px", fontSize: 16 }}>{knowledgeStatement(open.pred, open.args)}</h3>
              <div className="fact">{open.pred}({open.args.join(", ")})</div>
            </div>
            <button className="btn ghost sm" onClick={() => setOpen(null)} aria-label="Close"><Icon name="x" /></button>
          </div>
          <div className="drawer-b">
            <div>
              <div className="section-title">Why the engine believes this</div>
              <p style={{ margin: 0 }}>{open.rationale}</p>
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {originLabel(open.origin).who} · {open.origin} · {open.confidence != null ? `confidence ${Math.round(open.confidence * 100)}% · ` : ""}proposed {ago(open.created_at)}
              </div>
            </div>
            <div>
              <div className="section-title">Gates</div>
              <div className="gates" style={{ borderTop: 0, paddingTop: 0 }}>
                {[["sanity", open.gate?.sanity ?? "pending"], ["canaries", open.gate?.canary ?? "pending"],
                  ["impact", `${open.gate?.suppresses ?? 0} finding(s) suppressed${open.gate?.over_budget ? " (over budget: needs approval)" : ""}`],
                  ["support", `${open.support ?? 0} independent piece(s) of evidence`]].map(([g, d]) => (
                  <div key={g} className="gate">
                    <span style={{ color: String(d).startsWith("fail") ? "var(--critical-text)" : "var(--good-text)" }}><Icon name={String(d).startsWith("fail") ? "x" : "check"} size={14} /></span>
                    <span className="g-name">{g}</span><span className="text-2">{d}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div className="section-title">Provenance</div>
              {(open.links ?? []).length === 0 && <span className="muted">No linked findings.</span>}
              {(open.links ?? []).map((l, i) => (
                <div key={i} className="impact-row" style={{ padding: "4px 0" }}>
                  <span className="chip" style={{ height: 18 }}>{l.relation.replace("_", " ")}</span>
                  <span className="ellipsis">{l.repo_id} · {short(l.source_fn)} · {l.cls}</span>
                </div>
              ))}
            </div>
            {impact && (
              <div>
                <div className="section-title">If activated now</div>
                {impact.length === 0 && <span className="muted">No finding changes in its scope.</span>}
                {impact.map((i, n) => (
                  <div key={n} className="impact-row" style={{ padding: "4px 0" }}>
                    <span className="chip" style={{ height: 18 }}>{i.repo}</span>
                    <span className="ellipsis grow">{short(i.source_fn)} · {i.cls}</span>
                    <span className="mono muted" style={{ fontSize: 11 }}>{i.from} → {i.to}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="drawer-f">
            {open.status !== "retired" && <button className="btn" disabled={busy} onClick={() => act(open, "retired")}><Icon name="undo" />Retire</button>}
            {open.status === "active" && <button className="btn" disabled={busy} onClick={() => act(open, "shadow")}><Icon name="eye" />Back to shadow</button>}
            {open.status !== "active" && <button className="btn primary" disabled={busy || open.gate?.canary?.startsWith("fail")} onClick={() => act(open, "active")}><Icon name="check" />Approve & activate</button>}
          </div>
        </div>
      )}
    </div>
  );
}
