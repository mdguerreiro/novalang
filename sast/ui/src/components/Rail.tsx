import { useEffect, useRef, useState } from "react";
import { api, type FindingDetail, type Preview, type Suggestion } from "../api";
import { Icon, ago, knowledgeStatement, originLabel, short } from "../lib";

export type Mode = null | "not_exploitable" | "accepted_risk";

const LEARNS = new Set(["SANITIZED", "GUARDED", "UNREACHABLE", "NOT_EXPOSED"]);

export function Rail({ f, mode, setMode, reasonIdx, setReasonIdx, onConfirm, onCommit, busy }: {
  f: FindingDetail;
  mode: Mode;
  setMode: (m: Mode) => void;
  reasonIdx: number | null;
  setReasonIdx: (i: number | null) => void;
  onConfirm: () => void;
  onCommit: (state: "not_exploitable" | "accepted_risk", s: Suggestion | null, scope: string | null, note: string) => void;
  busy: boolean;
}) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [loading, setLoading] = useState(false);
  const [scope, setScope] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const reqId = useRef(0);
  const options = f.suggestions.filter((s) => s.reason !== "ACCEPTED_RISK");
  const chosen = reasonIdx != null ? options[reasonIdx] ?? null : null;

  useEffect(() => { setPreview(null); setScope(null); setNote(""); }, [f.id]);

  useEffect(() => {
    if (mode !== "not_exploitable" || !chosen || !LEARNS.has(chosen.reason)) { setPreview(null); return; }
    const id = ++reqId.current;
    setLoading(true);
    api.preview(f.id, chosen.reason, chosen.detail, scope)
      .then((p) => { if (id === reqId.current) { setPreview(p); if (!scope && p.knowledge) setScope(p.knowledge.scope); } })
      .finally(() => id === reqId.current && setLoading(false));
  }, [mode, chosen?.label, scope, f.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const triaged = f.triage_state !== "untriaged";
  const humanVerdict = [...f.verdicts].reverse().find((v) => v.kind === "human");
  const changed = preview?.impact.filter((i) => i.to === "mitigated") ?? [];
  const blocked = preview && (preview.canary !== "pass" || (preview.sanity && preview.sanity !== "pass"));

  return (
    <aside className="rail" aria-label="Triage">
      <div className="rail-sec">
        <div className="section-title">Your verdict</div>
        {triaged && humanVerdict && (
          <div className="t-note info" style={{ marginBottom: 10 }}>
            <Icon name="check" size={13} />
            <span>{f.triage_state.replace("_", " ")} by {originLabel(humanVerdict.actor).who} {ago(humanVerdict.created_at)}
              {humanVerdict.reason_code ? ` · ${humanVerdict.reason_code.toLowerCase()}` : ""}</span>
          </div>
        )}
        <div className="actions">
          <button className="action" onClick={onConfirm} disabled={busy}>
            <span className="a-top"><span style={{ color: "var(--critical-text)" }}><Icon name="alert" /></span>Confirm<span className="kbd">C</span></span>
            <small>Real vulnerability</small>
          </button>
          <button className={`action${mode === "not_exploitable" ? " on" : ""}`} onClick={() => setMode(mode === "not_exploitable" ? null : "not_exploitable")} disabled={busy}>
            <span className="a-top"><span style={{ color: "var(--good-text)" }}><Icon name="shield" /></span>Not exploitable<span className="kbd">X</span></span>
            <small>Teaches the engine why</small>
          </button>
          <button className={`action${mode === "accepted_risk" ? " on" : ""}`} onClick={() => setMode(mode === "accepted_risk" ? null : "accepted_risk")} disabled={busy}>
            <span className="a-top"><Icon name="lock" />Accept risk<span className="kbd">A</span></span>
            <small>Governance only</small>
          </button>
          <button className="action" onClick={() => window.dispatchEvent(new CustomEvent("sentinel:next"))}>
            <span className="a-top"><Icon name="arrow" />Skip<span className="kbd">J</span></span>
            <small>Next in queue</small>
          </button>
        </div>

        {mode === "not_exploitable" && (
          <>
            <div className="reasons" role="radiogroup" aria-label="Reason">
              {options.map((s, i) => (
                <button key={i} role="radio" aria-checked={reasonIdx === i} className={`reason${reasonIdx === i ? " on" : ""}`} onClick={() => setReasonIdx(i)}>
                  <span className="num">{i + 1}</span>
                  <span className="grow ellipsis" title={s.label}>{s.label}</span>
                  {LEARNS.has(s.reason) ? <span className="chip accent learn"><Icon name="brain" size={11} />learns</span> : <span className="chip learn">no learning</span>}
                </button>
              ))}
            </div>
            {chosen && LEARNS.has(chosen.reason) && (
              <div className="impact" aria-live="polite">
                <div className="impact-h"><Icon name="brain" /> The engine will learn {loading && <span className="spinner" style={{ marginLeft: "auto" }} />}</div>
                <div className="impact-b">
                  {preview?.knowledge && (
                    <>
                      <div style={{ fontWeight: 600 }}>{knowledgeStatement(preview.knowledge.pred, preview.knowledge.args)}</div>
                      <div className="fact">{preview.knowledge.pred}({preview.knowledge.args.join(", ")})</div>
                      <div className="row" style={{ justifyContent: "space-between" }}>
                        <span className="muted">Scope</span>
                        <span className="scope-pick">
                          {["repo", "org"].map((s) => <button key={s} className={(scope ?? preview.knowledge!.scope) === s ? "on" : ""} onClick={() => setScope(s)}>{s === "repo" ? "This repo" : "Organization"}</button>)}
                        </span>
                      </div>
                      <div className="impact-row">
                        <Icon name={preview.canary === "pass" ? "check" : "x"} size={14} />
                        <span style={{ color: preview.canary === "pass" ? "var(--good-text)" : "var(--critical-text)" }}>
                          {preview.canary === "pass" ? "Canary corpus and confirmed findings unaffected" : preview.canary}
                        </span>
                      </div>
                      <div className="impact-row">
                        <Icon name="layers" size={14} />
                        <span><b>{changed.length}</b> finding{changed.length === 1 ? "" : "s"} re-decided across <b>{new Set(changed.map((c) => c.repo)).size}</b> repo{new Set(changed.map((c) => c.repo)).size === 1 ? "" : "s"}</span>
                      </div>
                      {changed.slice(0, 5).map((c, i) => (
                        <div key={i} className="impact-row muted" style={{ paddingLeft: 20 }}>
                          <span className="chip" style={{ height: 18 }}>{c.repo}</span>
                          <span className="ellipsis">{short(c.source_fn)} · {c.cls}</span>
                          {c.finding && c.finding.id === f.id && <span className="chip accent" style={{ height: 18 }}>this</span>}
                        </div>
                      ))}
                      {preview.over_budget && <div className="t-note warn"><Icon name="alert" size={13} /> Large blast radius: it will start in shadow mode until approved.</div>}
                    </>
                  )}
                  {!preview && <div className="skeleton" style={{ height: 64 }} />}
                </div>
              </div>
            )}
            <textarea className="note" placeholder="Optional note for the audit trail…" value={note} onChange={(e) => setNote(e.target.value)} style={{ marginTop: 10 }} />
            <button className="btn primary" style={{ width: "100%", marginTop: 8, height: 34, justifyContent: "center" }}
              disabled={!chosen || busy || !!blocked} onClick={() => onCommit("not_exploitable", chosen, scope, note)}>
              {busy ? <span className="spinner" /> : <Icon name={chosen && LEARNS.has(chosen.reason) ? "brain" : "check"} />}
              {chosen && LEARNS.has(chosen.reason) ? "Mark not exploitable & teach engine" : "Mark not exploitable"}
              <span className="kbd" style={{ marginLeft: 6, background: "transparent", color: "white", borderColor: "rgb(255 255 255 / .4)" }}>↵</span>
            </button>
          </>
        )}
        {mode === "accepted_risk" && (
          <>
            <textarea className="note" placeholder="Why is this risk acceptable? Who owns it?" value={note} onChange={(e) => setNote(e.target.value)} style={{ marginTop: 12 }} autoFocus />
            <button className="btn primary" style={{ width: "100%", marginTop: 8, height: 34, justifyContent: "center" }} disabled={busy}
              onClick={() => onCommit("accepted_risk", null, null, note)}>Accept risk</button>
          </>
        )}
      </div>

      {f.knowledge.length > 0 && (
        <div className="rail-sec">
          <div className="section-title">Knowledge involved</div>
          {f.knowledge.map((k) => (
            <div key={`${k.id}-${k.relation}`} style={{ padding: "6px 0" }}>
              <div className="row"><span className="mono muted" style={{ fontSize: 11 }}>{k.id}</span>
                <span className={`chip ${k.status === "active" ? "good" : k.status === "shadow" ? "accent" : ""}`} style={{ height: 18 }}>{k.status}</span>
                <span className="chip" style={{ height: 18 }}>{k.relation?.replace("_", " ")}</span>
              </div>
              <div style={{ marginTop: 3 }}>{knowledgeStatement(k.pred, k.args)}</div>
              <div className="muted" style={{ fontSize: 11.5 }}>{originLabel(k.origin).who} · {k.scope}</div>
            </div>
          ))}
        </div>
      )}

      <div className="rail-sec">
        <div className="section-title">Activity</div>
        <div className="timeline">
          {f.verdicts.map((v) => (
            <div key={v.id} className="tl">
              <span className="dot" style={{ background: v.kind === "human" ? "var(--accent)" : "var(--border-strong)" }} />
              <div><b>{originLabel(v.actor).who}</b> <span className="text-2">{v.verdict.replace("_", " ").toLowerCase()}{v.reason_code ? ` · ${v.reason_code.toLowerCase()}` : ""}</span>
                <div className="muted" style={{ fontSize: 11 }}>{ago(v.created_at)}{v.gate?.accepted === false && v.kind !== "human" ? " · not accepted by gates" : ""}</div></div>
            </div>
          ))}
          {f.verdicts.length === 0 && <span className="muted">Decided by the engine at scan time.</span>}
        </div>
      </div>
    </aside>
  );
}
