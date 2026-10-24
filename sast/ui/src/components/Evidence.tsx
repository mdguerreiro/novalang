import { useMemo, useState } from "react";
import type { FindingDetail, ProofNode, Step, VerdictRow } from "../api";
import { Conf, Icon, Sev, highlightLine, pct, short } from "../lib";

const KIND_LABEL: Record<Step["kind"], string> = {
  source: "Source", flow: "Flows", call: "Calls", param: "Enters", return: "Returns", guard: "Guard",
  sanitizer: "Sanitizer", assumption: "Assumption", sink: "Sink",
};
const KIND_GLYPH: Record<Step["kind"], string> = {
  source: "S", flow: "", call: "→", param: "⤷", return: "↩", guard: "?", sanitizer: "✓", assumption: "!", sink: "!",
};

export function CodeLines({ content, line, l1, l2, span, file, onOpen }: {
  content: string; line: number; l1: number; l2: number; span?: [number, number]; file?: string; onOpen?: () => void;
}) {
  const lines = content.split("\n");
  const rows = [];
  for (let n = Math.max(1, l1); n <= Math.min(lines.length, l2); n++) {
    const focus = n === line;
    rows.push(
      <div key={n} className={`code-row${focus ? " focus" : ""}`}>
        <span className="code-ln">{n}</span>
        <span className="code-src">{highlightLine(lines[n - 1] ?? "", focus ? span : undefined)}</span>
      </div>,
    );
  }
  return (
    <div className="code">
      {file && (
        <div className="code-file">
          <Icon name="code" size={12} /> <span className="mono">{file}</span>
          {onOpen && <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={onOpen}>Open file</button>}
        </div>
      )}
      {rows}
    </div>
  );
}

function Trace({ f, onOpenFile }: { f: FindingDetail; onOpenFile: (file: string, line: number) => void }) {
  const path = f.data.path;
  return (
    <div className="trace">
      {path.map((st, i) => {
        const content = f.files[st.file]?.content ?? "";
        const span: [number, number] | undefined = st.end_line === st.line ? [st.col - 1, st.end_col - 1] : [st.col - 1, 10_000];
        const prev = path[i - 1];
        const crossed = prev && prev.fn !== st.fn;
        const guardOk = st.kind === "guard" && !!st.note;
        return (
          <div key={i} className={`t-step ${st.kind}`}>
            <div className="t-rail">
              <div className={`t-node${guardOk ? " ok" : ""}`}>{KIND_GLYPH[st.kind] || i + 1}</div>
              {i < path.length - 1 && <div className="t-line" />}
            </div>
            <div className="t-body">
              <div className="t-head">
                <span className="t-kind" style={{ color: st.kind === "source" || st.kind === "sink" ? "var(--critical-text)" : st.kind === "sanitizer" ? "var(--good-text)" : st.kind === "assumption" ? "var(--warning-text)" : "var(--text-2)" }}>
                  {KIND_LABEL[st.kind]}
                </span>
                {crossed && <span className="chip accent"><Icon name="arrow" size={11} />{short(st.fn)}()</span>}
                {i === 0 && <span className="chip">{f.source_kind || "input"}</span>}
                {st.kind === "sink" && <span className="chip bad">{f.cwe}</span>}
                <span className="grow" />
                <span className="t-loc" onClick={() => onOpenFile(st.file, st.line)} title="Open file at this line">{st.file}:{st.line}</span>
              </div>
              <CodeLines content={content} line={st.line} l1={st.line - (i === 0 ? 1 : 0)} l2={st.line} span={span} />
              {st.note && (
                <div className={`t-note ${st.kind === "sanitizer" || guardOk ? "good" : st.kind === "assumption" ? "warn" : "info"}`}>
                  <Icon name={st.kind === "assumption" ? "alert" : "check"} size={13} /> {st.note}
                </div>
              )}
              {st.other_kills.length > 0 && (
                <div className="t-note info"><Icon name="info" size={13} /> {st.other_kills.join(", ")}, but not against {f.title.toLowerCase()}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DecisionBanner({ f }: { f: FindingDetail }) {
  const by = f.data.decided_by;
  const human = f.triage_state !== "untriaged";
  const cfg = useMemo(() => {
    if (human) {
      const map: Record<string, [string, string, string]> = {
        confirmed: ["Confirmed by a reviewer", "Counts as a true positive; the engine and canaries learned from it.", "critical"],
        not_exploitable: ["Marked not exploitable", "The reviewer's structured reason was turned into engine knowledge where possible.", "good"],
        accepted_risk: ["Risk accepted", "Governance only; nothing was learned about correctness.", "warning"],
      };
      return map[f.triage_state];
    }
    switch (f.lane) {
      case "confirmed": return ["Exploitable path proved", by === "tier2" ? "The verifier agent discharged the open assumptions and the engine re-derived the flow." : "Every step is modelled: no sanitizer, no open assumption.", "critical"];
      case "review": return ["Needs your judgement", "The engine and the agent could not settle this. Your decision teaches both.", "warning"];
      case "suppressed": return ["Proved safe by the engine", `Derived mitigation: ${f.data.mitigations.map((m) => m.label).join("; ")}.`, "good"];
      case "suppressed_ai": return ["Suppressed by AI, with proof", by === "tier1" ? "A neural predicate labelled an unknown API or guard, and the engine re-derived the mitigation." : "The agent's evidence-bearing claims were re-checked and reproduced by the engine.", "good"];
      default: return ["Test-only flow", "Lives in tests or tooling; kept for completeness.", "neutral"];
    }
  }, [f, by, human]);
  const tone = cfg[2];
  const color = tone === "critical" ? "var(--critical)" : tone === "good" ? "var(--good)" : tone === "warning" ? "var(--warning)" : "var(--text-3)";
  const tiers: [string, string, boolean][] = [
    ["engine", "Engine", true],
    ["tier1", "Oracle", f.verdicts.some((v) => v.kind === "oracle")],
    ["tier2", "Agent", f.verdicts.some((v) => v.kind === "agent")],
    ["human", "Human", human],
  ];
  const decided = human ? "human" : by ?? (f.lane === "review" ? "" : "engine");
  return (
    <div className="decision">
      <div className="icon" style={{ background: color, color: tone === "warning" ? "#3a2a00" : "white" }}>
        <Icon name={tone === "good" ? "shield" : tone === "critical" ? "alert" : tone === "warning" ? "eye" : "flask"} size={17} />
      </div>
      <div>
        <h4>{cfg[0]}</h4>
        <p>{cfg[1]}</p>
      </div>
      <div className="tier-strip" aria-label="Decision tiers">
        {tiers.map(([id, label, on]) => (
          <span key={id} className={`tier${on ? " on" : ""}${decided === id ? " decided" : ""}`} title={decided === id ? "Decided here" : on ? "Consulted" : "Not needed"}>
            {decided === id && <Icon name="check" size={11} />}{label}
          </span>
        ))}
      </div>
    </div>
  );
}

function VerdictCard({ v, onCite }: { v: VerdictRow; onCite: (file: string, line: number) => void }) {
  const isOracle = v.kind === "oracle";
  const isHuman = v.kind === "human";
  const tone = v.verdict === "FALSE_POSITIVE" ? "good" : v.verdict === "TRUE_POSITIVE" ? "bad" : "warn";
  const votes = v.evidence.votes;
  if (isHuman) return null;
  return (
    <div className="card agent">
      <div className="card-h">
        <Icon name={isOracle ? "book" : "sparkle"} />
        {isOracle ? "Spec oracle (Tier 1)" : "Verifier agent (Tier 2)"}
        <span className="chip outline mono" style={{ fontWeight: 500 }}>{v.actor.split(":")[1]}</span>
        <span className="grow" />
        <span className={`verdict-badge chip ${tone}`}>
          {v.verdict === "FALSE_POSITIVE" ? "False positive" : v.verdict === "TRUE_POSITIVE" ? "True positive" : v.verdict === "NEEDS_HUMAN" ? "Needs human" : "Abstained"}
        </span>
      </div>
      <div className="card-b">
        {v.evidence.rationale && <p style={{ margin: "0 0 8px" }}>{v.evidence.rationale}</p>}
        {votes && (
          <div className="row muted" style={{ fontSize: 12 }}>
            <span className="votes" aria-label={`${votes.agree} of ${votes.k} samples agree`}>
              {Array.from({ length: votes.k }, (_, i) => <i key={i} className={i < votes.agree ? "y" : ""} />)}
            </span>
            {votes.agree}/{votes.k} samples agree
            {v.evidence.confidence != null && <>· raw confidence {pct(v.evidence.confidence)} (not used for decisions)</>}
          </div>
        )}
        {votes?.dissent && votes.dissent.length > 0 && <div className="t-note warn"><Icon name="alert" size={13} /> Dissent: {votes.dissent.join("; ")}</div>}
        {isOracle && v.evidence.labels && (
          <div className="claims">
            {v.evidence.labels.map((l) => (
              <div key={l.id} className="claim">
                <span className="claim-id">{l.id.replace("K-", "K")}</span>
                <div>
                  <div className="mono" style={{ fontSize: 12 }}>{l.pred}({(l.args as string[]).join(", ")})</div>
                  <div className="muted">{l.rationale} · confidence {pct(l.confidence)}</div>
                </div>
              </div>
            ))}
          </div>
        )}
        {v.evidence.claims && v.evidence.claims.length > 0 && (
          <div className="claims">
            {v.evidence.claims.map((c) => (
              <div key={c.id} className="claim">
                <span className="claim-id">{c.id}</span>
                <div>
                  <div>{c.statement}</div>
                  <div className="row wrap" style={{ marginTop: 4, gap: 6 }}>
                    {c.cite && (
                      <button className="cite" onClick={() => onCite(c.cite!.file, c.cite!.l1)} title={`sha256 ${c.cite.sha256.slice(0, 12)}…`}>
                        <Icon name="lock" size={10} /> {c.cite.file}:{c.cite.l1}{c.cite.l2 !== c.cite.l1 ? `-${c.cite.l2}` : ""}
                      </button>
                    )}
                    {c.fact && <span className="chip outline mono" style={{ fontSize: 11 }}>{c.fact.pred}({c.fact.args.join(", ")})</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        {v.gate.checks && (
          <div className="gates">
            <div className="section-title" style={{ margin: 0 }}>Symbolic gates {v.gate.accepted ? "· accepted" : "· not accepted"}</div>
            {v.gate.checks.map((g, i) => (
              <div key={i} className="gate">
                <span style={{ color: g.ok ? "var(--good-text)" : "var(--critical-text)" }}><Icon name={g.ok ? "check" : "x"} size={14} /></span>
                <span className="g-name">{g.gate}</span>
                <span className="text-2">{g.detail}</span>
              </div>
            ))}
          </div>
        )}
        {v.evidence.cost && <div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>{v.evidence.cost.samples} samples · {v.evidence.cost.tool_calls} tool calls · {(((v.evidence.cost.tokens_in ?? 0) + (v.evidence.cost.tokens_out ?? 0)) / 1000).toFixed(1)}k tokens</div>}
      </div>
    </div>
  );
}

function ProofTree({ node, depth = 0 }: { node: ProofNode; depth?: number }) {
  const kids = node.children ?? [];
  const label = <span>{node.atom}{node.rule ? <span className="muted"> · rule {node.rule}</span> : null}</span>;
  if (!kids.length && !node.absent) return <div style={{ marginLeft: 14 }}>{label}</div>;
  return (
    <details open={depth < 2}>
      <summary>▸ {label}</summary>
      {kids.map((k, i) => <ProofTree key={i} node={k} depth={depth + 1} />)}
      {node.absent?.map((a, i) => <div key={`a${i}`} className="absent" style={{ marginLeft: 14 }}>not {a}</div>)}
    </details>
  );
}

export function Evidence({ f, onOpenFile, onSelect }: { f: FindingDetail; onOpenFile: (file: string, line: number) => void; onSelect: (id: number) => void }) {
  const [showProof, setShowProof] = useState(false);
  const machine = f.verdicts.filter((v) => v.kind !== "human");
  const ex = f.explanation;
  const cal = f.calibration;
  return (
    <div className="evidence">
      <div className="f-head">
        <div className="row wrap" style={{ gap: 10 }}>
          <Sev s={f.severity} />
          <span className="chip mono">{f.cwe}</span>
          <span className="chip">{f.repo_id}</span>
          {f.shadow_by && <span className="chip accent" title="A knowledge item in shadow mode would suppress this finding"><Icon name="eye" size={11} />Shadow: would be suppressed by {f.shadow_by}</span>}
          {f.audit === 1 && <span className="chip warn"><Icon name="flask" size={11} />Audit sample</span>}
        </div>
        <h2 className="f-title">{f.title} <span className="muted" style={{ fontWeight: 500, fontSize: 15 }}>in {short(f.source_fn)}</span></h2>
        <div className="f-sub">
          <span className="flow-line">{short(f.source_fn)}() <Icon name="arrow" size={12} /> {short(f.sink_fn)}()</span>
          <span className="muted">·</span>
          <span className="mono muted" style={{ fontSize: 12 }}>{f.file}:{f.line}</span>
          {f.posterior != null && (f.lane === "review" || f.lane === "confirmed") && (
            <>
              <span className="muted">·</span>
              <Conf p={f.posterior} />
              <span className="muted" style={{ fontSize: 12 }}>
                {cal.calibrated ? `${pct(cal.rate)} of ${cal.n} similar findings were confirmed` : `uncalibrated (${cal.n} similar triaged)`}
              </span>
            </>
          )}
        </div>
      </div>

      <DecisionBanner f={f} />

      <div className="explain">
        <div className="card">
          <div className="card-h"><Icon name="alert" /> Why this is a finding</div>
          <div className="card-b"><ul>{ex.why.map((w, i) => <li key={i}>{w}</li>)}</ul></div>
        </div>
        <div className="card">
          <div className="card-h"><Icon name="shield" /> Why it might not be</div>
          <div className="card-b">
            {ex.why_not.length ? <ul>{ex.why_not.map((w, i) => <li key={i}>{w}</li>)}</ul> : <span className="muted">No candidate mitigation on this path. Nothing the engine can see makes it safe.</span>}
          </div>
        </div>
        {ex.counterfactual && <div className="counterfactual"><Icon name="sparkle" /> <span>{ex.counterfactual}</span></div>}
      </div>

      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-h"><Icon name="git" /> Data flow <span className="muted" style={{ fontWeight: 500 }}>· {f.data.path.length} steps across {new Set(f.data.path.map((s) => s.fn)).size} functions</span></div>
        <div className="card-b"><Trace f={f} onOpenFile={onOpenFile} /></div>
      </div>

      {machine.map((v) => <VerdictCard key={v.id} v={v} onCite={onOpenFile} />)}

      {f.related.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <div className="card-h"><Icon name="layers" /> Shares a derivation with <span className="muted" style={{ fontWeight: 500 }}>· your verdict re-ranks these</span></div>
          <div className="card-b">
            {f.related.slice(0, 6).map((r, i) => (
              <div key={i} className="related-item" onClick={() => onSelect(r.finding.id)}>
                <Sev s={r.finding.severity} />
                <span className="r-name grow ellipsis">{r.finding.title} in <b>{short(r.finding.source_fn)}</b></span>
                <span className="chip mono" style={{ fontSize: 10.5 }}>{r.hypothesis.split(":").slice(0, 2).join(":").replace("summ:", "via ").replace("asm:", "")}</span>
                <Conf p={r.finding.posterior} />
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-h">
          <Icon name="book" /> Derivation <span className="muted" style={{ fontWeight: 500 }}>· Datalog provenance</span>
          <span className="grow" />
          <button className="btn ghost sm" onClick={() => setShowProof((s) => !s)}>{showProof ? "Hide" : "Show"}</button>
        </div>
        {showProof && f.data.proof && <div className="card-b proof"><ProofTree node={f.data.proof} /></div>}
      </div>
    </div>
  );
}
