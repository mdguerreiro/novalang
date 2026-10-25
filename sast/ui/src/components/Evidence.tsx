import { useState } from "react";
import type { FindingDetail, ProofNode, Step, VerdictRow } from "../api";
import { Conf, Icon, Sev, highlightLine, pct, short } from "../lib";

const KIND_LABEL: Record<Step["kind"], string> = {
  source: "Source", flow: "Flow", call: "Call", param: "Param", return: "Return", guard: "Validation",
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
        const guardOk = st.kind === "guard" && !!st.note && st.note.startsWith("Validation");
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
                {crossed && <span className="chip accent">{short(st.fn)}()</span>}
                {st.kind === "sink" && <span className="chip bad">{f.cwe}</span>}
                <span className="grow" />
                <span className="t-loc" onClick={() => onOpenFile(st.file, st.line)} title="Open file">{st.file}:{st.line}</span>
              </div>
              <CodeLines content={content} line={st.line} l1={st.line - (i === 0 ? 1 : 0)} l2={st.line} span={span} />
              {st.note && (() => {
                const assumed = st.kind === "assumption" || st.note.startsWith("Un") || st.note.startsWith("No route") || (st.kind === "guard" && !guardOk);
                return (
                  <div className={`t-note ${assumed ? "warn" : st.kind === "sanitizer" || guardOk ? "good" : "info"}`}>
                    <Icon name={assumed ? "alert" : "check"} size={13} /> {st.note}
                  </div>
                );
              })()}
              {st.other_kills.length > 0 && (
                <div className="t-note info"><Icon name="info" size={13} /> {st.other_kills.join(", ")} (not {f.cls.toUpperCase()})</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

const STATUS: Record<string, [string, string]> = {
  confirmed: ["Open", "critical"], review: ["Review", "warning"], suppressed: ["Closed by engine", "good"],
  suppressed_ai: ["Closed by AI", "good"], test: ["Test code", "neutral"],
};
const TRIAGE: Record<string, [string, string]> = {
  confirmed: ["True positive", "critical"], not_exploitable: ["Not exploitable", "good"], accepted_risk: ["Risk accepted", "warning"],
};

function StatusRow({ f }: { f: FindingDetail }) {
  const human = f.triage_state !== "untriaged";
  const [label, tone] = human ? TRIAGE[f.triage_state] : STATUS[f.lane] ?? ["Unknown", "neutral"];
  const by = human ? "human" : f.data.decided_by ?? (f.lane === "review" ? "" : "engine");
  const tiers: [string, string, boolean][] = [
    ["engine", "Engine", true],
    ["tier1", "Oracle", f.verdicts.some((v) => v.kind === "oracle")],
    ["tier2", "Agent", f.verdicts.some((v) => v.kind === "agent")],
    ["human", "Analyst", human],
  ];
  const cls = tone === "critical" ? "bad" : tone === "good" ? "good" : tone === "warning" ? "warn" : "";
  return (
    <div className="status-row">
      <span className={`chip ${cls}`} style={{ fontWeight: 650 }}>{label}</span>
      <span className="muted">Decided by</span>
      <div className="tier-strip" aria-label="Decided by">
        {tiers.map(([id, name, on]) => (
          <span key={id} className={`tier${on ? " on" : ""}${by === id ? " decided" : ""}`}>
            {by === id && <Icon name="check" size={11} />}{name}
          </span>
        ))}
      </div>
    </div>
  );
}

const CHECK_ICON: Record<string, { icon: "check" | "alert" | "x" | "info"; color: string; label: string }> = {
  applies: { icon: "check", color: "var(--good-text)", label: "Applies" },
  unverified: { icon: "alert", color: "var(--warning-text)", label: "Unverified" },
  missing: { icon: "x", color: "var(--critical-text)", label: "None" },
  other_class: { icon: "info", color: "var(--text-3)", label: "Other class" },
};

function Explanation({ f, onOpenFile }: { f: FindingDetail; onOpenFile: (file: string, line: number) => void }) {
  const ex = f.explanation;
  return (
    <div className="explain">
      <div className="card">
        <div className="card-h">Summary</div>
        <div className="card-b">
          <dl className="kv">
            {ex.summary.map((r) => (
              <div key={r.k}>
                <dt>{r.k}</dt>
                <dd>
                  <code className="kv-code" title={r.v}>{r.v}</code>
                  {(r.loc || r.note) && (
                    <span className="kv-meta">
                      {r.loc && <button className="cite" onClick={() => { const [file, line] = r.loc.split(":"); onOpenFile(file, Number(line)); }}>{r.loc}</button>}
                      {r.note && <span className="muted">{r.note}</span>}
                    </span>
                  )}
                </dd>
              </div>
            ))}
            {ex.fix && (
              <div>
                <dt>{ex.fix.k}</dt>
                <dd>{ex.fix.v}</dd>
              </div>
            )}
          </dl>
        </div>
      </div>
      <div className="card">
        <div className="card-h">Mitigations</div>
        <div className="card-b">
          <ul className="checks">
            {ex.checks.map((c, i) => {
              const m = CHECK_ICON[c.state];
              return (
                <li key={i} title={m.label}>
                  <span style={{ color: m.color }}><Icon name={m.icon} size={14} /></span>
                  <span>{c.text}</span>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </div>
  );
}

const VERDICT: Record<string, [string, string]> = {
  FALSE_POSITIVE: ["False positive", "good"], TRUE_POSITIVE: ["True positive", "bad"],
  NEEDS_HUMAN: ["Needs analyst", "warn"], ABSTAIN: ["No verdict", "warn"],
};
const GATE_NAME: Record<string, string> = {
  citation: "Citation", votes: "Votes", discharge: "Engine re-check", alarm: "Flow exists", policy: "Policy", verdict: "Verdict",
};

function VerdictCard({ v, onCite }: { v: VerdictRow; onCite: (file: string, line: number) => void }) {
  if (v.kind === "human") return null;
  const isOracle = v.kind === "oracle";
  const [label, tone] = VERDICT[v.verdict] ?? [v.verdict, "warn"];
  const votes = v.evidence.votes;
  return (
    <div className="card agent">
      <div className="card-h">
        <Icon name={isOracle ? "book" : "sparkle"} />
        {isOracle ? "Oracle" : "Agent"}
        <span className="chip outline mono" style={{ fontWeight: 500 }}>{v.actor.split(":").slice(1).join(":")}</span>
        <span className="grow" />
        {votes && (
          <span className="row muted" style={{ fontSize: 12, gap: 6 }} title={`${votes.agree} of ${votes.k} samples agree`}>
            <span className="votes">{Array.from({ length: votes.k }, (_, i) => <i key={i} className={i < votes.agree ? "y" : ""} />)}</span>
            {votes.agree}/{votes.k}
          </span>
        )}
        <span className={`verdict-badge chip ${tone}`}>{label}</span>
      </div>
      <div className="card-b">
        {v.evidence.rationale && <p style={{ margin: "0 0 8px" }}>{v.evidence.rationale}</p>}
        {votes?.dissent && votes.dissent.length > 0 && <div className="t-note warn"><Icon name="alert" size={13} /> Dissent: {votes.dissent.join("; ")}</div>}
        {isOracle && v.evidence.labels && (
          <div className="claims">
            {v.evidence.labels.map((l) => (
              <div key={l.id} className="claim">
                <span className="claim-id">{l.id}</span>
                <div>
                  <code>{l.pred}({(l.args as string[]).join(", ")})</code>
                  <div className="muted">{l.rationale} Confidence {pct(l.confidence)}.</div>
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
                      <button className="cite" onClick={() => onCite(c.cite!.file, c.cite!.l1)} title={`sha256 ${c.cite.sha256.slice(0, 12)}`}>
                        <Icon name="lock" size={10} /> {c.cite.file}:{c.cite.l1}{c.cite.l2 !== c.cite.l1 ? `-${c.cite.l2}` : ""}
                      </button>
                    )}
                    {c.fact && <code className="chip outline">{c.fact.pred}({c.fact.args.join(", ")})</code>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        {v.gate.checks && (
          <div className="gates">
            {v.gate.checks.map((g, i) => (
              <div key={i} className="gate">
                <span style={{ color: g.ok ? "var(--good-text)" : "var(--critical-text)" }}><Icon name={g.ok ? "check" : "x"} size={14} /></span>
                <span className="g-name">{GATE_NAME[g.gate] ?? g.gate}</span>
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
  const label = <span>{node.atom}{node.rule ? <span className="muted"> rule {node.rule}</span> : null}</span>;
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
  const cal = f.calibration;
  return (
    <div className="evidence">
      <div className="f-head">
        <div className="row wrap" style={{ gap: 10 }}>
          <Sev s={f.severity} />
          <span className="chip mono">{f.cwe}</span>
          <span className="chip">{f.repo_id}</span>
          {f.shadow_by && <span className="chip accent" title="Shadow knowledge item that would close this finding"><Icon name="eye" size={11} />Shadow: {f.shadow_by}</span>}
          {f.audit === 1 && <span className="chip warn"><Icon name="flask" size={11} />Audit sample</span>}
        </div>
        <h2 className="f-title">{f.title} <span className="muted mono" style={{ fontWeight: 500, fontSize: 14 }}>{short(f.source_fn)}()</span></h2>
        <div className="f-sub">
          <span className="mono muted" style={{ fontSize: 12 }}>{f.file}:{f.line}</span>
          {f.posterior != null && (f.lane === "review" || f.lane === "confirmed") && (
            <>
              <span className="muted">·</span>
              <Conf p={f.posterior} />
              <span className="muted" style={{ fontSize: 12 }} title="Share of triaged findings in the same class and lane that were true positives">
                {cal.calibrated ? `${pct(cal.rate)} TP in ${cal.n} similar` : "not calibrated"}
              </span>
            </>
          )}
        </div>
      </div>

      <StatusRow f={f} />
      <Explanation f={f} onOpenFile={onOpenFile} />

      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-h"><Icon name="git" /> Data flow <span className="muted" style={{ fontWeight: 500 }}>{f.data.path.length} steps, {new Set(f.data.path.map((s) => s.fn)).size} functions</span></div>
        <div className="card-b"><Trace f={f} onOpenFile={onOpenFile} /></div>
      </div>

      {machine.map((v) => <VerdictCard key={v.id} v={v} onCite={onOpenFile} />)}

      {f.related.length > 0 && (
        <div className="card" style={{ marginBottom: 14 }}>
          <div className="card-h"><Icon name="layers" /> Same root cause</div>
          <div className="card-b">
            {f.related.slice(0, 6).map((r, i) => (
              <div key={i} className="related-item" onClick={() => onSelect(r.finding.id)}>
                <Sev s={r.finding.severity} />
                <span className="r-name grow ellipsis">{r.finding.title} <code>{short(r.finding.source_fn)}()</code></span>
                <span className="chip mono" style={{ fontSize: 10.5 }}>{r.hypothesis.split(":").slice(0, 2).join(":").replace("summ:", "via ").replace("asm:", "")}</span>
                <Conf p={r.finding.posterior} />
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-h">
          <Icon name="book" /> Derivation
          <span className="grow" />
          <button className="btn ghost sm" onClick={() => setShowProof((s) => !s)}>{showProof ? "Hide" : "Show"}</button>
        </div>
        {showProof && f.data.proof && <div className="card-b proof"><ProofTree node={f.data.proof} /></div>}
      </div>
    </div>
  );
}
