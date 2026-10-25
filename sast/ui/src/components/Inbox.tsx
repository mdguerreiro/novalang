import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, type FindingDetail, type FindingSummary, type Suggestion } from "../api";
import { Conf, Icon, LANES, Sev, short } from "../lib";
import { CodeLines, Evidence } from "./Evidence";
import { Rail, type Mode } from "./Rail";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export interface ToastFn { (msg: string, opts?: { undo?: () => void; icon?: "check" | "brain" | "layers" }): void }

function laneOf(f: FindingSummary, lane: string) {
  if (lane === "audit") return f.audit === 1 && f.lane === "suppressed_ai";
  return f.lane === lane;
}

function order(list: FindingSummary[], lane: string) {
  return [...list].sort((a, b) => {
    if (lane === "review") {
      // Information gain first: the most uncertain finding teaches the most.
      const ua = Math.abs((a.posterior ?? 0.5) - 0.5), ub = Math.abs((b.posterior ?? 0.5) - 0.5);
      if (ua !== ub) return ua - ub;
    }
    return SEV_RANK[a.severity] - SEV_RANK[b.severity] || (b.posterior ?? 0) - (a.posterior ?? 0) || a.id - b.id;
  });
}

function groupLabel(key: string) {
  const [kind, ...rest] = key.split(":");
  const subject = rest.join(":");
  switch (kind) {
    case "maybe_sanitizer": return `Unverified sanitizer: ${short(subject)}()`;
    case "unknown_api": return `Unmodelled call: ${subject}`;
    case "unknown_guard": return `Unverified validation: ${short(subject.replace(/^call:/, ""))}()`;
    case "via": return `Sink in ${short(rest[0])}() · ${rest[1]?.toUpperCase()}`;
    default: return `${short(rest[0])} · ${rest[1]?.toUpperCase()}`;
  }
}

export function Inbox({ repo, toast, refreshOverview }: { repo: string | null; toast: ToastFn; refreshOverview: () => void }) {
  const [all, setAll] = useState<FindingSummary[]>([]);
  const [lane, setLane] = useState("review");
  const [query, setQuery] = useState("");
  const [grouped, setGrouped] = useState(true);
  const [sel, setSel] = useState<number | null>(null);
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [mode, setMode] = useState<Mode>(null);
  const [reasonIdx, setReasonIdx] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [file, setFile] = useState<{ file: string; line: number } | null>(null);
  const [help, setHelp] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const undoStack = useRef<(() => Promise<void>)[]>([]);

  const load = useCallback(async () => {
    const rows = await api.findings(repo ?? undefined);
    setAll(rows);
    return rows;
  }, [repo]);

  useEffect(() => {
    load().then((rows) => {
      const firstLane = rows.some((r) => r.lane === "review") ? "review" : "confirmed";
      setLane(firstLane);
    });
  }, [load]);

  const counts = useMemo(() => Object.fromEntries(LANES.map((l) => [l.id, all.filter((f) => laneOf(f, l.id)).length])), [all]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = all.filter((f) => laneOf(f, lane)).filter((f) => !q || [f.title, f.source_fn, f.sink_fn, f.file, f.cls, f.cwe, f.repo_id].join(" ").toLowerCase().includes(q));
    const sorted = order(list, lane);
    if (!grouped) return sorted;
    // Keep groups together, ordered by their best member.
    const groups = new Map<string, FindingSummary[]>();
    for (const f of sorted) groups.set(f.group_key, [...(groups.get(f.group_key) ?? []), f]);
    return [...groups.values()].flat();
  }, [all, lane, query, grouped]);

  useEffect(() => {
    if (!visible.length) { setSel(null); setDetail(null); return; }
    if (sel == null || !visible.some((f) => f.id === sel)) setSel(visible[0].id);
  }, [visible]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (sel == null) return;
    let alive = true;
    api.finding(sel).then((d) => alive && setDetail(d));
    setMode(null);
    setReasonIdx(null);
    return () => { alive = false; };
  }, [sel]);

  const move = useCallback((delta: number) => {
    if (!visible.length) return;
    const i = Math.max(0, visible.findIndex((f) => f.id === sel));
    const next = visible[Math.min(visible.length - 1, Math.max(0, i + delta))];
    setSel(next.id);
    document.getElementById(`q-${next.id}`)?.scrollIntoView({ block: "nearest" });
  }, [visible, sel]);

  const advance = useCallback((fromId: number) => {
    const i = visible.findIndex((f) => f.id === fromId);
    const rest = visible.filter((f, j) => j > i && f.triage_state === "untriaged");
    if (rest.length) setSel(rest[0].id);
  }, [visible]);

  const afterChange = useCallback(async (fid: number) => {
    await load();
    refreshOverview();
    setDetail(await api.finding(fid));
  }, [load, refreshOverview]);

  const confirm = useCallback(async () => {
    if (!detail || busy) return;
    setBusy(true);
    const fid = detail.id;
    try {
      await api.triage(fid, { state: "confirmed" });
      undoStack.current.push(async () => { await api.triage(fid, { state: "untriaged" }); });
      const rel = detail.related.length;
      toast(`True positive: ${detail.title}, ${short(detail.source_fn)}()${rel ? `. ${rel} related re-ranked` : ""}`,
        { icon: "check", undo: () => undoLast() });
      await afterChange(fid);
      advance(fid);
    } finally { setBusy(false); }
  }, [detail, busy]); // eslint-disable-line react-hooks/exhaustive-deps

  const commit = useCallback(async (state: "not_exploitable" | "accepted_risk", s: Suggestion | null, scope: string | null, note: string) => {
    if (!detail || busy) return;
    setBusy(true);
    const fid = detail.id;
    try {
      const res = await api.triage(fid, { state, reason: s?.reason ?? (state === "accepted_risk" ? "ACCEPTED_RISK" : null), detail: s?.detail ?? {}, scope, note });
      const k = res.knowledge;
      undoStack.current.push(async () => {
        if (k) await api.setKnowledge(k.id, "retired");
        await api.triage(fid, { state: "untriaged" });
      });
      if (k && k.status === "active") {
        const repos = res.rescanned.length;
        toast(`${k.id} active: ${k.pred}(${k.args.join(", ")}). ${repos} repo${repos === 1 ? "" : "s"} re-evaluated.`, { icon: "brain", undo: () => undoLast() });
      } else if (k) {
        toast(`${k.id} in ${k.status}. Approve in Knowledge.`, { icon: "brain", undo: () => undoLast() });
      } else {
        toast(state === "accepted_risk" ? "Risk accepted" : "Not exploitable", { icon: "check", undo: () => undoLast() });
      }
      await afterChange(fid);
      setMode(null);
      advance(fid);
    } catch (e) {
      toast(`Save failed: ${(e as Error).message}`);
    } finally { setBusy(false); }
  }, [detail, busy]); // eslint-disable-line react-hooks/exhaustive-deps

  const undoLast = useCallback(async () => {
    const fn = undoStack.current.pop();
    if (!fn) return;
    await fn();
    await load();
    refreshOverview();
    if (sel != null) setDetail(await api.finding(sel));
    toast("Undone", { icon: "check" });
  }, [load, refreshOverview, sel, toast]);

  const applyToGroup = useCallback(async () => {
    if (!detail || detail.triage_state === "untriaged") { toast("Triage this finding first, then press ."); return; }
    const last = [...detail.verdicts].reverse().find((v) => v.kind === "human");
    const ids = visible.filter((f) => f.group_key === detail.group_key && f.id !== detail.id && f.triage_state === "untriaged").map((f) => f.id);
    if (!ids.length || !last) { toast("No other untriaged findings in group"); return; }
    const state = detail.triage_state as "confirmed" | "not_exploitable" | "accepted_risk";
    await api.bulk(ids, state, last.reason_code, (last.evidence.detail ?? {}) as Record<string, string>);
    undoStack.current.push(async () => { for (const id of ids) await api.triage(id, { state: "untriaged" }); });
    toast(`${state.replace("_", " ")}: ${ids.length} more in ${groupLabel(detail.group_key)}`, { icon: "layers", undo: () => undoLast() });
    await load();
    refreshOverview();
  }, [detail, visible, toast, load, refreshOverview, undoLast]);

  useEffect(() => {
    const onNext = () => move(1);
    window.addEventListener("sentinel:next", onNext);
    return () => window.removeEventListener("sentinel:next", onNext);
  }, [move]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) {
        if (e.key === "Escape") (t as HTMLInputElement).blur();
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const opts = detail?.suggestions.filter((s) => s.reason !== "ACCEPTED_RISK") ?? [];
      switch (e.key) {
        case "j": case "ArrowDown": move(1); e.preventDefault(); break;
        case "k": case "ArrowUp": move(-1); e.preventDefault(); break;
        case "c": confirm(); break;
        case "x": setMode((m) => (m === "not_exploitable" ? null : "not_exploitable")); setReasonIdx(opts.length ? 0 : null); break;
        case "a": setMode((m) => (m === "accepted_risk" ? null : "accepted_risk")); break;
        case "u": undoLast(); break;
        case ".": applyToGroup(); break;
        case "g": setGrouped((g) => !g); break;
        case "/": searchRef.current?.focus(); e.preventDefault(); break;
        case "?": setHelp((h) => !h); break;
        case "Escape": setMode(null); setFile(null); setHelp(false); break;
        case "[": case "]": {
          const ids = LANES.map((l) => l.id);
          const i = ids.indexOf(lane);
          setLane(ids[(i + (e.key === "]" ? 1 : ids.length - 1)) % ids.length]);
          break;
        }
        case "Enter":
          if (mode === "not_exploitable" && reasonIdx != null) commit("not_exploitable", opts[reasonIdx] ?? null, null, "");
          break;
        default:
          if (mode === "not_exploitable" && /^[1-9]$/.test(e.key)) {
            const i = Number(e.key) - 1;
            if (i < opts.length) setReasonIdx(i);
          }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [move, confirm, undoLast, applyToGroup, detail, mode, reasonIdx, commit, lane]);

  const inboxTotal = all.filter((f) => f.lane === "review" || (f.audit === 1 && f.lane === "suppressed_ai")).length;
  const inboxDone = all.filter((f) => (f.lane === "review" || (f.audit === 1 && f.lane === "suppressed_ai")) && f.triage_state !== "untriaged").length;
  let lastGroup = "";

  return (
    <div className="inbox">
      <section className="queue" aria-label="Findings queue">
        <div className="lanes" role="tablist">
          {LANES.map((l) => (
            <button key={l.id} role="tab" aria-selected={lane === l.id} className={`lane-tab${lane === l.id ? " active" : ""}`} onClick={() => setLane(l.id)} title={l.hint}>
              {l.label}<span className="n">{counts[l.id] ?? 0}</span>
            </button>
          ))}
        </div>
        <div className="queue-tools">
          <input ref={searchRef} className="search" placeholder="Filter" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Filter findings" />
          <button className={`btn sm${grouped ? "" : " ghost"}`} onClick={() => setGrouped((g) => !g)} title="Group by root cause (G)"><Icon name="layers" size={13} /> Root cause</button>
        </div>
        <div className="queue-list">
          {visible.length === 0 && (
            <div className="empty">
              <Icon name="check" size={28} />
              <h3>{lane === "review" ? "Nothing to review" : "Empty"}</h3>
            </div>
          )}
          {visible.map((f) => {
            const header = grouped && f.group_key !== lastGroup;
            lastGroup = f.group_key;
            return (
              <div key={f.id}>
                {header && (
                  <div className="group-h">
                    <Icon name="layers" size={12} /> <span className="grow ellipsis">{groupLabel(f.group_key)}</span>
                    <span className="muted">{visible.filter((v) => v.group_key === f.group_key).length}</span>
                  </div>
                )}
                <div id={`q-${f.id}`} className={`q-item${sel === f.id ? " sel" : ""}${f.triage_state !== "untriaged" ? " done" : ""}`} onClick={() => setSel(f.id)} role="button" aria-current={sel === f.id}>
                  <div className="q-title ellipsis"><Sev s={f.severity} /> <span className="ellipsis">{f.title}</span></div>
                  <div>{(f.lane === "review" || f.lane === "confirmed") && <Conf p={f.posterior} />}</div>
                  <div className="q-meta">
                    <span className="mono ellipsis" style={{ fontSize: 11.5 }}>{short(f.source_fn)} → {short(f.sink_fn)}</span>
                    <span className="grow" />
                    {f.triage_state !== "untriaged" && <span className="chip good" style={{ height: 18 }}><Icon name="check" size={10} />{f.triage_state.replace("_", " ")}</span>}
                    {f.shadow_by && <span className="chip accent" style={{ height: 18 }} title={`Would be suppressed by ${f.shadow_by}`}>shadow</span>}
                    {!repo && <span className="chip" style={{ height: 18 }}>{f.repo_id.replace("acme-", "")}</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        <div className="progress">
          <div className="row"><span>Reviewed</span><span className="grow" /><b>{inboxDone}/{inboxTotal}</b></div>
          <div className="progress-track"><i style={{ width: `${inboxTotal ? (inboxDone / inboxTotal) * 100 : 100}%` }} /></div>
          <div className="row muted" style={{ marginTop: 8, fontSize: 11.5, gap: 10 }}>
            <span><span className="kbd">J</span><span className="kbd">K</span> move</span>
            <span><span className="kbd">C</span> TP</span>
            <span><span className="kbd">X</span> not exploitable</span>
            <span><span className="kbd">?</span> keys</span>
          </div>
        </div>
      </section>

      {detail ? (
        <>
          <Evidence f={detail} onOpenFile={(file, line) => setFile({ file, line })} onSelect={(id) => {
            const target = all.find((x) => x.id === id);
            if (target && !laneOf(target, lane)) setLane(target.lane);
            setSel(id);
          }} />
          <Rail f={detail} mode={mode} setMode={setMode} reasonIdx={reasonIdx} setReasonIdx={setReasonIdx} onConfirm={confirm} onCommit={commit} busy={busy} />
        </>
      ) : (
        <div className="evidence"><div className="skeleton" style={{ height: 28, width: 320, marginBottom: 14 }} /><div className="skeleton" style={{ height: 120 }} /></div>
      )}

      {file && detail?.files[file.file] && (
        <div className="overlay" onClick={() => setFile(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={file.file}>
            <div className="modal-h"><Icon name="code" /> <span className="mono">{file.file}</span><span className="grow" /><span className="muted mono" style={{ fontSize: 11 }}>sha256 {detail.files[file.file]!.sha256.slice(0, 12)}…</span><button className="btn ghost sm" onClick={() => setFile(null)}><Icon name="x" /></button></div>
            <div className="modal-b code-scroll" ref={(el) => { if (el) setTimeout(() => el.querySelector(".code-row.focus")?.scrollIntoView({ block: "center" }), 0); }}>
              <CodeLines content={detail.files[file.file]!.content} line={file.line} l1={1} l2={100000} />
            </div>
          </div>
        </div>
      )}

      {help && (
        <div className="overlay" onClick={() => setHelp(false)}>
          <div className="modal" style={{ width: 620 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-h"><Icon name="keyboard" /> <b>Shortcuts</b><span className="grow" /><button className="btn ghost sm" onClick={() => setHelp(false)}><Icon name="x" /></button></div>
            <div className="shortcuts">
              {[["Next / previous", "J / K"], ["True positive", "C"], ["Not exploitable", "X"], ["Reason", "1-9"], ["Commit", "↵"],
                ["Accept risk", "A"], ["Apply to group", "."], ["Undo", "U"], ["Group by root cause", "G"], ["Switch lane", "[ / ]"],
                ["Search", "/"], ["Close", "Esc"]].map(([l, k]) => <div key={l}><span>{l}</span><span className="kbd">{k}</span></div>)}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
