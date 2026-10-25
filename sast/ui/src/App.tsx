import { useCallback, useEffect, useRef, useState } from "react";
import { api, type EventRow, type Overview } from "./api";
import { Icon, ago } from "./lib";
import { Inbox, type ToastFn } from "./components/Inbox";
import { Knowledge } from "./components/Knowledge";
import { Insights } from "./components/Insights";

type View = "inbox" | "knowledge" | "insights" | "activity";

interface Toast { id: number; msg: string; undo?: () => void; icon?: "check" | "brain" | "layers" }

function readHash(): { view: View; repo: string | null } {
  const [v, r] = location.hash.replace(/^#\/?/, "").split("/");
  const view = (["inbox", "knowledge", "insights", "activity"].includes(v) ? v : "inbox") as View;
  return { view, repo: r ? decodeURIComponent(r) : null };
}

function Activity() {
  const [rows, setRows] = useState<EventRow[]>([]);
  useEffect(() => { api.events().then(setRows); }, []);
  return (
    <div className="page">
      <div className="card"><div className="card-b">
        {rows.map((e) => (
          <div key={e.id} className="event">
            <span className="muted">{ago(e.ts)}</span>
            <span className="mono" style={{ fontSize: 11.5 }}>{e.actor}</span>
            <span><b>{e.type}</b>{e.knowledge_id ? <span className="chip" style={{ marginLeft: 6 }}>{e.knowledge_id}</span> : null}
              {e.finding_id ? <a href={`#/inbox`} style={{ marginLeft: 6 }}>finding #{e.finding_id}</a> : null}
              <span className="muted" style={{ marginLeft: 8 }}>{Object.entries(e.payload).filter(([, v]) => v != null && typeof v !== "object").slice(0, 4).map(([k, v]) => `${k}=${v}`).join(" · ")}</span></span>
          </div>
        ))}
      </div></div>
    </div>
  );
}

export function App() {
  const [{ view, repo }, setRoute] = useState(readHash);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [scanning, setScanning] = useState(false);
  const [theme, setTheme] = useState<string | null>(() => { try { return localStorage.getItem("sentinel-theme"); } catch { return null; } });
  const seq = useRef(0);
  const [inboxKey, setInboxKey] = useState(0);

  useEffect(() => {
    const on = () => setRoute(readHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme;
    try { if (theme) localStorage.setItem("sentinel-theme", theme); } catch { /* storage unavailable */ }
  }, [theme]);

  const refreshOverview = useCallback(() => { api.overview().then(setOverview); }, []);
  useEffect(refreshOverview, [refreshOverview]);

  const toast: ToastFn = useCallback((msg, opts) => {
    const id = ++seq.current;
    setToasts((t) => [...t.slice(-2), { id, msg, ...opts }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6500);
  }, []);

  const go = (v: View, r: string | null = repo) => { location.hash = `#/${v}${r ? `/${encodeURIComponent(r)}` : ""}`; };

  const rescan = async () => {
    const targets = repo ? [repo] : overview?.repos.map((r) => r.id) ?? [];
    setScanning(true);
    try {
      for (const r of targets) await api.scan(r);
      toast(`Scanned ${targets.length} repo${targets.length === 1 ? "" : "s"}`, { icon: "check" });
      refreshOverview();
      setInboxKey((k) => k + 1);
    } finally { setScanning(false); }
  };

  const inboxCount = overview?.repos.filter((r) => !repo || r.id === repo).reduce((a, r) => a + (r.lanes.review ?? 0), 0) ?? 0;
  const pending = (overview?.knowledge.shadow ?? 0) + (overview?.knowledge.candidate ?? 0);
  const titles: Record<View, string> = { inbox: "Triage", knowledge: "Knowledge", insights: "Insights", activity: "Activity" };
  const effectiveDark = theme ? theme === "dark" : window.matchMedia?.("(prefers-color-scheme: dark)").matches;

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <div className="brand"><span className="brand-mark"><Icon name="shield" size={14} stroke={2.4} /></span>Sentinel</div>
        <div className="org"><span className="org-avatar">A</span><span className="grow">{overview?.orgs[0]?.name ?? "…"}</span></div>
        <button className={`nav-item${view === "inbox" ? " active" : ""}`} onClick={() => go("inbox")}><Icon name="inbox" />Triage<span className="count">{inboxCount || ""}</span></button>
        <button className={`nav-item${view === "knowledge" ? " active" : ""}`} onClick={() => go("knowledge")}><Icon name="brain" />Knowledge<span className="count">{pending || ""}</span></button>
        <button className={`nav-item${view === "insights" ? " active" : ""}`} onClick={() => go("insights")}><Icon name="chart" />Insights</button>
        <button className={`nav-item${view === "activity" ? " active" : ""}`} onClick={() => go("activity")}><Icon name="activity" />Activity</button>
        <div className="nav-label">Repositories</div>
        <button className={`nav-item${!repo ? " active" : ""}`} onClick={() => go(view === "inbox" ? "inbox" : view, null)}><Icon name="layers" />All repositories</button>
        {overview?.repos.map((r) => (
          <button key={r.id} className={`nav-item${repo === r.id ? " active" : ""}`} onClick={() => go("inbox", r.id)}>
            <Icon name="git" />{r.name}<span className="count">{r.lanes.review ?? 0}</span>
          </button>
        ))}
        <div className="sidebar-foot">
          <span className="chip" title="Deterministic mock, no API key"><Icon name="sparkle" size={11} />Model: mock</span>
          <span className="grow" />
          <button className="btn ghost sm" onClick={() => setTheme(effectiveDark ? "light" : "dark")} aria-label="Toggle theme"><Icon name={effectiveDark ? "sun" : "moon"} size={14} /></button>
        </div>
      </nav>
      <main className="main">
        <header className="topbar">
          <h1>{titles[view]}</h1>
          {repo && <span className="chip">{repo}</span>}
          <span className="spacer" />
          {view === "inbox" && <span className="muted" style={{ fontSize: 12 }}><span className="kbd">?</span> shortcuts</span>}
          <button className="btn" onClick={rescan} disabled={scanning}>{scanning ? <span className="spinner" /> : <Icon name="play" size={13} />}Rescan</button>
        </header>
        <div className="content">
          {view === "inbox" && <Inbox key={`${repo}-${inboxKey}`} repo={repo} toast={toast} refreshOverview={refreshOverview} />}
          {view === "knowledge" && <Knowledge toast={toast} refreshOverview={refreshOverview} orgId={overview?.orgs[0]?.id ?? null} />}
          {view === "insights" && <Insights key={inboxKey} />}
          {view === "activity" && <Activity />}
        </div>
      </main>
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className="toast">
            <span className="t-icon"><Icon name={t.icon ?? "check"} /></span>
            <span className="grow">{t.msg}</span>
            {t.undo && <button onClick={() => { t.undo!(); setToasts((x) => x.filter((y) => y.id !== t.id)); }}>Undo <span style={{ opacity: .6 }}>U</span></button>}
          </div>
        ))}
      </div>
    </div>
  );
}
