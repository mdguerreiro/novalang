import { Fragment, type ReactNode } from "react";

const KW = new Set(("False None True and as assert async await break class continue def del elif else except finally for from " +
  "global if import in is lambda nonlocal not or pass raise return try while with yield").split(" "));
const TOKEN = /(#.*$)|("""[\s\S]*?"""|'''[\s\S]*?'''|[rbfuRBFU]{0,2}"(?:\\.|[^"\\])*"|[rbfuRBFU]{0,2}'(?:\\.|[^'\\])*')|(@[\w.]+)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_]\w*\b)(?=\s*\()|(\b[A-Za-z_]\w*\b)/gm;

/** Minimal Python highlighter: returns spans with token classes for one line. */
export function highlightLine(line: string, hl?: [number, number]): ReactNode {
  const parts: { text: string; cls?: string; start: number }[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(line))) {
    if (m.index > last) parts.push({ text: line.slice(last, m.index), start: last });
    const cls = m[1] ? "tk-com" : m[2] ? "tk-str" : m[3] ? "tk-dec" : m[4] ? "tk-num" : m[5] ? (KW.has(m[5]) ? "tk-kw" : "tk-fn") : m[6] && KW.has(m[6]) ? "tk-kw" : undefined;
    parts.push({ text: m[0], cls, start: m.index });
    last = m.index + m[0].length;
  }
  if (last < line.length) parts.push({ text: line.slice(last), start: last });
  if (!hl) return parts.map((p, i) => <span key={i} className={p.cls}>{p.text}</span>);
  // Split tokens at the highlight boundaries so the exact span gets the marker.
  const [a, b] = hl;
  const out: ReactNode[] = [];
  parts.forEach((p, i) => {
    const s = p.start, e = p.start + p.text.length;
    const cuts = [s, Math.max(s, Math.min(e, a)), Math.max(s, Math.min(e, b)), e];
    for (let j = 0; j < 3; j++) {
      const t = line.slice(cuts[j], cuts[j + 1]);
      if (!t) continue;
      const inside = j === 1;
      out.push(<span key={`${i}-${j}`} className={[p.cls, inside ? "hl" : ""].filter(Boolean).join(" ") || undefined}>{t}</span>);
    }
  });
  return <Fragment>{out}</Fragment>;
}

export const short = (fn: string) => (fn ? fn.split(".").pop()! : "");
export const pct = (x: number | null | undefined, digits = 0) => (x == null ? "n/a" : `${(x * 100).toFixed(digits)}%`);
export const ago = (ts: number) => {
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

export const LANES: { id: string; label: string; hint: string }[] = [
  { id: "review", label: "Review", hint: "Undecided. Needs an analyst." },
  { id: "confirmed", label: "Open", hint: "Exploitable path, no open assumptions." },
  { id: "audit", label: "Audit", hint: "Random sample of AI closures." },
  { id: "suppressed_ai", label: "Closed by AI", hint: "Closed by oracle or agent, re-derived by the engine." },
  { id: "suppressed", label: "Closed by engine", hint: "Mitigation proven by the engine." },
  { id: "test", label: "Tests", hint: "Flow only in test code." },
];

/** Human-readable statement of a knowledge fact. */
export function knowledgeStatement(pred: string, args: string[]): string {
  const cls = (c: string) => (c === "all" ? "all classes" : c.toUpperCase());
  const name = (s: string) => s.replace(/^call:/, "");
  switch (pred) {
    case "sanitizer_api": return `${name(args[0])} sanitizes ${cls(args[1])}`;
    case "propagator_api": return `${name(args[0])} propagates taint`;
    case "safe_pred": return `${name(args[0])} validates ${cls(args[1])}`;
    case "not_safe_pred": return `${name(args[0])} is not a validator`;
    case "safe_type": return `Type ${args[0]} is safe for ${cls(args[1])}`;
    case "dead_fn": return `${short(args[0])}() is dead code`;
    case "internal_only": return `${short(args[0])}() is internal only`;
    case "not_sanitizer": return `${short(args[0])}() is not a sanitizer`;
    case "sink_api": return `${name(args[0])} arg ${args[1]} is a ${cls(args[2])} sink`;
    case "not_sink_api": return `${name(args[0])} is not a sink`;
    case "framework_source": return `@${name(args[0])} handlers take request input`;
    case "not_framework_source": return `@${name(args[0])} is not a request handler`;
    case "entry_source": return `${short(args[0])}() param ${args[1]} is ${args[2]} input`;
    case "not_entry": return `${short(args[0])}() is not an entry point`;
    case "registrar": return `${name(args[0])} registers request handlers`;
    case "not_registrar": return `${name(args[0])} does not register handlers`;
    case "spec_rule": return `${args[1][0].toUpperCase()}${args[1].slice(1)} rule: ${args[0].replace(/^spec\.(learned\.)?(R-\d+\.)?/, "")}${args[2] ? ` (${args[2].toUpperCase()})` : ""}`;
    default: return `${pred}(${args.join(", ")})`;
  }
}

export function originLabel(origin: string): { who: string; kind: "human" | "agent" | "oracle" | "curated" } {
  const [k, rest] = origin.split(":");
  if (k === "human") return { who: rest === "you" ? "You" : rest, kind: "human" };
  if (k === "agent") return { who: "Agent", kind: "agent" };
  if (k === "oracle") return { who: "Oracle", kind: "oracle" };
  return { who: "Curated", kind: "curated" };
}

export function Sev({ s }: { s: string }) {
  return <span className={`sev ${s}`}><span className="bar" />{s}</span>;
}

export function Conf({ p }: { p: number | null }) {
  if (p == null) return null;
  return (
    <span className="conf" title="Probability of true positive">
      <span className="conf-bar"><i style={{ width: `${Math.round(p * 100)}%` }} /></span>
      {Math.round(p * 100)}%
    </span>
  );
}

type IconName = "inbox" | "list" | "brain" | "chart" | "activity" | "shield" | "check" | "x" | "alert" | "sparkle" | "code" |
  "arrow" | "git" | "undo" | "eye" | "book" | "play" | "sun" | "moon" | "keyboard" | "layers" | "flask" | "lock" | "info";

const PATHS: Record<IconName, string> = {
  inbox: "M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  brain: "M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Zm0 0a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Zm0-13v18",
  chart: "M3 3v18h18M7 16l4-6 4 3 5-7",
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  check: "M20 6 9 17l-5-5",
  x: "M18 6 6 18M6 6l12 12",
  alert: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01",
  sparkle: "M12 3l1.9 5.6L19.5 10l-5.6 1.9L12 17.5l-1.9-5.6L4.5 10l5.6-1.4z",
  code: "m16 18 6-6-6-6M8 6l-6 6 6 6",
  arrow: "M5 12h14M13 6l6 6-6 6",
  git: "M6 3v12M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 9a9 9 0 0 1-9 9",
  undo: "M3 7v6h6M21 17a9 9 0 0 0-15-6.7L3 13",
  eye: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  book: "M4 19.5A2.5 2.5 0 0 1 6.5 17H20V2H6.5A2.5 2.5 0 0 0 4 4.5v15zM20 17v5H6.5A2.5 2.5 0 0 1 4 19.5",
  play: "m5 3 14 9-14 9V3z",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42",
  moon: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z",
  keyboard: "M2 6h20v12H2zM6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10",
  layers: "m12 2 10 5-10 5L2 7l10-5zM2 17l10 5 10-5M2 12l10 5 10-5",
  flask: "M9 3h6M10 3v6L4 20a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 20l-6-11V3",
  lock: "M5 11h14v10H5zM8 11V7a4 4 0 1 1 8 0v4",
  info: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01",
};

export function Icon({ name, size = 15, stroke = 2 }: { name: IconName; size?: number; stroke?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  );
}
