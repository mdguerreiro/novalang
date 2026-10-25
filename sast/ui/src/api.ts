export type Lane = "review" | "confirmed" | "suppressed" | "suppressed_ai" | "test";
export type TriageState = "untriaged" | "confirmed" | "not_exploitable" | "accepted_risk";

export interface FindingSummary {
  id: number;
  repo_id: string;
  fingerprint: string;
  cls: string;
  cwe: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  engine_status: "confirmed" | "undecided" | "mitigated" | "test_only";
  lane: Lane;
  triage_state: TriageState;
  source_fn: string;
  sink_fn: string;
  file: string;
  line: number;
  source_kind: string;
  posterior: number | null;
  group_key: string;
  group_size: number;
  shadow_by: string | null;
  audit: number;
  is_open: number;
  updated_at: number;
}

export interface Step {
  node: number;
  file: string;
  line: number;
  col: number;
  end_line: number;
  end_col: number;
  fn: string;
  kind: "source" | "flow" | "call" | "param" | "return" | "guard" | "sanitizer" | "assumption" | "sink";
  label: string;
  note: string;
  other_kills: string[];
}

export interface Citation { file: string; l1: number; l2: number; sha256: string }
export interface Claim { id: string; kind: string; statement: string; cite: Citation | null; fact: { pred: string; args: unknown[] } | null }
export interface GateCheck { gate: string; ok: boolean; detail: string }

export interface VerdictRow {
  id: number;
  actor: string;
  kind: "agent" | "oracle" | "human";
  verdict: string;
  reason_code: string | null;
  evidence: {
    claims?: Claim[];
    votes?: { k: number; agree: number; dissent?: string[] };
    confidence?: number;
    rationale?: string;
    model?: string;
    cost?: Record<string, number>;
    proposed?: { pred: string; args: unknown[]; scope: string; rationale: string }[];
    labels?: { id: string; pred: string; args: unknown[]; confidence: number; rationale: string }[];
    detail?: Record<string, string>;
    note?: string;
  };
  gate: { accepted?: boolean; lane?: string; checks?: GateCheck[] };
  created_at: number;
}

export interface Knowledge {
  id: string;
  scope: "repo" | "org" | "global";
  org_id: string | null;
  repo_id: string | null;
  pred: string;
  args: string[];
  status: "candidate" | "shadow" | "active" | "retired";
  origin: string;
  confidence: number | null;
  rationale: string | null;
  gate: { canary?: string; sanity?: string; suppresses?: number; over_budget?: boolean; impact?: ImpactRow[]; conflicts?: ImpactRow[] };
  corroborations: number;
  created_at: number;
  updated_at: number;
  relation?: string;
  links?: { relation: string; finding_id: number | null; repo_id: string; source_fn: string; cls: string; lane: string }[];
  support?: number;
  applied_to?: number[];
  shadowing?: number[];
}

export interface ImpactRow {
  repo: string;
  fingerprint: string;
  from: string;
  to: string;
  cls: string;
  source_fn: string;
  finding?: { id: number; repo_id: string; title: string; source_fn: string; file: string; line: number; lane: Lane; triage_state: TriageState };
}

export interface Suggestion { reason: string; detail: Record<string, string>; label: string }

export interface ProofNode { atom: string; rule?: number; children?: ProofNode[]; absent?: string[] }

export interface FindingDetail extends FindingSummary {
  data: {
    path: Step[];
    proof: ProofNode | null;
    mitigations: { why: unknown; label: string; knowledge: string[] }[];
    assumptions: { asm: unknown[]; label: string }[];
    source_rule: string;
    sink_rule: string;
    decided_by: "engine" | "tier1" | "tier2" | null;
  };
  files: Record<string, { content: string; sha256: string } | null>;
  verdicts: VerdictRow[];
  knowledge: Knowledge[];
  related: { hypothesis: string; finding: FindingSummary }[];
  events: { id: number; ts: number; actor: string; type: string; payload: Record<string, unknown> }[];
  explanation: {
    summary: { k: string; v: string; loc: string; note: string }[];
    checks: { state: "applies" | "unverified" | "missing" | "other_class"; text: string }[];
    fix: { k: string; v: string } | null;
  };
  suggestions: Suggestion[];
  calibration: { n: number; confirmed: number; rate: number | null; calibrated: boolean };
}

export interface Preview {
  knowledge: { pred: string; args: string[]; scope: string } | null;
  learns: boolean;
  impact: ImpactRow[];
  canary: string;
  sanity?: string;
  conflicts?: ImpactRow[];
  over_budget?: boolean;
  suppresses?: number;
}

export interface ScanStats {
  findings: number;
  lanes: Record<Lane, number>;
  decided: { engine: number; tier1: number; tier2: number; human_queue: number };
  tier0_rate: number;
  auto_rate: number;
  tier1_calls: number;
  tier1_cache_hits: number;
  tier2_calls: number;
  agent_cost: Record<string, number>;
  resolved_by_learned_knowledge: number;
  seconds: number;
}

export interface Overview {
  orgs: { id: string; name: string }[];
  repos: { id: string; name: string; org_id: string; lanes: Partial<Record<Lane, number>>; inbox: number; last_scan: { id: number; stats: ScanStats; finished_at: number } | null }[];
  knowledge: Partial<Record<Knowledge["status"], number>>;
}

export interface Insights {
  scans: { id: number; repo_id: string; started_at: number; finished_at: number; stats: ScanStats }[];
  audit: { audited: number; missed_tps: number };
  effective_fp: { shown_triaged: number; fp: number };
  verdicts: Record<string, number>;
  knowledge: { origin: string; status: string; n: number }[];
}

export interface StageScore { tp: number; fp: number; fn: number; precision: number; recall: number; missed: string[]; false_alarms: string[] }
export interface Benchmark {
  available: boolean;
  stages?: Record<string, StageScore>;
  ai_suppression?: { suppressed: number; wrongly_suppressed_tps: string[] };
  coverage?: { findings: number; human_queue: number; auto_decided: number };
  flywheel?: Record<string, { tier0_rate?: number; tier2_calls?: number; tier1_calls?: number; resolved_by_learned_knowledge?: number }>;
}

export interface EventRow { id: number; ts: number; actor: string; type: string; finding_id: number | null; knowledge_id: string | null; payload: Record<string, unknown> }

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...init });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail ?? msg; } catch { /* body was not JSON */ }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export const api = {
  overview: () => req<Overview>("/api/overview"),
  findings: (repo?: string) => req<FindingSummary[]>(`/api/findings${repo ? `?repo=${encodeURIComponent(repo)}` : ""}`),
  finding: (id: number) => req<FindingDetail>(`/api/findings/${id}`),
  preview: (id: number, reason: string, detail: Record<string, string>, scope?: string | null) =>
    req<Preview>(`/api/findings/${id}/preview`, { method: "POST", body: JSON.stringify({ reason, detail, scope }) }),
  triage: (id: number, body: { state: TriageState; reason?: string | null; detail?: Record<string, string>; scope?: string | null; note?: string }) =>
    req<{ state: string; knowledge: Knowledge | null; rescanned: { repo: string }[]; finding: FindingDetail }>(
      `/api/findings/${id}/triage`, { method: "POST", body: JSON.stringify({ actor: "human:you", ...body }) }),
  bulk: (ids: number[], state: TriageState, reason?: string | null, detail?: Record<string, string>) =>
    req<{ count: number }>("/api/findings/bulk", { method: "POST", body: JSON.stringify({ ids, state, reason, detail, actor: "human:you" }) }),
  knowledge: () => req<Knowledge[]>("/api/knowledge"),
  setKnowledge: (id: string, status: string) =>
    req<Knowledge>(`/api/knowledge/${id}`, { method: "POST", body: JSON.stringify({ status, actor: "human:you" }) }),
  previewKnowledge: (id: string) => req<Preview & { impact: ImpactRow[] }>(`/api/knowledge/${id}/preview`, { method: "POST" }),
  scan: (repo: string) => req<ScanStats>(`/api/scan/${repo}`, { method: "POST" }),
  insights: () => req<Insights>("/api/insights"),
  events: () => req<EventRow[]>("/api/events"),
  benchmark: () => req<Benchmark>("/api/benchmark"),
};
