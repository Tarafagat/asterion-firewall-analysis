export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  severity: Severity;
  title: string;
  detail: string;
  recommendation?: string;
}

export interface Report {
  analyzed_at: string;
  backend: string;
  present: string[];
  readable: boolean;
  os: string;
  score: number;
  findings: Finding[];
  raw_summary?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Sin barra inicial a propósito: relativo a la URL actual de la página,
  // no a la raíz del dominio. Así el mismo build funciona standalone (la
  // página vive en "/") y embebido dentro del dashboard local de Asterion
  // vía /api/plugins/<name>/proxy/ (la página vive ahí, y el navegador
  // resuelve "api/v1/x" contra ese prefijo en vez de contra la raíz).
  const res = await fetch(path.replace(/^\//, ""), init);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ? `${body.error}${body.detail ? ": " + body.detail : ""}` : `HTTP ${res.status}`);
  }
  return res.json();
}

export interface Rule {
  action: "allow" | "deny";
  port: number;
  proto?: "tcp" | "udp";
  description?: string;
}

export interface RuleSet {
  id: string;
  name: string;
  rules: Rule[];
  created_at: string;
  updated_at: string;
}

export interface LabTestResult {
  name: string;
  vm: string;
  run: string;
  output: string;
  exit_code: number;
  passed: boolean;
  failed_why?: string;
}

export interface LabTestReport {
  lab_name: string;
  passed: boolean;
  results: LabTestResult[];
}

const jsonInit = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: body !== undefined ? JSON.stringify(body) : undefined,
});

export const api = {
  latest: () => request<Report>("/api/v1/analysis"),
  analyzeNow: () => request<Report>("/api/v1/analysis", { method: "POST" }),
  history: (limit = 20) => request<Report[]>(`/api/v1/history?limit=${limit}`),
  listRuleSets: () => request<RuleSet[]>("/api/v1/rule-sets"),
  createRuleSet: (rs: Omit<RuleSet, "id" | "created_at" | "updated_at">) =>
    request<RuleSet>("/api/v1/rule-sets", jsonInit("POST", rs)),
  updateRuleSet: (id: string, rs: Omit<RuleSet, "id" | "created_at" | "updated_at">) =>
    request<RuleSet>(`/api/v1/rule-sets/${id}`, jsonInit("PUT", rs)),
  deleteRuleSet: (id: string) => request<void>(`/api/v1/rule-sets/${id}`, jsonInit("DELETE")),
  labTest: (id: string) => request<LabTestReport>(`/api/v1/rule-sets/${id}/lab-test`, jsonInit("POST")),
};
