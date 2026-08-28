import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import {
  api,
  type Finding,
  type LabTestReport,
  type Report,
  type Rule,
  type RuleSet,
  type Severity,
} from "./lib/api";

type Tab = "analysis" | "rules";

export default function App() {
  const [tab, setTab] = useState<Tab>("analysis");
  const [report, setReport] = useState<Report | null>(null);
  const [history, setHistory] = useState<Report[] | null>(null);
  const [ruleSets, setRuleSets] = useState<RuleSet[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  async function loadLatest() {
    try {
      setReport(await api.latest());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo cargar el análisis.");
    }
  }

  async function loadHistory() {
    try {
      setHistory(await api.history());
    } catch {
      // el historial es secundario — si falla, el reporte actual igual se ve
    }
  }

  async function loadRuleSets() {
    setRuleSets(await api.listRuleSets().catch(() => []));
  }

  useEffect(() => {
    loadLatest();
    loadHistory();
    loadRuleSets();
  }, []);

  async function handleAnalyzeNow() {
    setAnalyzing(true);
    setError(null);
    try {
      const fresh = await api.analyzeNow();
      setReport(fresh);
      await loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo correr el análisis.");
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <div className="shell">
      <div className="topbar">
        <h1>Firewall Analysis</h1>
        <span className="badge">Plugin de Asterion</span>
      </div>
      <main>
        <p className="hint">
          Lee el estado real del firewall de esta máquina (pf/Application Firewall/ufw/nftables/iptables, lo que
          esté presente) y lo convierte en hallazgos con severidad y recomendación — no solo "prendido o apagado".
          Además podés declarar reglas propias y probarlas de verdad en un Asterion Lab efímero antes de confiar
          en ellas.
        </p>

        <div className="tabs">
          <button className={`tab ${tab === "analysis" ? "active" : ""}`} onClick={() => setTab("analysis")}>
            Análisis
          </button>
          <button className={`tab ${tab === "rules" ? "active" : ""}`} onClick={() => setTab("rules")}>
            Reglas de firewall ({ruleSets.length})
          </button>
        </div>

        {error && <p className="error-text">{error}</p>}

        {tab === "analysis" && (
          <>
            {report && (
              <div className="card">
                <p className="section-title">Puntaje actual</p>
                <div className="score-row">
                  <span className="score" style={{ color: scoreColor(report.score) }}>
                    {report.score}
                  </span>
                  <span className="score-label">/ 100</span>
                </div>
                <div className="meta-row">
                  <span>Backend: {report.backend}</span>
                  <span>Presentes: {report.present.join(", ") || "ninguno"}</span>
                  <span>SO: {report.os}</span>
                  <span>{new Date(report.analyzed_at).toLocaleString()}</span>
                </div>
                <button className="primary-btn" style={{ marginTop: "1rem" }} onClick={handleAnalyzeNow} disabled={analyzing}>
                  {analyzing ? "Analizando…" : "Analizar ahora"}
                </button>

                {report.findings.length > 0 && (
                  <div style={{ marginTop: "1.25rem" }}>
                    <p className="section-title">Hallazgos por severidad</p>
                    <SeverityBars findings={report.findings} />
                  </div>
                )}

                {report.findings.map((f, i) => (
                  <FindingCard key={i} finding={f} />
                ))}

                {report.raw_summary && (
                  <>
                    <p className="section-title" style={{ marginTop: "1rem" }}>
                      Salida cruda (resumen)
                    </p>
                    <pre className="raw">{report.raw_summary}</pre>
                  </>
                )}
              </div>
            )}

            {history && history.length > 1 && (
              <div className="card">
                <p className="section-title">Puntaje en el tiempo</p>
                <ScoreSparkline history={history} />
                <div className="history-list">
                  {history.map((h, i) => (
                    <div className="history-item" key={i}>
                      <span>{new Date(h.analyzed_at).toLocaleString()}</span>
                      <span style={{ color: scoreColor(h.score) }}>
                        {h.score}/100 · {h.findings.length} hallazgo{h.findings.length === 1 ? "" : "s"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {tab === "rules" && <RuleSetsPanel ruleSets={ruleSets} onChange={loadRuleSets} />}
      </main>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className={`finding ${finding.severity}`}>
      <div className="finding-title">
        <span className={`sev-pill ${finding.severity}`}>{finding.severity}</span>
        {finding.title}
      </div>
      <div className="finding-detail">{finding.detail}</div>
      {finding.recommendation && <div className="finding-rec">→ {finding.recommendation}</div>}
    </div>
  );
}

function scoreColor(score: number): string {
  if (score >= 85) return "var(--low)";
  if (score >= 60) return "var(--medium)";
  if (score >= 35) return "var(--high)";
  return "var(--critical)";
}

// Sparkline a mano, sin librería de gráficos: un polyline SVG sobre el
// historial (más viejo a la izquierda) con un punto coloreado por
// severidad del puntaje en cada análisis — alcanza para ver la tendencia
// de un vistazo sin traer una dependencia nueva.
function ScoreSparkline({ history }: { history: Report[] }) {
  const points = [...history].reverse();
  const width = 600;
  const height = 140;
  const pad = 14;
  const n = points.length;
  const xFor = (i: number) => pad + (i * (width - pad * 2)) / Math.max(n - 1, 1);
  const yFor = (score: number) => pad + (height - pad * 2) * (1 - score / 100);
  const linePoints = points.map((p, i) => `${xFor(i)},${yFor(p.score)}`).join(" ");

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="sparkline" preserveAspectRatio="none">
      {[0, 25, 50, 75, 100].map((g) => (
        <line key={g} x1={pad} x2={width - pad} y1={yFor(g)} y2={yFor(g)} className="sparkline-grid" />
      ))}
      <polyline points={linePoints} className="sparkline-line" fill="none" />
      {points.map((p, i) => (
        <circle key={i} cx={xFor(i)} cy={yFor(p.score)} r={3.5} fill={scoreColor(p.score)} />
      ))}
    </svg>
  );
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

function SeverityBars({ findings }: { findings: Finding[] }) {
  const counts = Object.fromEntries(
    severityOrder.map((s) => [s, findings.filter((f) => f.severity === s).length]),
  ) as Record<Severity, number>;
  const max = Math.max(1, ...Object.values(counts));

  return (
    <div className="severity-bars">
      {severityOrder
        .filter((s) => counts[s] > 0)
        .map((s) => (
          <div className="severity-bar-row" key={s}>
            <span className={`sev-pill ${s}`}>{s}</span>
            <div className="severity-bar-track">
              <div className={`severity-bar-fill ${s}`} style={{ width: `${(counts[s] / max) * 100}%` }} />
            </div>
            <span className="severity-bar-count">{counts[s]}</span>
          </div>
        ))}
    </div>
  );
}

function RuleSetsPanel({ ruleSets, onChange }: { ruleSets: RuleSet[]; onChange: () => void }) {
  const [editing, setEditing] = useState<RuleSet | null>(null);
  const [creating, setCreating] = useState(false);
  const [testing, setTesting] = useState<RuleSet | null>(null);

  async function handleDelete(id: string) {
    if (!window.confirm("¿Borrar este conjunto de reglas?")) return;
    await api.deleteRuleSet(id);
    onChange();
  }

  return (
    <div className="card">
      <p className="section-title">Reglas de firewall</p>
      <p className="hint" style={{ marginBottom: "0.75rem" }}>
        Declarás las reglas que querés (mismo vocabulario que usa Asterion Lab: allow/deny, puerto, tcp/udp), y las
        probás de verdad — Asterion levanta una VM efímera, las aplica con ufw real, y otra VM chica intenta
        conectarse a cada puerto para confirmar que el resultado es el esperado. Nada de esto es simulado.
      </p>
      {ruleSets.length === 0 && <p className="hint">Todavía no hay conjuntos de reglas.</p>}
      {ruleSets.map((rs) => (
        <div className="template-item" key={rs.id}>
          <div>
            <div className="name">{rs.name}</div>
            <div className="subject">
              {rs.rules.length} regla{rs.rules.length === 1 ? "" : "s"} —{" "}
              {rs.rules.map((r) => `${r.action} ${r.port}/${r.proto ?? "tcp"}`).join(", ")}
            </div>
          </div>
          <div className="btn-row">
            <button className="small-btn" onClick={() => setTesting(rs)}>
              Probar en un Lab
            </button>
            <button className="small-btn" onClick={() => setEditing(rs)}>
              Editar
            </button>
            <button className="danger-btn" onClick={() => handleDelete(rs.id)}>
              Borrar
            </button>
          </div>
        </div>
      ))}

      <button className="small-btn" style={{ marginTop: "0.85rem" }} onClick={() => setCreating(true)}>
        + Nuevo conjunto de reglas
      </button>

      {(creating || editing) && (
        <RuleSetForm
          ruleSet={editing}
          onDone={() => {
            setCreating(false);
            setEditing(null);
            onChange();
          }}
          onCancel={() => {
            setCreating(false);
            setEditing(null);
          }}
        />
      )}

      {testing && <LabTestModal ruleSet={testing} onClose={() => setTesting(null)} />}
    </div>
  );
}

function RuleSetForm({
  ruleSet,
  onDone,
  onCancel,
}: {
  ruleSet: RuleSet | null;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(ruleSet?.name ?? "");
  const [rules, setRules] = useState<Rule[]>(ruleSet?.rules ?? [{ action: "allow", port: 22, proto: "tcp" }]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function updateRule(i: number, patch: Partial<Rule>) {
    setRules(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || rules.length === 0) return;
    setSaving(true);
    setError(null);
    try {
      if (ruleSet) {
        await api.updateRuleSet(ruleSet.id, { name, rules });
      } else {
        await api.createRuleSet({ name, rules });
      }
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "No se pudo guardar.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ marginTop: "1rem", borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: "1rem" }}>
      <label>Nombre</label>
      <input className="field" value={name} onChange={(e) => setName(e.target.value)} required />

      <label>Reglas</label>
      <div className="rule-table">
        <div className="rule-row rule-row-head">
          <span>Acción</span>
          <span>Puerto</span>
          <span>Protocolo</span>
          <span>Descripción</span>
          <span />
        </div>
        {rules.map((r, i) => (
          <div className="rule-row" key={i}>
            <select className="field" value={r.action} onChange={(e) => updateRule(i, { action: e.target.value as Rule["action"] })}>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </select>
            <input
              className="field"
              type="number"
              min={1}
              max={65535}
              value={r.port}
              onChange={(e) => updateRule(i, { port: parseInt(e.target.value, 10) || 0 })}
            />
            <select className="field" value={r.proto ?? "tcp"} onChange={(e) => updateRule(i, { proto: e.target.value as Rule["proto"] })}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <input
              className="field"
              value={r.description ?? ""}
              placeholder="opcional"
              onChange={(e) => updateRule(i, { description: e.target.value })}
            />
            <button type="button" className="danger-btn" onClick={() => setRules(rules.filter((_, j) => j !== i))}>
              ×
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        className="small-btn"
        style={{ marginTop: "0.5rem" }}
        onClick={() => setRules([...rules, { action: "allow", port: 80, proto: "tcp" }])}
      >
        + regla
      </button>

      <div className="btn-row" style={{ marginTop: "0.85rem" }}>
        <button className="primary-btn" type="submit" disabled={saving}>
          {saving ? "Guardando…" : "Guardar"}
        </button>
        <button className="small-btn" type="button" onClick={onCancel}>
          Cancelar
        </button>
      </div>
      {error && (
        <p className="error-text" style={{ marginTop: "0.5rem" }}>
          {error}
        </p>
      )}
    </form>
  );
}

function LabTestModal({ ruleSet, onClose }: { ruleSet: RuleSet; onClose: () => void }) {
  const [running, setRunning] = useState(true);
  const [result, setResult] = useState<LabTestReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .labTest(ruleSet.id)
      .then((r) => {
        if (!cancelled) setResult(r);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "No se pudo correr el laboratorio.");
      })
      .finally(() => {
        if (!cancelled) setRunning(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="modal-overlay" onClick={running ? undefined : onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <p className="section-title">Probar "{ruleSet.name}" en un Lab</p>

        {running && (
          <>
            <p className="hint">
              Corriendo un laboratorio real: VM QEMU con las reglas aplicadas por ufw, más una VM cliente probando
              cada puerto de verdad — esto puede tardar hasta un minuto. No cierres esta ventana.
            </p>
            <div className="spinner" />
          </>
        )}

        {error && <p className="error-text">{error}</p>}

        {result && (
          <>
            <p className={result.passed ? "success-text" : "error-text"} style={{ marginBottom: "0.75rem" }}>
              {result.passed ? "✓ Todas las reglas se comportaron como se esperaba." : "✗ Alguna regla no se comportó como se esperaba."}
              {" "}
              <span className="hint">({result.lab_name})</span>
            </p>
            <div className="result-list">
              {result.results.map((r, i) => (
                <div className={`result-row ${r.passed ? "ok" : "err"}`} key={i}>
                  <div>
                    <div>
                      {r.passed ? "✓" : "✗"} {r.name}
                    </div>
                    <div className="hint">
                      {r.run} → exit {r.exit_code}
                      {r.failed_why ? ` — ${r.failed_why}` : ""}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {!running && (
          <button className="primary-btn" style={{ marginTop: "1rem" }} onClick={onClose}>
            Cerrar
          </button>
        )}
      </div>
    </div>
  );
}
