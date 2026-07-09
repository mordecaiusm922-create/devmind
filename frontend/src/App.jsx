import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Rocket,
  Shield,
  Orbit,
  TerminalSquare,
  Database,
  Layers3,
  Activity,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  Cpu,
  Lock,
  GitBranch,
  OrbitIcon,
  Satellite,
  Loader2,
} from "lucide-react";

const C = {
  bg: "#05060a",
  panel: "rgba(10,14,22,0.86)",
  panel2: "rgba(13,18,28,0.96)",
  border: "rgba(255,255,255,0.10)",
  border2: "rgba(120,180,255,0.18)",
  text: "#eef4ff",
  muted: "#93a6c8",
  dim: "#64728f",
  blue: "#74c0ff",
  cyan: "#49f1ff",
  green: "#58f7b0",
  yellow: "#ffd46a",
  red: "#ff6f7d",
  glow: "rgba(73,241,255,0.16)",
};

const API_BASE = "https://devmind-2cej.onrender.com";

// Each scenario hits the REAL live API. Nothing here is simulated —
// the decision, risk_score, and why-chain shown are whatever the
// production engine actually returns at the moment you click "Run".
const SCENARIOS = [
  {
    id: "iam-wildcard",
    title: "IAM wildcard policy",
    surface: "Terraform",
    agent: "Codex",
    actionLabel: "apply aws_iam_policy",
    endpoint: "/evaluate-change",
    body: {
      agent_id: "codex-agent",
      change_type: "terraform_apply",
      surface: "infrastructure",
      payload: 'Action: "*" Resource: "*" Effect: Allow',
    },
  },
  {
    id: "privileged-k8s",
    title: "Privileged container manifest",
    surface: "Kubernetes",
    agent: "Claude Code",
    actionLabel: "kubectl apply privileged pod",
    endpoint: "/evaluate-change",
    body: {
      agent_id: "claude-code-agent",
      change_type: "k8s_manifest",
      surface: "kubernetes",
      payload: "privileged: true\nhostNetwork: true",
    },
  },
  {
    id: "pocketos-blast-radius",
    title: "Production volume destroy (PocketOS scenario)",
    surface: "Terraform",
    agent: "Cursor",
    actionLabel: "terraform apply -destroy",
    endpoint: "/evaluate-change",
    body: {
      agent_id: "cursor-agent",
      change_type: "terraform_apply",
      surface: "infrastructure",
      payload: "production volume destroy",
      affects_production: true,
      blast_radius: "org",
    },
  },
  {
    id: "safe-staging",
    title: "Staging deployment",
    surface: "Deployment",
    agent: "Codex",
    actionLabel: "deploy staging service",
    endpoint: "/evaluate",
    body: {
      agent_id: "codex-agent",
      tool: "deployment",
      operation: "deploy",
      payload: "deploy staging-service to staging environment",
    },
  },
];

// The MCP tools actually exposed by devmind_server.py — verified against source.
const TOOLS = [
  ["execute_command", "Run a shell command (terminal surface)"],
  ["read_file", "Read a file (filesystem surface)"],
  ["write_file", "Write a file (filesystem surface)"],
  ["delete_file", "Delete a file (filesystem surface)"],
  ["git_operation", "Git commands (git surface)"],
  ["http_request", "Outbound HTTP (network surface)"],
  ["db_query", "Database query (database surface)"],
  ["deploy", "Deployment action (deployment surface)"],
  ["session_status", "Inspect current session governance state"],
];

const toneMap = {
  blue: [C.blue, "rgba(116,192,255,0.12)"],
  cyan: [C.cyan, "rgba(73,241,255,0.12)"],
  green: [C.green, "rgba(88,247,176,0.12)"],
  yellow: [C.yellow, "rgba(255,212,106,0.12)"],
  red: [C.red, "rgba(255,111,125,0.12)"],
  dim: [C.muted, "rgba(147,166,200,0.08)"],
};

function Pill({ children, tone = "blue" }) {
  const [fg, bg] = toneMap[tone] || toneMap.blue;
  return (
    <span
      className="inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]"
      style={{ color: fg, background: bg, borderColor: "rgba(255,255,255,0.12)" }}
    >
      {children}
    </span>
  );
}

function Metric({ value, label }) {
  return (
    <div className="rounded-2xl border p-4" style={{ background: C.panel, borderColor: C.border }}>
      <div className="text-2xl font-semibold tracking-tight" style={{ color: C.text }}>{value}</div>
      <div className="mt-1 text-sm" style={{ color: C.muted }}>{label}</div>
    </div>
  );
}

function Card({ icon: Icon, title, text }) {
  return (
    <div className="rounded-2xl border p-5" style={{ background: C.panel, borderColor: C.border }}>
      <div className="flex items-center gap-3">
        <div className="rounded-xl border p-2" style={{ background: C.panel2, borderColor: C.border2 }}>
          <Icon size={18} color={C.cyan} />
        </div>
        <h3 className="text-base font-semibold" style={{ color: C.text }}>{title}</h3>
      </div>
      <p className="mt-4 text-sm leading-6" style={{ color: C.muted }}>{text}</p>
    </div>
  );
}

function decisionColor(decision) {
  if (decision === "BLOCK") return C.red;
  if (decision === "ESCALATE") return C.yellow;
  if (decision === "ALLOW") return C.green;
  return C.cyan;
}

function VerdictTag({ verdict }) {
  const tone = verdict === "BLOCK" ? "red" : verdict === "ESCALATE" ? "yellow" : verdict === "ALLOW" ? "green" : "cyan";
  return <Pill tone={tone}>{verdict || "…"}</Pill>;
}

export default function App() {
  const [activeId, setActiveId] = useState(SCENARIOS[0].id);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState([]);
  const [result, setResult] = useState(null); // real API response
  const [error, setError] = useState(null);

  const active = useMemo(() => SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0], [activeId]);

  const run = async () => {
    setRunning(true);
    setLog([]);
    setResult(null);
    setError(null);

    const pushLine = (text, color) => setLog((prev) => [...prev, { id: `${Date.now()}-${Math.random()}`, text, color }]);

    pushLine("intercept()", C.dim);
    pushLine(`agent: ${active.agent}`, C.text);
    pushLine(`surface: ${active.surface}`, C.cyan);
    pushLine(`POST ${API_BASE}${active.endpoint}`, C.text);

    const t0 = performance.now();
    try {
      const res = await fetch(`${API_BASE}${active.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(active.body),
      });
      const elapsed = Math.round(performance.now() - t0);
      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || `HTTP ${res.status}`);
        pushLine(`error: ${data.detail || res.status}`, C.red);
        setRunning(false);
        return;
      }

      pushLine(`response in ${elapsed}ms`, C.dim);
      pushLine(`decision: ${data.decision}`, decisionColor(data.decision));
      pushLine(`risk_score: ${data.risk_score}`, data.risk_score >= 70 ? C.red : data.risk_score >= 30 ? C.yellow : C.green);
      (data.why || []).forEach((w) => pushLine(`  · ${w}`, C.muted));
      pushLine(`escalation_required: ${data.escalation_required}`, C.text);
      pushLine(`audit_id: ${data.audit_id}`, C.dim);

      setResult({ ...data, elapsedMs: elapsed });
    } catch (e) {
      // Free-tier Render instances sleep when idle — first call can take 10-20s to wake up.
      pushLine("Cold start on the free instance can take up to 20s on first request — retrying helps.", C.yellow);
      setError("Could not reach the live API right now. It may be waking up from idle (free tier). Try again in a few seconds.");
    }
    setRunning(false);
  };

  const surfaceColor = (surface) => {
    if (surface === "Terraform") return C.yellow;
    if (surface === "Kubernetes") return C.blue;
    if (surface === "Deployment") return C.cyan;
    return C.muted;
  };

  return (
    <div className="min-h-screen overflow-hidden" style={{ background: C.bg, color: C.text }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500;700&display=swap');
        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body { margin: 0; font-family: Inter, system-ui, sans-serif; }
        .mono { font-family: 'IBM Plex Mono', monospace; }
        ::selection { background: rgba(73,241,255,0.24); }
      `}</style>

      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-[-210px] h-[560px] w-[860px] -translate-x-1/2 rounded-full blur-3xl" style={{ background: "radial-gradient(circle, rgba(73,241,255,0.14), transparent 72%)" }} />
        <div className="absolute right-[-140px] top-[180px] h-[260px] w-[260px] rounded-full blur-3xl" style={{ background: "radial-gradient(circle, rgba(116,192,255,0.14), transparent 70%)" }} />
      </div>

      <header className="sticky top-0 z-50 border-b backdrop-blur-2xl" style={{ background: "rgba(5,6,10,0.72)", borderColor: C.border }}>
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-2xl border p-2" style={{ background: C.panel2, borderColor: C.border2 }}>
              <Rocket size={18} color={C.cyan} />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight" style={{ color: C.text }}>DevMind</div>
              <div className="text-[11px] uppercase tracking-[0.22em]" style={{ color: C.muted }}>runtime governance for autonomous agents</div>
            </div>
          </div>
          <div className="hidden items-center gap-3 md:flex">
            <a href="#demo" className="text-sm" style={{ color: C.muted }}>Live demo</a>
            <a href="#architecture" className="text-sm" style={{ color: C.muted }}>Architecture</a>
            <a href="#tools" className="text-sm" style={{ color: C.muted }}>MCP tools</a>
            <a href="https://github.com/mordecaiusm922-create/devmind" className="text-sm" style={{ color: C.muted }}>GitHub</a>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 pb-20 pt-16">
        <section className="grid items-center gap-12 lg:grid-cols-2">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border px-4 py-2" style={{ background: C.panel, borderColor: C.border2 }}>
              <Satellite size={14} color={C.yellow} />
              <span className="mono text-[11px] uppercase tracking-[0.2em]" style={{ color: C.yellow }}>live API · deterministic · no LLM in the path</span>
            </div>

            <h1 className="max-w-xl text-5xl font-extrabold leading-[1.02] tracking-[-0.06em] md:text-6xl">
              The control plane
              <span className="block bg-gradient-to-r from-white via-cyan-200 to-blue-300 bg-clip-text text-transparent" style={{ filter: "drop-shadow(0 0 18px rgba(73,241,255,0.12))" }}>
                between agent and production.
              </span>
            </h1>

            <p className="mt-6 max-w-2xl text-base leading-7" style={{ color: C.muted }}>
              DevMind intercepts every action an AI agent attempts against real infrastructure and evaluates it before execution.
              The demo below is not a simulation — it calls the production API live, every time.
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              <a href="#demo" className="inline-flex items-center gap-2 rounded-2xl border px-5 py-3 text-sm font-semibold transition-transform hover:-translate-y-0.5" style={{ background: C.cyan, color: "#04101a", borderColor: C.cyan }}>
                Run the live demo <ArrowRight size={16} />
              </a>
              <a href="https://github.com/mordecaiusm922-create/devmind" className="inline-flex items-center gap-2 rounded-2xl border px-5 py-3 text-sm font-semibold transition-transform hover:-translate-y-0.5" style={{ background: C.panel, color: C.text, borderColor: C.border }}>
                <OrbitIcon size={16} /> View source
              </a>
            </div>

            <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-3">
              <Metric value="~50ms" label="typical policy evaluation" />
              <Metric value="178" label="deterministic tests, CI-enforced" />
              <Metric value="28" label="real-world risk scenarios" />
            </div>
          </div>

          <div className="rounded-[28px] border p-5 shadow-2xl" style={{ background: C.panel, borderColor: C.border2, boxShadow: `0 0 0 1px ${C.glow}, 0 30px 90px rgba(0,0,0,0.45)` }}>
            <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: C.border }}>
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-red-400/80" />
                <div className="h-3 w-3 rounded-full bg-yellow-300/80" />
                <div className="h-3 w-3 rounded-full bg-green-400/80" />
              </div>
              <div className="mono text-xs uppercase tracking-[0.2em]" style={{ color: C.muted }}>devmind-2cej.onrender.com</div>
              <Pill tone="green">production</Pill>
            </div>

            <div className="mt-4 rounded-2xl border p-4" style={{ borderColor: C.border, background: C.panel2 }}>
              <div className="flex items-center gap-2 mb-3">
                <Activity size={16} color={C.cyan} />
                <span className="text-sm font-semibold">What this page actually does</span>
              </div>
              <p className="text-sm leading-6" style={{ color: C.muted }}>
                Scroll to the demo section, pick a scenario, and click Run. Your browser sends a real HTTP request to
                the production DevMind API and renders whatever it actually returns — decision, risk score, and the
                exact reasoning chain. Nothing on this page is pre-recorded.
              </p>
              <p className="mt-3 text-xs" style={{ color: C.dim }}>
                Note: the API runs on a free instance and may take up to 20s to respond on the first request after being idle.
              </p>
            </div>
          </div>
        </section>

        <section id="demo" className="mt-24 grid gap-8 lg:grid-cols-[1.05fr_0.95fr]">
          <div>
            <div className="mb-6 flex items-center gap-3">
              <Pill tone="cyan">Live demo — real API</Pill>
              <span className="text-sm" style={{ color: C.muted }}>Choose a scenario, then run it against production.</span>
            </div>

            <div className="grid gap-3">
              {SCENARIOS.map((item) => {
                const isActive = item.id === activeId;
                return (
                  <motion.button
                    key={item.id}
                    whileHover={{ y: -2 }}
                    whileTap={{ scale: 0.99 }}
                    onClick={() => {
                      setActiveId(item.id);
                      setLog([]);
                      setResult(null);
                      setError(null);
                    }}
                    className="rounded-2xl border p-4 text-left transition-all"
                    style={{ background: isActive ? "rgba(73,241,255,0.08)" : C.panel, borderColor: isActive ? C.border2 : C.border }}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-base font-semibold" style={{ color: C.text }}>{item.title}</span>
                        </div>
                        <div className="mt-2 text-sm mono" style={{ color: C.muted }}>{item.actionLabel}</div>
                      </div>
                      <div className="mono text-xs" style={{ color: C.dim }}>{item.surface}</div>
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </div>

          <div className="rounded-[28px] border p-5" style={{ background: C.panel, borderColor: C.border2 }}>
            <div className="flex items-center justify-between border-b pb-4" style={{ borderColor: C.border }}>
              <div className="flex items-center gap-2">
                <TerminalSquare size={18} color={C.cyan} />
                <span className="font-semibold">Decision trace</span>
              </div>
              <button
                onClick={run}
                disabled={running}
                className="inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold transition-opacity disabled:cursor-not-allowed disabled:opacity-70"
                style={{ background: C.cyan, color: "#03101a", borderColor: C.cyan }}
              >
                {running && <Loader2 size={14} className="animate-spin" />}
                {running ? "Calling live API…" : "Run against production"}
              </button>
            </div>

            <div className="mono mt-4 rounded-2xl border p-4 text-[12px] leading-7 overflow-x-auto" style={{ minHeight: 280, background: C.panel2, borderColor: C.border }}>
              {log.length === 0 ? (
                <div style={{ color: C.dim }}>Press the button to send a real request to devmind-2cej.onrender.com.</div>
              ) : (
                log.map((line) => <div key={line.id} style={{ color: line.color, whiteSpace: "pre-wrap" }}>{line.text}</div>)
              )}
            </div>

            {error && (
              <div className="mt-4 rounded-2xl border p-4" style={{ background: "rgba(255,212,106,0.08)", borderColor: "rgba(255,212,106,0.28)" }}>
                <span className="text-sm" style={{ color: C.yellow }}>{error}</span>
              </div>
            )}

            {result && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 rounded-2xl border p-4"
                style={{
                  background: result.decision === "BLOCK" ? "rgba(255,111,125,0.08)" : result.decision === "ESCALATE" ? "rgba(255,212,106,0.08)" : "rgba(88,247,176,0.08)",
                  borderColor: result.decision === "BLOCK" ? "rgba(255,111,125,0.28)" : result.decision === "ESCALATE" ? "rgba(255,212,106,0.28)" : "rgba(88,247,176,0.28)",
                }}
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 size={18} color={decisionColor(result.decision)} />
                    <span className="text-sm font-semibold">Live outcome — audit_id {result.audit_id?.slice(0, 8)}…</span>
                  </div>
                  <VerdictTag verdict={result.decision} />
                </div>
                <p className="mt-3 text-sm leading-6" style={{ color: C.muted }}>
                  risk_score: {result.risk_score} · responded in {result.elapsedMs}ms
                </p>
              </motion.div>
            )}
          </div>
        </section>

        <section id="architecture" className="mt-24">
          <div className="mb-8">
            <Pill tone="yellow">Architecture</Pill>
            <h2 className="mt-4 text-3xl font-bold tracking-[-0.04em]">Deterministic governance across every autonomous action.</h2>
            <p className="mt-3 max-w-3xl text-sm leading-7" style={{ color: C.muted }}>
              Policy first, blast radius second, evidence third. No language model sits in the decision path —
              the same input always produces the same output.
            </p>
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Card icon={Shield} title="Deterministic control" text="Unsafe actions are stopped before execution. The decision is a code path, not a suggestion." />
            <Card icon={Layers3} title="Blast-radius scoring" text="Every action is mapped to a scope: process, service, cluster, account, or organization." />
            <Card icon={Database} title="Tamper-evident audit" text="Each decision returns a unique audit_id and a full reasoning chain, so teams can replay exactly what happened." />
            <Card icon={Orbit} title="Session memory" text="Risk accumulates across the session, making repeated low-grade violations harder to hide." />
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <div className="rounded-2xl border p-5" style={{ background: C.panel, borderColor: C.border }}>
              <div className="mb-4 flex items-center gap-2">
                <Lock size={16} color={C.yellow} />
                <h3 className="font-semibold">Threat model</h3>
              </div>
              <ul className="space-y-3 text-sm leading-6" style={{ color: C.muted }}>
                <li>• IAM wildcards that expand permissions across the org.</li>
                <li>• Privileged pods and host networking in Kubernetes.</li>
                <li>• Hardcoded secrets and private keys in payloads.</li>
                <li>• ORG/ACCOUNT-scoped changes — escalated unconditionally, no override.</li>
                <li>• Accumulated session risk from repeated low-grade violations.</li>
              </ul>
            </div>

            <div className="rounded-2xl border p-5" style={{ background: C.panel, borderColor: C.border }}>
              <div className="mb-4 flex items-center gap-2">
                <Cpu size={16} color={C.cyan} />
                <h3 className="font-semibold">Why this is not a prompt layer</h3>
              </div>
              <p className="text-sm leading-7" style={{ color: C.muted }}>
                A prompt can shape output. A control plane changes execution. This layer sits at the application
                boundary, evaluating the action itself — not asking the model to behave.
              </p>
            </div>
          </div>
        </section>

        <section id="tools" className="mt-24">
          <div className="mb-8">
            <Pill tone="blue">MCP integration</Pill>
            <h2 className="mt-4 text-3xl font-bold tracking-[-0.04em]">9 tools, exposed over MCP</h2>
            <p className="mt-3 max-w-3xl text-sm leading-7" style={{ color: C.muted }}>
              Works with any MCP-compatible client — Claude Desktop, Cursor, or your own. Governance acts on the
              action, not on which model produced it. Source: <code className="mono">devmind_server.py</code>.
            </p>
          </div>

          <div className="overflow-hidden rounded-[28px] border" style={{ background: C.panel, borderColor: C.border2 }}>
            <div className="grid grid-cols-[240px_1fr] border-b px-5 py-3 mono text-[11px] uppercase tracking-[0.18em]" style={{ color: C.dim, background: C.panel2, borderColor: C.border }}>
              <div>Tool</div>
              <div>Description</div>
            </div>
            {TOOLS.map(([tool, desc], i) => (
              <div key={tool} className="grid grid-cols-[240px_1fr] gap-6 px-5 py-4 text-sm" style={{ background: i % 2 === 0 ? "rgba(255,255,255,0.01)" : "transparent", borderTop: i === 0 ? "none" : `1px solid ${C.border}` }}>
                <div className="mono" style={{ color: C.yellow }}>{tool}</div>
                <div style={{ color: C.muted }}>{desc}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-24 grid gap-4 lg:grid-cols-3">
          <div className="rounded-2xl border p-5 lg:col-span-2" style={{ background: C.panel, borderColor: C.border }}>
            <div className="mb-4 flex items-center gap-2">
              <GitBranch size={16} color={C.cyan} />
              <h3 className="font-semibold">Control flow</h3>
            </div>
            <div className="mono text-sm leading-8" style={{ color: C.muted }}>
              <div style={{ color: C.text }}>agent tool call / infra change</div>
              <div>↓</div>
              <div style={{ color: C.cyan }}>policy_engine.evaluate_action() / infra_engine.evaluate_change()</div>
              <div>↓</div>
              <div style={{ color: C.text }}>hard blocks → blast radius gate → production escalation → risk scoring</div>
              <div>↓</div>
              <div style={{ color: C.text }}>ALLOW · REVIEW · ESCALATE · BLOCK</div>
            </div>
          </div>

          <div className="rounded-2xl border p-5" style={{ background: C.panel, borderColor: C.border }}>
            <div className="mb-4 flex items-center gap-2">
              <AlertTriangle size={16} color={C.yellow} />
              <h3 className="font-semibold">Get involved</h3>
            </div>
            <p className="text-sm leading-6 mb-4" style={{ color: C.muted }}>
              DevMind is open source and early. If you're running agents against real infrastructure, feedback on
              real edge cases is the most valuable thing you can give right now.
            </p>
            <a href="https://github.com/mordecaiusm922-create/devmind" className="inline-flex items-center gap-2 text-sm font-semibold" style={{ color: C.cyan }}>
              View on GitHub <ArrowRight size={14} />
            </a>
          </div>
        </section>
      </main>
    </div>
  );
}