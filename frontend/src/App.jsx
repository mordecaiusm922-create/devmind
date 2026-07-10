import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Rocket,
  Shield,
  Orbit,
  Terminal,
  Database,
  Layers,
  Activity,
  CheckCircle2,
  ArrowRight,
  Cpu,
  Lock,
  GitBranch,
  Satellite,
  Loader2,
  ExternalLink,
  Zap,
  Code2,
  BarChart3,
} from "lucide-react";

// --- Design tokens (Anthropic-inspired palette) ---
const tokens = {
  // Base
  bg: "#fafafa",
  surface: "#ffffff",
  surfaceAlt: "#f5f5f5",
  border: "rgba(0,0,0,0.06)",
  borderAccent: "rgba(99,102,241,0.15)",
  // Text
  text: "#0f0f0f",
  textSecondary: "#525252",
  textMuted: "#737373",
  textInverse: "#ffffff",
  // Accent
  primary: "#4f46e5",        // indigo 600
  primaryLight: "#818cf8",   // indigo 400
  accentWarm: "#f97316",     // orange 500
  accentGreen: "#059669",
  accentRed: "#dc2626",
  accentYellow: "#d97706",
  // Gradients
  gradientPrimary: "linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)",
  gradientLight: "linear-gradient(135deg, rgba(99,102,241,0.06) 0%, rgba(139,92,246,0.04) 100%)",
  // Shadows
  shadowCard: "0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.06)",
  shadowElevated: "0 10px 25px -5px rgba(0,0,0,0.08), 0 4px 10px -6px rgba(0,0,0,0.05)",
};

const API_BASE = "https://devmind-2cej.onrender.com";

const SCENARIOS = [
  {
    id: "iam-wildcard",
    title: "IAM wildcard policy",
    surface: "Terraform",
    agent: "Codex",
    actionLabel: "apply aws_iam_policy",
    endpoint: "/evaluate-change",
    body: { agent_id: "codex-agent", change_type: "terraform_apply", surface: "infrastructure", payload: 'Action: "*" Resource: "*" Effect: Allow' },
  },
  {
    id: "privileged-k8s",
    title: "Privileged container",
    surface: "Kubernetes",
    agent: "Claude Code",
    actionLabel: "kubectl apply privileged pod",
    endpoint: "/evaluate-change",
    body: { agent_id: "claude-code-agent", change_type: "k8s_manifest", surface: "kubernetes", payload: "privileged: true\nhostNetwork: true" },
  },
  {
    id: "pocketos-blast-radius",
    title: "Production volume destroy",
    surface: "Terraform",
    agent: "Cursor",
    actionLabel: "terraform apply -destroy",
    endpoint: "/evaluate-change",
    body: { agent_id: "cursor-agent", change_type: "terraform_apply", surface: "infrastructure", payload: "production volume destroy", affects_production: true, blast_radius: "org" },
  },
  {
    id: "safe-staging",
    title: "Staging deployment",
    surface: "Deployment",
    agent: "Codex",
    actionLabel: "deploy staging service",
    endpoint: "/evaluate",
    body: { agent_id: "codex-agent", tool: "deployment", operation: "deploy", payload: "deploy staging-service to staging environment" },
  },
];

const TOOLS = [
  ["execute_command", "Run a shell command"],
  ["read_file", "Read a file"],
  ["write_file", "Write a file"],
  ["delete_file", "Delete a file"],
  ["git_operation", "Git operations"],
  ["http_request", "Outbound HTTP request"],
  ["db_query", "Database query"],
  ["deploy", "Deployment action"],
  ["session_status", "Session governance state"],
];

// --- Helpers ---
const decisionColor = (d) =>
  d === "BLOCK" ? tokens.accentRed : d === "ESCALATE" ? tokens.accentYellow : d === "ALLOW" ? tokens.accentGreen : tokens.primary;

const decisionBg = (d) =>
  d === "BLOCK" ? "rgba(220,38,38,0.06)" : d === "ESCALATE" ? "rgba(217,119,6,0.06)" : d === "ALLOW" ? "rgba(5,150,105,0.06)" : "rgba(99,102,241,0.06)";

function Badge({ children, color = tokens.primary, variant = "outline" }) {
  return (
    <span
      className="inline-flex items-center rounded-full px-3 py-1 text-xs font-medium tracking-wide"
      style={{
        color,
        background: variant === "filled" ? color + "12" : "transparent",
        border: variant === "filled" ? `1px solid ${color}20` : `1px solid ${color}25`,
      }}
    >
      {children}
    </span>
  );
}

function MetricCard({ value, label, icon: Icon }) {
  return (
    <div className="flex items-start gap-3 rounded-2xl p-5" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowCard }}>
      {Icon && <Icon size={20} style={{ color: tokens.primaryLight, marginTop: 2 }} />}
      <div>
        <div className="text-2xl font-bold" style={{ color: tokens.text }}>{value}</div>
        <div className="text-sm mt-0.5" style={{ color: tokens.textMuted }}>{label}</div>
      </div>
    </div>
  );
}

function FeatureCard({ icon: Icon, title, desc }) {
  return (
    <div className="rounded-2xl p-6 transition-all hover:shadow-md" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowCard }}>
      <div className="w-10 h-10 rounded-xl flex items-center justify-center mb-4" style={{ background: tokens.gradientLight }}>
        <Icon size={20} style={{ color: tokens.primary }} />
      </div>
      <h3 className="text-base font-semibold mb-2" style={{ color: tokens.text }}>{title}</h3>
      <p className="text-sm leading-6" style={{ color: tokens.textSecondary }}>{desc}</p>
    </div>
  );
}

export default function App() {
  const [activeId, setActiveId] = useState(SCENARIOS[0].id);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const active = useMemo(() => SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0], [activeId]);

  const run = async () => {
    setRunning(true);
    setLog([]);
    setResult(null);
    setError(null);
    const pushLine = (text, color) => setLog((prev) => [...prev, { id: `${Date.now()}-${Math.random()}`, text, color }]);
    pushLine("Intercepting agent action…", tokens.textMuted);
    pushLine(`Agent: ${active.agent}`, tokens.text);
    pushLine(`Surface: ${active.surface}`, tokens.primaryLight);
    pushLine(`POST ${API_BASE}${active.endpoint}`, tokens.textSecondary);
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
        pushLine(`Error: ${data.detail || res.status}`, tokens.accentRed);
        setRunning(false);
        return;
      }
      pushLine(`Response in ${elapsed}ms`, tokens.textMuted);
      pushLine(`Decision: ${data.decision}`, decisionColor(data.decision));
      pushLine(`Risk score: ${data.risk_score}`, data.risk_score >= 70 ? tokens.accentRed : data.risk_score >= 30 ? tokens.accentYellow : tokens.accentGreen);
      (data.why || []).forEach((w) => pushLine(`  • ${w}`, tokens.textSecondary));
      pushLine(`Escalation required: ${data.escalation_required}`, tokens.text);
      pushLine(`Audit ID: ${data.audit_id}`, tokens.textMuted);
      setResult({ ...data, elapsedMs: elapsed });
    } catch (e) {
      pushLine("Cold start: free instance may need up to 20s on first request.", tokens.accentYellow);
      setError("Could not reach the API — it might be waking up from idle. Please try again.");
    }
    setRunning(false);
  };

  return (
    <div className="min-h-screen" style={{ background: tokens.bg, color: tokens.text, fontFamily: "'Inter', system-ui, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
        body { margin: 0; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        ::selection { background: rgba(99,102,241,0.2); }
      `}</style>

      {/* --- Header --- */}
      <header className="sticky top-0 z-50 backdrop-blur-xl" style={{ background: "rgba(250,250,250,0.8)", borderBottom: `1px solid ${tokens.border}` }}>
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: tokens.gradientPrimary }}>
              <Rocket size={18} style={{ color: tokens.textInverse }} />
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight" style={{ color: tokens.text }}>DevMind</div>
              <div className="text-[11px] uppercase tracking-widest" style={{ color: tokens.textMuted }}>Runtime governance</div>
            </div>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium" style={{ color: tokens.textSecondary }}>
            <a href="#demo" className="hover:text-indigo-600 transition-colors">Live demo</a>
            <a href="#architecture" className="hover:text-indigo-600 transition-colors">Architecture</a>
            <a href="#tools" className="hover:text-indigo-600 transition-colors">MCP tools</a>
            <a href="https://github.com/mordecaiusm922-create/devmind" className="inline-flex items-center gap-1.5 hover:text-indigo-600 transition-colors">
              GitHub <ExternalLink size={14} />
            </a>
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 pt-16 pb-24">
        {/* --- Hero --- */}
        <section className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-xs font-semibold uppercase tracking-wider mb-6" style={{ background: tokens.gradientLight, color: tokens.primary, border: `1px solid ${tokens.borderAccent}` }}>
              <Satellite size={14} /> Live API · Deterministic engine
            </div>
            <h1 className="text-5xl lg:text-6xl font-extrabold leading-[1.08] tracking-tight" style={{ color: tokens.text }}>
              The control plane
              <span className="block mt-1" style={{ background: tokens.gradientPrimary, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                between agent and production.
              </span>
            </h1>
            <p className="mt-6 text-lg leading-8 max-w-xl" style={{ color: tokens.textSecondary }}>
              DevMind intercepts every action an AI agent attempts against real infrastructure and evaluates it before execution.
              The demo below calls the production API — every outcome you see is a real response.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <a href="#demo" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold text-white shadow-md hover:shadow-lg transition-all" style={{ background: tokens.gradientPrimary }}>
                <Zap size={16} /> Run the live demo
              </a>
              <a href="https://github.com/mordecaiusm922-create/devmind" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold transition-all" style={{ background: tokens.surface, color: tokens.text, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowCard }}>
                <Code2 size={16} /> View source
              </a>
            </div>

            <div className="mt-10 grid grid-cols-1 sm:grid-cols-3 gap-4">
              <MetricCard value="~50ms" label="Avg. evaluation latency" icon={Activity} />
              <MetricCard value="178" label="Deterministic tests" icon={Shield} />
              <MetricCard value="28" label="Risk scenarios" icon={BarChart3} />
            </div>
          </div>

          <div className="rounded-3xl p-6 shadow-xl" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowElevated }}>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-3 h-3 rounded-full bg-red-400" />
              <div className="w-3 h-3 rounded-full bg-yellow-400" />
              <div className="w-3 h-3 rounded-full bg-green-400" />
              <span className="mono text-xs ml-2" style={{ color: tokens.textMuted }}>devmind-2cej.onrender.com</span>
              <Badge color={tokens.accentGreen} variant="filled">production</Badge>
            </div>
            <div className="rounded-2xl p-5" style={{ background: tokens.surfaceAlt, border: `1px solid ${tokens.border}` }}>
              <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Activity size={16} style={{ color: tokens.primary }} /> How the demo works
              </h3>
              <p className="text-sm leading-6" style={{ color: tokens.textSecondary }}>
                Pick a real-world scenario below, then click "Run against production". Your browser sends a direct HTTP request to the DevMind API and renders the live decision, risk score, and reasoning chain — nothing is simulated.
              </p>
              <p className="text-xs mt-3 italic" style={{ color: tokens.textMuted }}>
                Free instance may take up to 20s on the first request after idle.
              </p>
            </div>
          </div>
        </section>

        {/* --- Live Demo --- */}
        <section id="demo" className="mt-24 grid lg:grid-cols-[1fr_1.2fr] gap-8">
          <div>
            <h2 className="text-2xl font-bold mb-2 flex items-center gap-2">
              <Terminal size={24} style={{ color: tokens.primary }} /> Live demo
            </h2>
            <p className="text-sm mb-6" style={{ color: tokens.textSecondary }}>Select a scenario to test against the production engine.</p>
            <div className="space-y-3">
              {SCENARIOS.map((s) => {
                const isActive = s.id === activeId;
                return (
                  <motion.button
                    key={s.id}
                    whileHover={{ scale: 1.01 }}
                    whileTap={{ scale: 0.99 }}
                    onClick={() => { setActiveId(s.id); setLog([]); setResult(null); setError(null); }}
                    className="w-full text-left rounded-2xl p-4 transition-all duration-200"
                    style={{
                      background: isActive ? tokens.gradientLight : tokens.surface,
                      border: isActive ? `1px solid ${tokens.borderAccent}` : `1px solid ${tokens.border}`,
                      boxShadow: isActive ? tokens.shadowElevated : tokens.shadowCard,
                    }}
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <span className="font-semibold" style={{ color: tokens.text }}>{s.title}</span>
                        <div className="text-sm mono mt-1" style={{ color: tokens.textMuted }}>{s.actionLabel}</div>
                      </div>
                      <Badge color={tokens.primaryLight}>{s.surface}</Badge>
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </div>

          <div className="rounded-3xl p-6 shadow-xl" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowElevated }}>
            <div className="flex items-center justify-between mb-5">
              <h3 className="font-semibold flex items-center gap-2">
                <BarChart3 size={18} style={{ color: tokens.primary }} /> Decision trace
              </h3>
              <button
                onClick={run}
                disabled={running}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white shadow-md hover:shadow-lg transition-all disabled:opacity-70"
                style={{ background: tokens.gradientPrimary, border: "none" }}
              >
                {running && <Loader2 size={14} className="animate-spin" />}
                {running ? "Calling API…" : "Run against production"}
              </button>
            </div>

            <div
              className="mono rounded-2xl p-5 text-sm leading-7 overflow-x-auto min-h-[240px]"
              style={{ background: tokens.surfaceAlt, border: `1px solid ${tokens.border}` }}
            >
              {log.length === 0 ? (
                <span style={{ color: tokens.textMuted }}>Click the button to send a real request to the live API.</span>
              ) : (
                log.map((line) => (
                  <div key={line.id} style={{ color: line.color, whiteSpace: "pre-wrap" }}>{line.text}</div>
                ))
              )}
            </div>

            <AnimatePresence>
              {error && (
                <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="mt-4 rounded-2xl p-4" style={{ background: "rgba(217,119,6,0.06)", border: "1px solid rgba(217,119,6,0.25)" }}>
                  <span className="text-sm" style={{ color: tokens.accentYellow }}>{error}</span>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence>
              {result && (
                <motion.div
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="mt-4 rounded-2xl p-5"
                  style={{ background: decisionBg(result.decision), border: `1px solid ${decisionColor(result.decision)}20` }}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-semibold text-sm flex items-center gap-2">
                      <CheckCircle2 size={18} style={{ color: decisionColor(result.decision) }} />
                      Audit ID {result.audit_id?.slice(0, 8)}…
                    </span>
                    <Badge color={decisionColor(result.decision)} variant="filled">{result.decision}</Badge>
                  </div>
                  <p className="text-sm" style={{ color: tokens.textSecondary }}>
                    Risk score: {result.risk_score} • Responded in {result.elapsedMs}ms
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </section>

        {/* --- Architecture --- */}
        <section id="architecture" className="mt-24">
          <div className="text-center max-w-3xl mx-auto mb-12">
            <Badge color={tokens.accentYellow}>Architecture</Badge>
            <h2 className="mt-4 text-3xl font-bold tracking-tight">Deterministic governance for every autonomous action.</h2>
            <p className="mt-3 text-base leading-7" style={{ color: tokens.textSecondary }}>
              Policy first, blast radius second, evidence third. No language model sits in the decision path — the same input always produces the same output.
            </p>
          </div>
          <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-5">
            <FeatureCard icon={Shield} title="Deterministic control" desc="Unsafe actions are stopped before execution. The decision is a code path, not a suggestion." />
            <FeatureCard icon={Layers} title="Blast‑radius scoring" desc="Every action is mapped to a scope: process, service, cluster, account, or organization." />
            <FeatureCard icon={Database} title="Tamper‑evident audit" desc="Each decision returns a unique audit ID and a full reasoning chain, replayable at any time." />
            <FeatureCard icon={Orbit} title="Session memory" desc="Risk accumulates across the session, making repeated low‑grade violations harder to hide." />
          </div>
          <div className="grid md:grid-cols-2 gap-5 mt-5">
            <div className="rounded-2xl p-6" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowCard }}>
              <div className="flex items-center gap-2 mb-3">
                <Lock size={18} style={{ color: tokens.accentYellow }} />
                <h3 className="font-semibold">Threat model</h3>
              </div>
              <ul className="space-y-2 text-sm" style={{ color: tokens.textSecondary }}>
                <li>• IAM wildcards that expand permissions across the org.</li>
                <li>• Privileged pods and host networking in Kubernetes.</li>
                <li>• Hardcoded secrets and private keys in payloads.</li>
                <li>• ORG/ACCOUNT‑scoped changes — escalated unconditionally.</li>
                <li>• Accumulated session risk from repeated low‑grade violations.</li>
              </ul>
            </div>
            <div className="rounded-2xl p-6" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowCard }}>
              <div className="flex items-center gap-2 mb-3">
                <Cpu size={18} style={{ color: tokens.primary }} />
                <h3 className="font-semibold">Not a prompt layer</h3>
              </div>
              <p className="text-sm leading-7" style={{ color: tokens.textSecondary }}>
                A prompt can shape output. A control plane changes execution. This layer sits at the application boundary, evaluating the action itself — not asking the model to behave.
              </p>
            </div>
          </div>
        </section>

        {/* --- MCP Tools --- */}
        <section id="tools" className="mt-24">
          <div className="text-center max-w-3xl mx-auto mb-12">
            <Badge color={tokens.primary}>MCP integration</Badge>
            <h2 className="mt-4 text-3xl font-bold tracking-tight">9 tools, exposed over MCP</h2>
            <p className="mt-3 text-base leading-7" style={{ color: tokens.textSecondary }}>
              Works with any MCP‑compatible client — Claude Desktop, Cursor, or your own. Governance acts on the action, not on which model produced it.
            </p>
          </div>
          <div className="overflow-hidden rounded-2xl shadow-md" style={{ background: tokens.surface, border: `1px solid ${tokens.border}` }}>
            <div className="grid grid-cols-[280px_1fr] px-6 py-4 text-xs font-semibold uppercase tracking-wider" style={{ background: tokens.surfaceAlt, color: tokens.textMuted, borderBottom: `1px solid ${tokens.border}` }}>
              <div>Tool</div>
              <div>Description</div>
            </div>
            {TOOLS.map(([tool, desc], i) => (
              <div
                key={tool}
                className="grid grid-cols-[280px_1fr] px-6 py-4 text-sm items-center"
                style={{ borderBottom: i !== TOOLS.length - 1 ? `1px solid ${tokens.border}` : "none" }}
              >
                <code className="mono font-medium" style={{ color: tokens.primary }}>{tool}</code>
                <span style={{ color: tokens.textSecondary }}>{desc}</span>
              </div>
            ))}
          </div>
        </section>

        {/* --- Control flow & CTA --- */}
        <section className="mt-24 grid md:grid-cols-3 gap-5">
          <div className="md:col-span-2 rounded-2xl p-6" style={{ background: tokens.surface, border: `1px solid ${tokens.border}`, boxShadow: tokens.shadowCard }}>
            <div className="flex items-center gap-2 mb-4">
              <GitBranch size={18} style={{ color: tokens.primary }} />
              <h3 className="font-semibold">Control flow</h3>
            </div>
            <div className="mono text-sm leading-8" style={{ color: tokens.textSecondary }}>
              <div style={{ color: tokens.text }}>agent tool call / infra change</div>
              <div>↓</div>
              <div style={{ color: tokens.primary }}>policy_engine.evaluate_action() / infra_engine.evaluate_change()</div>
              <div>↓</div>
              <div style={{ color: tokens.text }}>hard blocks → blast radius gate → production escalation → risk scoring</div>
              <div>↓</div>
              <div style={{ color: tokens.text }}>ALLOW · REVIEW · ESCALATE · BLOCK</div>
            </div>
          </div>
          <div className="rounded-2xl p-6 flex flex-col justify-between" style={{ background: tokens.gradientLight, border: `1px solid ${tokens.borderAccent}` }}>
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Rocket size={18} style={{ color: tokens.primary }} />
                <h3 className="font-semibold">Get involved</h3>
              </div>
              <p className="text-sm leading-6" style={{ color: tokens.textSecondary }}>
                DevMind is open source and early. If you're running agents against real infrastructure, your feedback on real edge cases is the most valuable thing right now.
              </p>
            </div>
            <a
              href="https://github.com/mordecaiusm922-create/devmind"
              className="mt-5 inline-flex items-center gap-2 text-sm font-semibold py-2.5 px-5 rounded-xl self-start transition-all"
              style={{ background: tokens.gradientPrimary, color: tokens.textInverse, boxShadow: tokens.shadowCard }}
            >
              View on GitHub <ArrowRight size={16} />
            </a>
          </div>
        </section>
      </main>

      <footer className="border-t py-8" style={{ borderColor: tokens.border }}>
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-4 text-sm" style={{ color: tokens.textMuted }}>
          <span>DevMind · Runtime governance for autonomous agents</span>
          <div className="flex gap-6">
            <a href="https://github.com/mordecaiusm922-create/devmind" className="hover:text-indigo-600 transition-colors">GitHub</a>
            <a href="#demo" className="hover:text-indigo-600 transition-colors">Demo</a>
          </div>
        </div>
      </footer>
    </div>
  );
}