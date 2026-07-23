import React, { useMemo, useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Rocket,
  Shield,
  Layers,
  Database,
  Activity,
  CheckCircle2,
  ArrowRight,
  Cpu,
  Lock,
  GitBranch,
  Loader2,
  Zap,
  Code2,
  BarChart3,
  ExternalLink,
  Terminal,
  Gauge,
  ScanLine,
} from "lucide-react";

// â”€â”€â”€ Design Tokens â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const T = {
  bg:       "#080c12",
  surface:  "#10161e",
  surface2: "#161c26",
  border:   "rgba(148,163,184,0.07)",
  borderA:  "rgba(45,212,191,0.14)",
  text:     "#e6edf3",
  text2:    "#8b9bb4",
  text3:    "#5c6e82",
  accent:   "#2dd4bf",
  accent2:  "#14b8a6",
  amber:    "#f59e0b",
  red:      "#ef4444",
  green:    "#10b981",
  glow:     "rgba(45,212,191,0.10)",
};

const API_BASE = "https://devmind-2cej.onrender.com";

const SCENARIOS = [
  { id: "iam-wildcard",    title: "IAM wildcard policy",              surface: "Terraform",   agent: "Codex",      actionLabel: "apply aws_iam_policy",      endpoint: "/evaluate-change", body: { agent_id:"codex-agent",       change_type:"terraform_apply", surface:"infrastructure", payload:'Action: "*" Resource: "*" Effect: Allow' } },
  { id: "privileged-k8s",  title: "Privileged container",            surface: "Kubernetes",  agent: "Claude Code", actionLabel: "kubectl apply privileged pod", endpoint: "/evaluate-change", body: { agent_id:"claude-code-agent",  change_type:"k8s_manifest",    surface:"kubernetes",     payload:"privileged: true\nhostNetwork: true" } },
  { id: "pocketos-blast",  title: "Production volume destroy",       surface: "Terraform",   agent: "Cursor",      actionLabel: "terraform apply -destroy",   endpoint: "/evaluate-change", body: { agent_id:"cursor-agent",      change_type:"terraform_apply", surface:"infrastructure", payload:"production volume destroy", affects_production:true, blast_radius:"org" } },
  { id: "safe-staging",    title: "Staging deployment",              surface: "Deployment",  agent: "Codex",      actionLabel: "deploy staging service",     endpoint: "/evaluate",         body: { agent_id:"codex-agent",       tool:"deployment", operation:"deploy", payload:"deploy staging-service to staging environment" } },
];

const TOOLS = [
  ["execute_command","Run a shell command (terminal surface)"],
  ["read_file","Read a file (filesystem surface)"],
  ["write_file","Write a file (filesystem surface)"],
  ["delete_file","Delete a file (filesystem surface)"],
  ["git_operation","Git commands (git surface)"],
  ["http_request","Outbound HTTP request (network surface)"],
  ["db_query","Database query (database surface)"],
  ["deploy","Deployment action (deployment surface)"],
  ["session_status","Inspect current session governance state"],
];

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const decisionClr = d => d==="BLOCK"?T.red : d==="ESCALATE"?T.amber : d==="ALLOW"?T.green : T.accent;
const decisionBg  = d => d==="BLOCK"?"rgba(239,68,68,0.06)" : d==="ESCALATE"?"rgba(245,158,11,0.06)" : d==="ALLOW"?"rgba(16,185,129,0.06)" : "rgba(45,212,191,0.06)";

function Badge({ children, color = T.accent, filled = false }) {
  return (
    <span className="inline-flex items-center rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]" style={{
      color: filled ? T.bg : color,
      background: filled ? color : "transparent",
      border: `1px solid ${color}28`,
    }}>{children}</span>
  );
}

function Metric({ value, label }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="text-3xl font-bold tracking-tight" style={{ color: T.text, fontFamily: "'Sora', sans-serif" }}>{value}</span>
      <span className="text-sm" style={{ color: T.text3 }}>{label}</span>
    </div>
  );
}

// â”€â”€â”€ Background Scan Lines â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function ScanLines() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-[0.03]" aria-hidden="true">
      <div className="absolute inset-0" style={{
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(45,212,191,1) 2px, rgba(45,212,191,1) 3px)",
        maskImage: "radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 70%)",
        WebkitMaskImage: "radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 70%)",
      }} />
      <motion.div
        className="absolute left-0 right-0 h-[3px]"
        style={{ background: T.accent, boxShadow: `0 0 40px ${T.accent}, 0 0 80px ${T.accent}` }}
        animate={{ top: ["-2%", "102%"] }}
        transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
      />
    </div>
  );
}

// â”€â”€â”€ Live Ticker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function LiveTicker() {
  const [dots, setDots] = useState("");
  useEffect(() => { const i = setInterval(() => setDots(p => p.length >= 3 ? "" : p + "."), 600); return () => clearInterval(i); }, []);
  return (
    <div className="flex items-center gap-2 text-xs" style={{ color: T.accent }}>
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ background: T.accent }} />
        <span className="relative inline-flex rounded-full h-2 w-2" style={{ background: T.accent }} />
      </span>
      <span className="mono tracking-wider">SYSTEM LIVE{dots}</span>
    </div>
  );
}

// â”€â”€â”€ App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export default function App() {
  const [activeId, setActiveId] = useState(SCENARIOS[0].id);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const terminalRef = useRef(null);

  const active = useMemo(() => SCENARIOS.find(s => s.id === activeId) ?? SCENARIOS[0], [activeId]);

  // Auto-scroll terminal
  useEffect(() => { if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight; }, [log]);

  const run = async () => {
    setRunning(true); setLog([]); setResult(null); setError(null);
    const push = (t, c) => setLog(p => [...p, { id: Math.random().toString(36), text: t, color: c }]);
    push("â–¸ intercept()", T.text3);
    push(`  agent   : ${active.agent}`, T.text2);
    push(`  surface : ${active.surface}`, T.accent);
    push(`  POST    : ${API_BASE}${active.endpoint}`, T.text3);
    push("", "transparent");
    const t0 = performance.now();
    try {
      const res = await fetch(`${API_BASE}${active.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(active.body),
      });
      const ms = Math.round(performance.now() - t0);
      const data = await res.json();
      if (!res.ok) { setError(data.detail || `HTTP ${res.status}`); push(`âœ— error: ${data.detail || res.status}`, T.red); setRunning(false); return; }
      push(`â—‚ response  ${ms}ms`, T.text3);
      push(`  decision : ${data.decision}`, decisionClr(data.decision));
      push(`  score    : ${data.risk_score}`, data.risk_score >= 70 ? T.red : data.risk_score >= 30 ? T.amber : T.green);
      (data.why || []).forEach(w => push(`    â€¢ ${w}`, T.text2));
      push(`  escalate : ${data.escalation_required}`, T.text);
      push(`  audit_id : ${data.audit_id}`, T.text3);
      setResult({ ...data, elapsedMs: ms });
    } catch (e) {
      push("âš  Cold start â€” free instance may take up to 20s", T.amber);
      setError("Could not reach the API. It may be waking up from idle. Please try again.");
    }
    setRunning(false);
  };

  const reset = () => { setLog([]); setResult(null); setError(null); };

  return (
    <div className="min-h-screen" style={{ background: T.bg, color: T.text, fontFamily: "'Inter', system-ui, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Sora:wght@500;600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
        body { margin: 0; -webkit-font-smoothing: antialiased; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        ::selection { background: rgba(45,212,191,0.25); color: ${T.text}; }
        html { scroll-behavior: smooth; }
      `}</style>

      {/* â”€â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <header className="sticky top-0 z-50 backdrop-blur-xl" style={{ background: "rgba(8,12,18,0.82)", borderBottom: `1px solid ${T.border}` }}>
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: T.accent }}>
              <Rocket size={16} style={{ color: T.bg }} />
            </div>
            <span className="text-sm font-bold tracking-tight mono">DevMind</span>
          </div>
          <div className="flex items-center gap-6">
            <LiveTicker />
            <nav className="hidden md:flex items-center gap-6 text-sm font-medium" style={{ color: T.text2 }}>
              <a href="#demo" className="hover:text-teal-400 transition-colors">Demo</a>
              <a href="#arch" className="hover:text-teal-400 transition-colors">Architecture</a>
              <a href="#tools" className="hover:text-teal-400 transition-colors">MCP</a>
              <a href="https://github.com/mordecaiusm922-create/devmind" className="inline-flex items-center gap-1.5 hover:text-teal-400 transition-colors">
                GitHub <ExternalLink size={13} />
              </a>
            </nav>
          </div>
        </div>
      </header>

      {/* â”€â”€â”€ Hero â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <section className="relative overflow-hidden">
        <ScanLines />
        <div className="relative max-w-6xl mx-auto px-6 pt-20 pb-24">
          <div className="grid lg:grid-cols-[1fr_1.1fr] gap-16 items-start">
            {/* Left column â€” thesis */}
            <div className="pt-6">
              <div className="inline-flex items-center gap-2 rounded-full px-4 py-1.5 mb-8 text-xs font-semibold uppercase tracking-widest" style={{ background: T.surface, border: `1px solid ${T.borderA}`, color: T.accent }}>
                <ScanLine size={13} /> Runtime Governance Engine
              </div>

              <h1 className="text-5xl lg:text-6xl font-extrabold leading-[1.06] tracking-[-0.04em]" style={{ fontFamily: "'Sora', sans-serif" }}>
                The control plane
                <br />
                <span style={{ color: T.accent }}>between agent</span>
                <span className="block" style={{ color: T.text2 }}>and production.</span>
              </h1>

              <p className="mt-6 text-base leading-7 max-w-lg" style={{ color: T.text2 }}>
                DevMind intercepts every action an AI agent attempts against real infrastructure
                and evaluates it deterministically before execution. No language model in the
                decision path â€” the same input always produces the same output.
              </p>

              <div className="mt-10 flex items-center gap-6 flex-wrap">
                <Metric value="~50ms" label="avg. evaluation" />
                <div className="w-px h-8" style={{ background: T.border }} />
                <Metric value="182" label="tests, CI-enforced" />
                <div className="w-px h-8" style={{ background: T.border }} />
                <Metric value="28" label="risk scenarios" />
              </div>

              <div className="mt-8 flex gap-3">
                <a href="https://github.com/mordecaiusm922-create/devmind" className="inline-flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all hover:-translate-y-0.5" style={{ background: T.surface, border: `1px solid ${T.border}`, color: T.text }}>
                  <Code2 size={15} /> View source
                </a>
                <a href="https://devmind-2cej.onrender.com/health" className="inline-flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all hover:-translate-y-0.5" style={{ border: `1px solid ${T.borderA}`, color: T.accent }}>
                  <Activity size={15} /> API health
                </a>
              </div>
            </div>

            {/* Right column â€” live terminal demo IN the hero */}
            <div id="demo" className="rounded-2xl overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}`, boxShadow: `0 0 0 1px ${T.glow}, 0 20px 60px rgba(0,0,0,0.4)` }}>
              {/* Terminal chrome */}
              <div className="flex items-center justify-between px-5 py-3" style={{ background: T.surface2, borderBottom: `1px solid ${T.border}` }}>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ background: "#ef4444" }} />
                  <div className="w-3 h-3 rounded-full" style={{ background: "#f59e0b" }} />
                  <div className="w-3 h-3 rounded-full" style={{ background: "#10b981" }} />
                </div>
                <div className="flex items-center gap-3">
                  <span className="mono text-[11px] tracking-wider" style={{ color: T.text3 }}>devmind-2cej.onrender.com</span>
                  <Badge color={T.green} filled>live</Badge>
                </div>
              </div>

              {/* Scenario selector */}
              <div className="grid grid-cols-2 gap-px p-2" style={{ background: T.surface2 }}>
                {SCENARIOS.map(s => {
                  const active = s.id === activeId;
                  return (
                    <button
                      key={s.id}
                      onClick={() => { setActiveId(s.id); reset(); }}
                      className="text-left px-4 py-3 rounded-xl transition-all duration-200"
                      style={{
                        background: active ? T.surface : "transparent",
                        border: active ? `1px solid ${T.borderA}` : "1px solid transparent",
                      }}
                    >
                      <div className="text-xs font-semibold" style={{ color: active ? T.text : T.text2 }}>{s.title}</div>
                      <div className="text-[10px] mono mt-0.5" style={{ color: T.text3 }}>{s.surface} Â· {s.agent}</div>
                    </button>
                  );
                })}
              </div>

              {/* Terminal output */}
              <div
                ref={terminalRef}
                className="mono text-[12px] leading-7 px-5 py-4 overflow-y-auto"
                style={{ height: 260, background: T.bg, color: T.text2 }}
              >
                {log.length === 0 && (
                  <div style={{ color: T.text3 }}>
                    <div>Select a scenario and run it against the production API.</div>
                    <div className="mt-2">Every response below is a real, live decision.</div>
                  </div>
                )}
                {log.map(l => (
                  <div key={l.id} style={{ color: l.color, whiteSpace: "pre-wrap", minHeight: l.text === "" ? "0.5em" : "auto" }}>
                    {l.text || "\u00A0"}
                  </div>
                ))}

                {/* Result card inline */}
                <AnimatePresence>
                  {result && (
                    <motion.div
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0 }}
                      className="mt-3 rounded-xl p-4"
                      style={{ background: decisionBg(result.decision), border: `1px solid ${decisionClr(result.decision)}20` }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-xs flex items-center gap-1.5" style={{ color: decisionClr(result.decision) }}>
                          <CheckCircle2 size={14} /> {result.decision}
                        </span>
                        <span className="text-[10px] mono" style={{ color: T.text3 }}>audit: {result.audit_id?.slice(0, 12)}</span>
                      </div>
                      <div className="text-[11px] mt-1" style={{ color: T.text3 }}>
                        risk_score: {result.risk_score} Â· {result.elapsedMs}ms
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {error && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3 rounded-xl p-3 text-[11px]" style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.2)", color: T.amber }}>
                    {error}
                  </motion.div>
                )}
              </div>

              {/* Action bar */}
              <div className="flex items-center gap-3 px-5 py-3" style={{ background: T.surface2, borderTop: `1px solid ${T.border}` }}>
                <button
                  onClick={run}
                  disabled={running}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all disabled:opacity-60 flex-1 justify-center"
                  style={{ background: T.accent, color: T.bg, border: "none" }}
                >
                  {running && <Loader2 size={14} className="animate-spin" />}
                  {running ? "Evaluatingâ€¦" : "Run against production"}
                  {!running && <Zap size={14} />}
                </button>
                <button
                  onClick={reset}
                  className="px-4 py-2.5 rounded-xl text-sm font-medium transition-all"
                  style={{ background: "transparent", border: `1px solid ${T.border}`, color: T.text3 }}
                >
                  Clear
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* â”€â”€â”€ Architecture â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <section id="arch" className="py-24">
        <div className="max-w-6xl mx-auto px-6">
          <div className="mb-14">
            <Badge color={T.amber}>Architecture</Badge>
            <h2 className="mt-4 text-3xl font-bold tracking-[-0.03em]" style={{ fontFamily: "'Sora', sans-serif" }}>
              Deterministic governance across every autonomous action.
            </h2>
            <p className="mt-3 max-w-2xl text-base leading-7" style={{ color: T.text2 }}>
              Policy first, blast radius second, evidence third. The same payload always
              produces the same decision â€” no non-determinism, no model in the loop.
            </p>
          </div>

          <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-4">
            {[
              [Shield, "Deterministic control", "Unsafe actions are stopped before execution. The decision is a code path, not a suggestion."],
              [Layers, "Blastâ€‘radius scoring", "Every action maps to a scope: process, service, cluster, account, or organization."],
              [Database, "Tamperâ€‘evident audit", "Each decision returns a unique audit ID and a full reasoning chain."],
              [Gauge, "Session memory", "Risk accumulates across the session â€” repeated lowâ€‘grade violations become harder to hide."],
            ].map(([Icon, title, desc]) => (
              <div key={title} className="rounded-2xl p-6 transition-all hover:border-teal-500/20" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                <div className="w-9 h-9 rounded-lg flex items-center justify-center mb-4" style={{ background: T.surface2 }}>
                  <Icon size={17} style={{ color: T.accent }} />
                </div>
                <h3 className="text-sm font-semibold mb-2">{title}</h3>
                <p className="text-sm leading-6" style={{ color: T.text2 }}>{desc}</p>
              </div>
            ))}
          </div>

          <div className="grid md:grid-cols-2 gap-4 mt-4">
            <div className="rounded-2xl p-6" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
              <div className="flex items-center gap-2 mb-3">
                <Lock size={16} style={{ color: T.amber }} />
                <h3 className="font-semibold text-sm">Threat model</h3>
              </div>
              <ul className="space-y-2 text-sm" style={{ color: T.text2 }}>
                <li>â€¢ IAM wildcards expanding permissions across the org</li>
                <li>â€¢ Privileged pods & host networking in Kubernetes</li>
                <li>â€¢ Hardcoded secrets and private keys in payloads</li>
                <li>â€¢ ORG/ACCOUNT scoped changes â€” escalated unconditionally</li>
                <li>â€¢ Accumulated session risk from repeated violations</li>
              </ul>
            </div>
            <div className="rounded-2xl p-6" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
              <div className="flex items-center gap-2 mb-3">
                <Cpu size={16} style={{ color: T.accent }} />
                <h3 className="font-semibold text-sm">Not a prompt layer</h3>
              </div>
              <p className="text-sm leading-7" style={{ color: T.text2 }}>
                A prompt can shape output. A control plane changes execution. DevMind
                sits at the application boundary, evaluating the action itself â€” not
                asking the model to behave.
              </p>
            </div>
          </div>

          {/* Control flow */}
          <div className="mt-4 rounded-2xl p-6" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
            <div className="flex items-center gap-2 mb-4">
              <GitBranch size={16} style={{ color: T.accent }} />
              <h3 className="font-semibold text-sm">Decision ladder</h3>
            </div>
            <div className="mono text-sm leading-8" style={{ color: T.text2 }}>
              <span style={{ color: T.text }}>agent tool call / infra change</span>
              <br />â†“<br />
              <span style={{ color: T.accent }}>policy_engine.evaluate_action() / infra_engine.evaluate_change()</span>
              <br />â†“<br />
              <span style={{ color: T.text }}>hard blocks â†’ blast radius gate â†’ production escalation â†’ risk scoring</span>
              <br />â†“<br />
              <span style={{ color: T.text }}>ALLOW Â· REVIEW Â· ESCALATE Â· BLOCK</span>
            </div>
          </div>
        </div>
      </section>

      {/* â”€â”€â”€ MCP Tools â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <section id="tools" className="py-24" style={{ background: T.surface }}>
        <div className="max-w-6xl mx-auto px-6">
          <div className="mb-14">
            <Badge color={T.accent}>MCP integration</Badge>
            <h2 className="mt-4 text-3xl font-bold tracking-[-0.03em]" style={{ fontFamily: "'Sora', sans-serif" }}>
              9 tools, exposed over MCP
            </h2>
            <p className="mt-3 max-w-2xl text-base leading-7" style={{ color: T.text2 }}>
              Works with any MCPâ€‘compatible client â€” Claude Desktop, Cursor, or your own.
              Governance acts on the action, not on which model produced it.
            </p>
          </div>

          <div className="overflow-hidden rounded-2xl" style={{ border: `1px solid ${T.border}` }}>
            <div className="grid grid-cols-[260px_1fr] px-6 py-3 text-xs font-semibold uppercase tracking-widest" style={{ color: T.text3, background: T.surface2, borderBottom: `1px solid ${T.border}` }}>
              <div>Tool</div>
              <div>Description</div>
            </div>
            {TOOLS.map(([tool, desc], i) => (
              <div
                key={tool}
                className="grid grid-cols-[260px_1fr] px-6 py-3.5 text-sm items-center"
                style={{ borderBottom: i !== TOOLS.length - 1 ? `1px solid ${T.border}` : "none", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.008)" }}
              >
                <code className="mono font-medium" style={{ color: T.accent }}>{tool}</code>
                <span style={{ color: T.text2 }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* â”€â”€â”€ Footer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <footer className="py-10" style={{ borderTop: `1px solid ${T.border}` }}>
        <div className="max-w-6xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-4 text-sm" style={{ color: T.text3 }}>
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded flex items-center justify-center" style={{ background: T.accent }}>
              <Rocket size={11} style={{ color: T.bg }} />
            </div>
            <span>DevMind Â· Runtime governance for autonomous agents</span>
          </div>
          <div className="flex gap-6">
            <a href="https://github.com/mordecaiusm922-create/devmind" className="hover:text-teal-400 transition-colors">GitHub</a>
            <a href="https://devmind-2cej.onrender.com/health" className="hover:text-teal-400 transition-colors">API status</a>
            <a href="https://devmind-mcp.onrender.com/mcp" className="hover:text-teal-400 transition-colors">MCP endpoint</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
