import { useState, useEffect, useRef } from "react";
import { supabase } from "./supabase";

// ─── Design tokens ────────────────────────────────────────────────────────────
const C = {
  bg:       "#07090a",
  bg1:      "#0f1112",
  bg2:      "#161a1b",
  bg3:      "#1d2124",
  border:   "#2a2d30",
  borderY:  "rgba(226,255,93,0.2)",
  yellow:   "#e2ff5d",
  yellowDim:"rgba(226,255,93,0.08)",
  yellowGlow:"rgba(226,255,93,0.15)",
  red:      "#ff4545",
  redDim:   "rgba(255,69,69,0.09)",
  orange:   "#ff8c42",
  blue:     "#5b9cf6",
  green:    "#4ade80",
  text:     "#f0f0f0",
  muted:    "#888d93",
  faint:    "#3d4248",
  mono:     "'IBM Plex Mono', 'Fira Code', 'JetBrains Mono', monospace",
};

const DEC = {
  BLOCK:    { color: C.red,    bg: C.redDim,                       border: "rgba(255,69,69,0.25)"    },
  ESCALATE: { color: C.orange, bg: "rgba(255,140,66,0.09)",        border: "rgba(255,140,66,0.25)"   },
  REVIEW:   { color: C.yellow, bg: C.yellowDim,                    border: C.borderY                 },
  ALLOW:    { color: C.green,  bg: "rgba(74,222,128,0.09)",        border: "rgba(74,222,128,0.25)"   },
};

// ─── Atoms ────────────────────────────────────────────────────────────────────
const Mono = ({ children, style }) => (
  <span style={{ fontFamily: C.mono, ...style }}>{children}</span>
);

function DecBadge({ d, size = 11 }) {
  const m = DEC[d] || DEC.ALLOW;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 9px", borderRadius: 4,
      background: m.bg, border: `1px solid ${m.border}`,
      color: m.color, fontFamily: C.mono,
      fontSize: size, fontWeight: 700, letterSpacing: "0.07em", whiteSpace: "nowrap",
    }}>
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: m.color, flexShrink: 0 }} />
      {d}
    </span>
  );
}

// ─── Interactive intercept demo ───────────────────────────────────────────────
const SCENARIOS = [
  {
    id: "iam",
    label: "IAM wildcard",
    agent: "claude-code",
    tool: "apply_terraform",
    params: { resource: "aws_iam_policy", Action: '"*"', Resource: '"*"' },
    decision: "BLOCK",
    reason: "iam_wildcard_action + iam_wildcard_resource — hard block, no override",
    blast_radius: "ORG",
    risk_score: 97,
    surface: "terraform",
  },
  {
    id: "k8s",
    label: "Privileged pod",
    agent: "codex",
    tool: "kubectl_apply",
    params: { kind: "Pod", privileged: "true", hostNetwork: "true" },
    decision: "BLOCK",
    reason: "privileged_container + hostNetwork — blast radius CLUSTER, production signal",
    blast_radius: "CLUSTER",
    risk_score: 91,
    surface: "kubernetes",
  },
  {
    id: "secret",
    label: "Secret in release",
    agent: "cursor",
    tool: "release_gate",
    params: { artifact: "app-v2.1.tar.gz", aws_key: "AKIAIOSFODNN7EXAMPLE" },
    decision: "BLOCK",
    reason: "hardcoded_secret in artifact — intercept_release() fired before deployment",
    blast_radius: "SERVICE",
    risk_score: 88,
    surface: "release",
  },
  {
    id: "session",
    label: "Session accumulation",
    agent: "claude-code",
    tool: "release_gate",
    params: { artifact: "api-v3.0.tar.gz", secrets_accessed: 1, prod_changes: 2 },
    decision: "BLOCK",
    reason: "session_risk_score=78 ≥ 70 — session history triggers release block regardless of clean artifact",
    blast_radius: "SERVICE",
    risk_score: 78,
    surface: "release",
  },
  {
    id: "safe",
    label: "Safe deploy",
    agent: "claude-code",
    tool: "kubectl_apply",
    params: { kind: "Deployment", image: "app:v1.2.3", replicas: 2, env: "staging" },
    decision: "ALLOW",
    reason: "no critical signals, blast radius FILE, staging environment — action executes",
    blast_radius: "FILE",
    risk_score: 8,
    surface: "kubernetes",
  },
];

function InterceptDemo() {
  const [active, setActive] = useState(0);
  const [phase, setPhase] = useState("idle"); // idle | intercepting | decided
  const [logLines, setLogLines] = useState([]);
  const logRef = useRef(null);
  const sc = SCENARIOS[active];

  const surfColor = { terraform: C.orange, kubernetes: C.blue, release: C.yellow, file: C.muted, git: C.muted };

  const run = (sc) => {
    setPhase("intercepting");
    setLogLines([]);

    const lines = [
      { t: 80,  text: `→ intercept() called`, color: C.muted },
      { t: 180, text: `  agent: ${sc.agent}`, color: C.muted },
      { t: 280, text: `  tool:  ${sc.tool}`, color: C.muted },
      { t: 400, text: `  surface: ${sc.surface}`, color: surfColor[sc.surface] || C.muted },
      { t: 560, text: `→ policy_engine.evaluate()`, color: C.text },
      { t: 720, text: `  blast_radius: ${sc.blast_radius}`, color: sc.blast_radius === "ORG" || sc.blast_radius === "CLUSTER" ? C.orange : C.muted },
      { t: 880, text: `  risk_score:   ${sc.risk_score}`, color: sc.risk_score >= 70 ? C.red : sc.risk_score >= 30 ? C.orange : C.green },
      { t: 1060, text: `→ decision: ${sc.decision}`, color: DEC[sc.decision]?.color || C.text },
      { t: 1220, text: `  reason: ${sc.reason}`, color: C.muted },
      { t: 1380, text: `→ AuditEngine.write() [SHA-256]`, color: C.faint },
      { t: 1520, text: `  ✓ written to devmind_audit.jsonl`, color: C.faint },
    ];

    lines.forEach(({ t, text, color }) => {
      setTimeout(() => {
        setLogLines(prev => [...prev, { text, color, id: t }]);
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
      }, t);
    });

    setTimeout(() => setPhase("decided"), 1600);
  };

  const select = (i) => {
    setActive(i);
    setPhase("idle");
    setLogLines([]);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      {/* Left: scenario picker + agent action */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {/* Scenario tabs */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {SCENARIOS.map((s, i) => (
            <button key={s.id} onClick={() => select(i)} style={{
              padding: "5px 12px", borderRadius: 5, fontSize: 11, cursor: "pointer",
              fontFamily: C.mono, fontWeight: active === i ? 700 : 400,
              background: active === i ? C.yellowDim : "transparent",
              border: `1px solid ${active === i ? C.borderY : C.border}`,
              color: active === i ? C.yellow : C.muted,
              transition: "all 0.12s",
            }}>{s.label}</button>
          ))}
        </div>

        {/* Agent action card */}
        <div style={{
          background: C.bg1, border: `1px solid ${C.border}`,
          borderRadius: 10, overflow: "hidden", flex: 1,
        }}>
          <div style={{
            padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
            background: C.bg2, display: "flex", alignItems: "center", gap: 10,
          }}>
            <div style={{ display: "flex", gap: 5 }}>
              {[C.red, C.yellow, C.green].map(c => (
                <span key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c, opacity: 0.6 }} />
              ))}
            </div>
            <Mono style={{ fontSize: 11, color: C.faint, flex: 1, textAlign: "center" }}>
              {sc.agent} — tool call
            </Mono>
          </div>
          <div style={{ padding: "16px 18px", fontFamily: C.mono, fontSize: 12, lineHeight: 2 }}>
            <div style={{ color: C.blue }}>{sc.tool}{"("}{`{`}</div>
            {Object.entries(sc.params).map(([k, v]) => (
              <div key={k} style={{ paddingLeft: 18 }}>
                <span style={{ color: C.muted }}>{k}</span>
                <span style={{ color: C.faint }}>: </span>
                <span style={{ color: typeof v === "number" ? C.orange : C.yellow }}>
                  {typeof v === "string" && !v.startsWith('"') ? `"${v}"` : String(v)}
                </span>
                <span style={{ color: C.faint }}>,</span>
              </div>
            ))}
            <div style={{ color: C.blue }}>{`}`}{")"}</div>
          </div>
        </div>

        {/* Run button */}
        <button onClick={() => run(sc)} disabled={phase === "intercepting"} style={{
          padding: "11px", borderRadius: 8, border: "none",
          background: phase === "intercepting" ? C.yellowDim : C.yellow,
          color: C.bg, fontSize: 13, fontWeight: 700,
          cursor: phase === "intercepting" ? "wait" : "pointer",
          fontFamily: C.mono, letterSpacing: "0.04em",
          boxShadow: phase !== "intercepting" ? `0 0 20px ${C.yellowGlow}` : "none",
          transition: "all 0.15s",
        }}>
          {phase === "intercepting" ? "intercepting…" : "run intercept() →"}
        </button>
      </div>

      {/* Right: governance output */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {/* Log terminal */}
        <div style={{
          background: C.bg1, border: `1px solid ${C.border}`,
          borderRadius: 10, overflow: "hidden", flex: 1,
        }}>
          <div style={{
            padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
            background: C.bg2, display: "flex", alignItems: "center", gap: 10,
          }}>
            <div style={{ display: "flex", gap: 5 }}>
              {[C.red, C.yellow, C.green].map(c => (
                <span key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c, opacity: 0.6 }} />
              ))}
            </div>
            <Mono style={{ fontSize: 11, color: C.faint, flex: 1, textAlign: "center" }}>
              devmind — governance output
            </Mono>
            {phase !== "idle" && (
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: phase === "decided" ? (DEC[sc.decision]?.color || C.green) : C.yellow, animation: phase === "intercepting" ? "pulse 1s infinite" : "none" }} />
            )}
          </div>
          <div ref={logRef} style={{
            padding: "14px 16px", height: 220, overflowY: "auto",
            fontFamily: C.mono, fontSize: 11.5, lineHeight: 1.9,
          }}>
            {phase === "idle" && (
              <span style={{ color: C.faint }}>waiting… press run intercept() to evaluate this action</span>
            )}
            {logLines.map(l => (
              <div key={l.id} style={{ color: l.color }}>{l.text}</div>
            ))}
          </div>
        </div>

        {/* Decision result */}
        {phase === "decided" && (
          <div style={{
            padding: "16px 18px", borderRadius: 10,
            background: DEC[sc.decision]?.bg || C.bg1,
            border: `1px solid ${DEC[sc.decision]?.border || C.border}`,
            animation: "fadeUp 0.3s ease both",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <DecBadge d={sc.decision} size={13} />
              <Mono style={{ fontSize: 11, color: C.muted }}>
                risk_score: <span style={{ color: sc.risk_score >= 70 ? C.red : sc.risk_score >= 30 ? C.orange : C.green, fontWeight: 700 }}>{sc.risk_score}</span>
              </Mono>
            </div>
            <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.6, fontFamily: C.mono }}>{sc.reason}</div>
            <div style={{ marginTop: 10, fontSize: 11, color: C.faint, fontFamily: C.mono }}>
              blast_radius: <span style={{ color: sc.blast_radius === "ORG" || sc.blast_radius === "CLUSTER" ? C.orange : C.muted }}>{sc.blast_radius}</span>
              <span style={{ marginLeft: 16 }}>→ audit log written</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Live stream ticker ────────────────────────────────────────────────────────
const STREAM = [
  { agent: "claude-code", action: "terraform apply iam-admin",    surface: "terraform", d: "BLOCK",    ms: "0.4ms" },
  { agent: "codex",       action: "kubectl apply privileged-pod", surface: "k8s",       d: "BLOCK",    ms: "0.3ms" },
  { agent: "cursor",      action: "release_gate api-v3.tar.gz",   surface: "release",   d: "REVIEW",   ms: "1.1ms" },
  { agent: "claude-code", action: "read_file .env.production",    surface: "file",      d: "ESCALATE", ms: "0.6ms" },
  { agent: "codex",       action: "git push origin main",         surface: "git",       d: "ALLOW",    ms: "0.2ms" },
  { agent: "cursor",      action: "helm upgrade --force prod",    surface: "helm",      d: "REVIEW",   ms: "0.8ms" },
  { agent: "claude-code", action: "iam_wildcard_resource aws",    surface: "terraform", d: "BLOCK",    ms: "0.4ms" },
  { agent: "codex",       action: "kubectl exec pod/api-prod",    surface: "k8s",       d: "BLOCK",    ms: "0.3ms" },
];

function LiveStream() {
  const [lines, setLines] = useState([]);
  const [blink, setBlink] = useState(true);
  const ref = useRef(null);
  const idx = useRef(0);

  useEffect(() => {
    const t = setInterval(() => {
      const ev = STREAM[idx.current % STREAM.length];
      idx.current++;
      const ts = new Date().toISOString().split("T")[1].slice(0, 8);
      setLines(p => [...p.slice(-12), { ...ev, ts, id: Date.now() }]);
    }, 1200);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const t = setInterval(() => setBlink(p => !p), 500);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  const sc = { terraform: C.orange, k8s: C.blue, release: C.yellow, file: C.muted, helm: C.blue, git: C.faint };

  return (
    <div style={{
      background: C.bg1, border: `1px solid ${C.border}`,
      borderRadius: 12, overflow: "hidden",
    }}>
      <div style={{
        padding: "10px 16px", background: C.bg2, borderBottom: `1px solid ${C.border}`,
        display: "flex", alignItems: "center", gap: 10,
      }}>
        <div style={{ display: "flex", gap: 5 }}>
          {[C.red, C.yellow, C.green].map(c => (
            <span key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c, opacity: 0.6 }} />
          ))}
        </div>
        <Mono style={{ fontSize: 11, color: C.faint, flex: 1, textAlign: "center" }}>devmind — live governance stream</Mono>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 5, height: 5, borderRadius: "50%", background: C.yellow, animation: "pulse 1.8s infinite" }} />
          <Mono style={{ fontSize: 10, color: C.yellow }}>live</Mono>
        </div>
      </div>
      <div ref={ref} style={{ padding: "12px 16px", height: 240, overflowY: "auto", fontFamily: C.mono, fontSize: 11.5, lineHeight: 1.95 }}>
        {lines.map(l => (
          <div key={l.id} style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "nowrap" }}>
            <span style={{ color: C.faint, flexShrink: 0, fontSize: 10 }}>{l.ts}</span>
            <span style={{ color: C.muted, flexShrink: 0, minWidth: 80 }}>{l.agent}</span>
            <span style={{ color: sc[l.surface] || C.muted, flexShrink: 0, fontSize: 10 }}>[{l.surface}]</span>
            <span style={{ color: C.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{l.action}</span>
            <span style={{ color: DEC[l.d]?.color || C.muted, fontWeight: 700, flexShrink: 0 }}>{l.d}</span>
            <span style={{ color: C.faint, fontSize: 10, flexShrink: 0 }}>{l.ms}</span>
          </div>
        ))}
        <span style={{ color: C.yellow, opacity: blink ? 1 : 0 }}>█</span>
      </div>
    </div>
  );
}

// ─── MCP tools table ──────────────────────────────────────────────────────────
const MCP_TOOLS = [
  ["evaluate_action",        "Agent tool calls — file writes, shell, API, database"],
  ["evaluate_terraform_plan","Terraform plans before apply"],
  ["evaluate_k8s_manifest",  "Kubernetes manifests before kubectl apply"],
  ["release_gate",           "Release artifacts before deployment"],
  ["session_status",         "Current session risk profile"],
  ["audit_log",              "Retrieve tamper-evident audit records"],
  ["policy_check",           "Query policy engine directly"],
  ["blast_radius_check",     "Evaluate scope of a proposed change"],
  ["session_reset",          "Reset session risk accumulation"],
  ["governance_report",      "Full session governance summary"],
  ["risk_score",             "Score an action without enforcing"],
  ["health",                 "DevMind server status"],
];

// ─── Nav ──────────────────────────────────────────────────────────────────────
function Nav({ user, apiKey, onSignIn, onSignOut }) {
  const [scrolled, setScrolled] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 24);
    window.addEventListener("scroll", fn, { passive: true });
    return () => window.removeEventListener("scroll", fn);
  }, []);

  const copy = () => {
    navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <nav style={{
      position: "fixed", top: 0, left: 0, right: 0, zIndex: 300,
      height: 56, padding: "0 28px",
      display: "flex", alignItems: "center", justifyContent: "space-between",
      background: scrolled ? "rgba(7,9,10,0.95)" : "transparent",
      backdropFilter: scrolled ? "blur(20px)" : "none",
      borderBottom: scrolled ? `1px solid ${C.border}` : "1px solid transparent",
      transition: "all 0.2s",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <svg width="26" height="26" viewBox="0 0 26 26" fill="none">
          <rect width="26" height="26" rx="6" fill={C.bg2} />
          <path d="M7 7h5c3.3 0 6 2.7 6 6s-2.7 6-6 6H7V7z"
            stroke={C.yellow} strokeWidth="1.8" fill="none" strokeLinejoin="round" />
          <rect x="10" y="10" width="4.5" height="4.5" rx="1" fill={C.yellow} />
        </svg>
        <Mono style={{ fontWeight: 700, fontSize: 14 }}>DevMind</Mono>
        <Mono style={{
          fontSize: 9, color: C.yellow, background: C.yellowDim,
          border: `1px solid ${C.borderY}`, padding: "2px 6px", borderRadius: 3,
          letterSpacing: "0.1em",
        }}>BETA</Mono>
      </div>

      <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
        {[["#demo","Demo"],["#how","How it works"],["#threats","Threats"],["#mcp","MCP tools"],["https://github.com/mordecaiusm922-create/devmind","GitHub ↗"]].map(([href, label]) => (
          <a key={href} href={href} target={href.startsWith("http") ? "_blank" : undefined} rel="noreferrer"
            style={{ fontSize: 13, color: C.muted, textDecoration: "none", transition: "color 0.12s" }}
            onMouseEnter={e => e.currentTarget.style.color = C.text}
            onMouseLeave={e => e.currentTarget.style.color = C.muted}>
            {label}
          </a>
        ))}
        {user ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <img src={user.user_metadata?.avatar_url} alt=""
              style={{ width: 26, height: 26, borderRadius: "50%", border: `1px solid ${C.borderY}` }} />
            {apiKey && (
              <button onClick={copy} style={{
                padding: "4px 10px", borderRadius: 5, fontSize: 11,
                background: C.yellowDim, border: `1px solid ${C.borderY}`,
                color: C.yellow, cursor: "pointer", fontFamily: C.mono,
              }}>{copied ? "copied!" : `${apiKey.slice(0,12)}…`}</button>
            )}
            <button onClick={onSignOut} style={{
              padding: "5px 12px", borderRadius: 5, fontSize: 12,
              background: C.bg2, border: `1px solid ${C.border}`,
              color: C.muted, cursor: "pointer",
            }}>out</button>
          </div>
        ) : (
          <button onClick={onSignIn} style={{
            padding: "6px 16px", borderRadius: 6, fontSize: 12, fontWeight: 600,
            background: C.yellowDim, border: `1px solid ${C.borderY}`,
            color: C.yellow, cursor: "pointer",
          }}>Sign in with GitHub</button>
        )}
      </div>
    </nav>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser]   = useState(null);
  const [apiKey, setApiKey] = useState(null);

  useEffect(() => {
    supabase.auth.getSession().then(async ({ data: { session } }) => {
      const u = session?.user ?? null;
      setUser(u);
      if (u) {
        const { data } = await supabase.from("users").select("api_key").eq("id", u.id).single();
        if (data) setApiKey(data.api_key);
      }
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (_ev, session) => {
      const u = session?.user ?? null;
      setUser(u);
      if (_ev === "SIGNED_IN" && u) {
        const key = `dm-${u.id.replace(/-/g,"").slice(0,24)}`;
        await supabase.from("users").upsert(
          { id: u.id, username: u.user_metadata?.user_name, email: u.email, api_key: key },
          { onConflict: "id", ignoreDuplicates: true }
        );
        setApiKey(key);
      }
    });
    return () => subscription.unsubscribe();
  }, []);

  const signIn = () => supabase.auth.signInWithOAuth({
    provider: "github",
    options: { redirectTo: "https://devmind-gamma.vercel.app" },
  });
  const signOut = () => supabase.auth.signOut();

  const Divider = () => (
    <div style={{ height: 1, background: `linear-gradient(90deg, transparent, ${C.border} 20%, ${C.border} 80%, transparent)` }} />
  );

  const SectionEyebrow = ({ label }) => (
    <Mono style={{ fontSize: 10, color: C.yellow, letterSpacing: "0.14em", textTransform: "uppercase", display: "block", marginBottom: 12 }}>
      {label}
    </Mono>
  );

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700;800&display=swap');
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
          background: ${C.bg};
          color: ${C.text};
          font-family: 'Inter', system-ui, sans-serif;
          -webkit-font-smoothing: antialiased;
        }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        input:focus { outline: none; border-color: ${C.borderY} !important; box-shadow: 0 0 0 3px ${C.yellowDim} !important; }
        @keyframes pulse  { 0%,100%{opacity:1}   50%{opacity:0.3}  }
        @keyframes fadeUp { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
        .fu  { animation: fadeUp 0.45s ease both; }
        .fu2 { animation: fadeUp 0.45s 0.08s ease both; }
        .fu3 { animation: fadeUp 0.45s 0.16s ease both; }
        .fu4 { animation: fadeUp 0.45s 0.24s ease both; }
        button { transition: opacity 0.1s, transform 0.1s; }
        button:hover:not(:disabled) { opacity: 0.82; }
        a { transition: color 0.12s; }
      `}</style>

      <Nav user={user} apiKey={apiKey} onSignIn={signIn} onSignOut={signOut} />

      {/* ── HERO ── */}
      <section style={{ padding: "120px 28px 80px", maxWidth: 1100, margin: "0 auto", position: "relative" }}>
        {/* Glow */}
        <div style={{
          position: "absolute", top: 60, left: "50%", transform: "translateX(-50%)",
          width: 700, height: 400, pointerEvents: "none",
          background: `radial-gradient(ellipse at 50% 0%, rgba(226,255,93,0.05) 0%, transparent 65%)`,
        }} />

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 56, alignItems: "center" }}>
          {/* Left */}
          <div>
            <div className="fu" style={{
              display: "inline-flex", alignItems: "center", gap: 7,
              padding: "5px 13px", borderRadius: 100, marginBottom: 24,
              background: C.yellowDim, border: `1px solid ${C.borderY}`,
            }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.yellow, animation: "pulse 2s infinite" }} />
              <Mono style={{ fontSize: 11, color: C.yellow, letterSpacing: "0.04em" }}>
                runtime governance · agent actions · session memory
              </Mono>
            </div>

            <h1 className="fu2" style={{
              fontSize: "clamp(28px, 3.5vw, 48px)", fontWeight: 800,
              lineHeight: 1.1, letterSpacing: "-0.04em", marginBottom: 20,
            }}>
              Your agents act.<br />
              <span style={{
                background: `linear-gradient(90deg, ${C.yellow}, #f0e868)`,
                WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
              }}>DevMind decides.</span>
            </h1>

            <p className="fu3" style={{
              fontSize: 15, color: C.muted, lineHeight: 1.72, marginBottom: 32, maxWidth: 420,
            }}>
              Every agent action — Terraform, Kubernetes, Helm, releases, secrets —
              intercepted and evaluated before it reaches your systems.
              Deterministic policy. Session memory. Tamper-evident audit.
            </p>

            <div className="fu4" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <a href="https://github.com/mordecaiusm922-create/devmind" target="_blank" rel="noreferrer" style={{
                  display: "inline-flex", alignItems: "center", gap: 7,
                  padding: "10px 22px", borderRadius: 7, fontSize: 13, fontWeight: 700,
                  background: C.yellow, color: C.bg, textDecoration: "none",
                  boxShadow: `0 0 24px ${C.yellowGlow}`,
                }}>
                  <svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                  View on GitHub
                </a>
                <a href="#demo" style={{
                  display: "inline-block", padding: "10px 20px", borderRadius: 7, fontSize: 13,
                  background: C.bg2, border: `1px solid ${C.border}`,
                  color: C.muted, textDecoration: "none",
                }}>See it intercept →</a>
              </div>
              <Mono style={{ fontSize: 11, color: C.faint }}>
                pip install devmind-agent
                <span style={{ color: C.faint }}> · coming to PyPI</span>
              </Mono>
            </div>

            {/* Stats */}
            <div className="fu4" style={{ display: "flex", gap: 28, marginTop: 36, flexWrap: "wrap" }}>
              {[["178","tests in CI"],["28/28","scenarios, 0 false negatives"],["<1ms","policy eval"]].map(([n,l]) => (
                <div key={n}>
                  <Mono style={{ fontSize: 22, fontWeight: 700, color: C.yellow, display: "block", letterSpacing: "-0.02em" }}>{n}</Mono>
                  <span style={{ fontSize: 11, color: C.faint }}>{l}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right: live stream */}
          <div className="fu3">
            <LiveStream />
          </div>
        </div>
      </section>

      <Divider />

      {/* ── INTERACTIVE DEMO ── */}
      <section id="demo" style={{ padding: "80px 28px", maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ marginBottom: 36 }}>
          <SectionEyebrow label="interactive demo" />
          <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 8 }}>
            Watch DevMind intercept in real time
          </h2>
          <p style={{ fontSize: 14, color: C.muted }}>
            Pick a scenario. Press run. See the decision ladder execute.
          </p>
        </div>
        <InterceptDemo />
      </section>

      <Divider />

      {/* ── HOW IT WORKS ── */}
      <section id="how" style={{ padding: "80px 28px", maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ marginBottom: 40 }}>
          <SectionEyebrow label="architecture" />
          <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 8 }}>
            Three questions before any system is touched
          </h2>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14, marginBottom: 28 }}>
          {[
            { q: "Is this action allowed?", body: "28 signals across Terraform, Kubernetes, Helm, and agent actions. Hard blocks are invariants — they cannot be overridden by the agent, by org rules, or by an LLM escalation. The code path to override doesn't exist." },
            { q: "What risk has this session built?", body: "DevMind tracks secrets accessed, production changes, infra modifications, and violations across the entire session. The release gate weighs history — not just the current artifact. An agent that accessed secrets earlier faces a harder gate on its next release." },
            { q: "Can you prove what happened?", body: "Every decision is written to an append-only JSONL with SHA-256 integrity before any system is touched. Agent ID, policy version, decision, blast radius, risk score — all recorded." },
          ].map(({ q, body }) => (
            <div key={q} style={{ padding: "22px 22px", borderRadius: 10, background: C.bg1, border: `1px solid ${C.border}` }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 10, lineHeight: 1.35 }}>{q}</h3>
              <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.65 }}>{body}</p>
            </div>
          ))}
        </div>

        {/* Decision ladder + session memory */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 14 }}>
          <div style={{ padding: "20px 22px", background: C.bg1, border: `1px solid ${C.border}`, borderRadius: 10 }}>
            <Mono style={{ fontSize: 10, color: C.faint, letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: 14 }}>decision ladder</Mono>
            <div style={{ fontFamily: C.mono, fontSize: 12, lineHeight: 2 }}>
              {[
                [C.muted,   "agent action (tool call)"],
                [C.faint,   "↓"],
                [C.yellow,  "DevMindSandbox.intercept()"],
                [C.faint,   "↓"],
                [C.text,    "policy_engine + infra_engine + release_gate"],
                [C.faint,   "↓"],
                [C.text,    "GovernanceDecision"],
                ["",        ""],
                [C.green,   "  ALLOW     → action executes"],
                [C.yellow,  "  REVIEW    → LLM evaluation via Groq"],
                [C.red,     "  BLOCK     → hard stop, no override"],
                [C.orange,  "  ESCALATE  → blast radius gate"],
                ["",        ""],
                [C.faint,   "↓"],
                [C.muted,   "AuditEngine → JSONL (SHA-256, append-only)"],
              ].map(([c, t], i) => (
                <div key={i} style={{ color: c || "transparent" }}>{t || "\u00a0"}</div>
              ))}
            </div>
          </div>

          <div style={{ padding: "20px 22px", background: C.bg1, border: `1px solid ${C.border}`, borderRadius: 10 }}>
            <Mono style={{ fontSize: 10, color: C.faint, letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: 14 }}>session memory</Mono>
            <div style={{ fontFamily: C.mono, fontSize: 12, lineHeight: 2 }}>
              <div style={{ color: C.faint }}>{"// SessionRiskProfile — accumulated"}</div>
              <div style={{ color: C.yellow }}>{"{"}</div>
              {[
                ["secrets_accessed",       "1",  C.orange],
                ["production_changes",     "2",  C.red   ],
                ["infra_changes",          "3",  C.orange],
                ["session_violation_count","1",  C.red   ],
                ["session_risk_score",    "78",  C.red   ],
              ].map(([k,v,vc]) => (
                <div key={k} style={{ paddingLeft: 16 }}>
                  <span style={{ color: C.muted }}>{k}</span>
                  <span style={{ color: C.faint }}>: </span>
                  <span style={{ color: vc, fontWeight: 700 }}>{v}</span>
                  <span style={{ color: C.faint }}>,</span>
                </div>
              ))}
              <div style={{ color: C.yellow }}>{"}"}</div>
              <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${C.border}`, color: C.faint }}>
                {"// release_gate → "}
                <span style={{ color: C.red, fontWeight: 700 }}>BLOCK</span>
                <span>{"  // score ≥ 70, regardless of artifact"}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Why not just a prompt */}
        <div style={{ marginTop: 14, padding: "20px 24px", background: C.yellowDim, border: `1px solid ${C.borderY}`, borderRadius: 10 }}>
          <Mono style={{ fontSize: 10, color: C.yellow, letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: 10 }}>why not just use a prompt?</Mono>
          <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.65, maxWidth: 780 }}>
            A system prompt is evaluated by the model at inference time. The model is non-deterministic.
            Under long context or adversarial input, instructions are not always honored.
            DevMind operates at the application layer — when it blocks an action, the action does not execute.
            The block is not a probability. It is a code path that returns <Mono style={{ color: C.red, fontWeight: 700 }}>BLOCK</Mono> before any system is touched.
            No prompt overrides <Mono style={{ color: C.yellow }}>iam_wildcard_action</Mono>.
          </p>
        </div>
      </section>

      <Divider />

      {/* ── THREAT MODEL ── */}
      <section id="threats" style={{ padding: "80px 28px", maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ marginBottom: 40 }}>
          <SectionEyebrow label="threat model" />
          <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 8 }}>
            Five threat classes in production today
          </h2>
          <p style={{ fontSize: 14, color: C.muted }}>All 28 scenarios tested. Zero false negatives.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 12 }}>
          {[
            { title: "Terraform privilege escalation", d: "BLOCK",
              body: "Agent creates IAM policy with Action: \"*\" or Resource: \"*\". Hard block at the policy engine — no LLM call made, no override possible. Blast radius: ORG." },
            { title: "Kubernetes container escape", d: "BLOCK",
              body: "Agent deploys pod with privileged: true or hostNetwork: true. Blast radius computed as CLUSTER → blocked before manifest reaches the cluster." },
            { title: "Secret injection into release", d: "BLOCK",
              body: "Agent packages artifact with hardcoded AWS key or API token. Artifact scan fires during intercept_release() — hard block before deployment." },
            { title: "Session-level risk accumulation", d: "BLOCK",
              body: "Each action looks reasonable in isolation. Session memory surfaces the pattern: secrets_accessed=1 + production_changes=2 → release gate raises to BLOCK regardless of clean artifact." },
            { title: "Blast radius override attempt", d: "ESCALATE",
              body: "ORG or ACCOUNT scope always escalates. The code path to override doesn't exist — this is an invariant tested in CI, not a configuration option." },
          ].map(({ title, d, body }) => (
            <div key={title} style={{
              padding: "18px 20px", borderRadius: 10,
              background: C.bg1, border: `1px solid ${C.border}`,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10, marginBottom: 10 }}>
                <div style={{ fontSize: 13, fontWeight: 600, lineHeight: 1.35 }}>{title}</div>
                <DecBadge d={d} size={10} />
              </div>
              <p style={{ fontSize: 12, color: C.muted, lineHeight: 1.65 }}>{body}</p>
            </div>
          ))}
        </div>
      </section>

      <Divider />

      {/* ── SURFACES ── */}
      <section style={{ padding: "80px 28px", maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ marginBottom: 40 }}>
          <SectionEyebrow label="coverage" />
          <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.03em" }}>
            What DevMind governs
          </h2>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
          {[
            { surface: "Terraform",      color: C.orange, items: ["IAM policies","Resource provisioning","State manipulation","Secret injection"] },
            { surface: "Kubernetes",     color: C.blue,   items: ["Privileged containers","hostNetwork","RBAC escalation","exec access"] },
            { surface: "Helm",           color: C.yellow, items: ["Chart deployments","Value overrides","Production releases","Force upgrades"] },
            { surface: "Releases",       color: C.green,  items: ["Artifact secrets","Session risk gates","Deployment approvals","Artifact scan"] },
            { surface: "Agent actions",  color: C.muted,  items: ["File writes","Shell commands","Database operations","API calls"] },
          ].map(({ surface, color, items }) => (
            <div key={surface} style={{ padding: "18px 18px", borderRadius: 10, background: C.bg1, border: `1px solid ${C.border}` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 14 }}>
                <span style={{ width: 7, height: 7, borderRadius: "50%", background: color }} />
                <Mono style={{ fontSize: 12, fontWeight: 700, color }}>{surface}</Mono>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {items.map(i => (
                  <div key={i} style={{ fontSize: 12, color: C.muted, display: "flex", gap: 7, alignItems: "flex-start" }}>
                    <span style={{ color: C.faint, flexShrink: 0, marginTop: 1 }}>·</span>{i}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <Divider />

      {/* ── MCP TOOLS ── */}
      <section id="mcp" style={{ padding: "80px 28px", maxWidth: 900, margin: "0 auto" }}>
        <div style={{ marginBottom: 36 }}>
          <SectionEyebrow label="integration" />
          <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 8 }}>12 MCP tools</h2>
          <p style={{ fontSize: 14, color: C.muted, marginBottom: 20 }}>
            Works with Claude Code, OpenAI Codex, or any MCP-compatible client.
            Governance is model-agnostic — it governs actions, not outputs.
          </p>
          {/* Quickstart */}
          <div style={{ background: C.bg1, border: `1px solid ${C.border}`, borderRadius: 10, padding: "16px 20px", fontFamily: C.mono, fontSize: 12, lineHeight: 1.9, marginBottom: 20 }}>
            <div style={{ color: C.faint, marginBottom: 6 }}>{"# quickstart"}</div>
            <div><span style={{ color: C.yellow }}>pip install</span> <span style={{ color: C.text }}>devmind-agent</span></div>
            <div style={{ marginTop: 8, color: C.faint }}>{"# MCP config"}</div>
            <div><span style={{ color: C.yellow }}>{"{"}</span></div>
            <div style={{ paddingLeft: 16 }}><span style={{ color: C.blue }}>"mcpServers"</span><span style={{ color: C.text }}>: {"{"}</span></div>
            <div style={{ paddingLeft: 32 }}><span style={{ color: C.blue }}>"devmind"</span><span style={{ color: C.text }}>: {"{"} <span style={{ color: C.blue }}>"command"</span>: <span style={{ color: C.green }}>"devmind"</span>, <span style={{ color: C.blue }}>"args"</span>: [<span style={{ color: C.green }}>"serve"</span>] {"}"}</span></div>
            <div style={{ paddingLeft: 16 }}><span style={{ color: C.text }}>{"}"}</span></div>
            <div><span style={{ color: C.yellow }}>{"}"}</span></div>
          </div>
        </div>

        <div style={{ borderRadius: 10, overflow: "hidden", border: `1px solid ${C.border}` }}>
          <div style={{ padding: "11px 20px", background: C.bg2, borderBottom: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between" }}>
            <Mono style={{ fontSize: 11, color: C.faint }}>tool</Mono>
            <Mono style={{ fontSize: 11, color: C.faint }}>governs</Mono>
          </div>
          {MCP_TOOLS.map(([tool, desc], i) => (
            <div key={tool} style={{
              display: "flex", gap: 20, padding: "11px 20px", alignItems: "center",
              borderBottom: i < MCP_TOOLS.length - 1 ? `1px solid rgba(255,255,255,0.03)` : "none",
              background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)",
            }}>
              <Mono style={{ fontSize: 12, color: C.yellow, flex: "0 0 200px" }}>{tool}</Mono>
              <span style={{ fontSize: 12, color: C.muted }}>{desc}</span>
            </div>
          ))}
        </div>
      </section>

      <Divider />

      {/* ── ROADMAP ── */}
      <section style={{ padding: "80px 28px", maxWidth: 720, margin: "0 auto" }}>
        <div style={{ marginBottom: 40 }}>
          <SectionEyebrow label="roadmap" />
          <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.03em" }}>Where DevMind is going</h2>
        </div>
        {[
          { phase: "Phase 1", label: "Adoption — now", active: true,
            items: ["pip install devmind-agent + devmind serve CLI", "Dashboard: session risk visualization", "First 10 real users — Claude Code community, HN, r/devops"] },
          { phase: "Phase 2", label: "Retention — with users", active: false,
            items: ["Agent Reputation System — cross-session persistence (Supabase)", "NIST AI RMF compliance baseline"] },
          { phase: "Phase 3", label: "Moat — with traction", active: false,
            items: ["Opt-in telemetry: {type, score, decision, surface} — off by default", "Infrastructure ready in Phase 1, activation requires no rewrite"] },
          { phase: "Phase 4", label: "Network — with volume", active: false,
            items: ["Agent Risk Intelligence Network", "Aggregated cross-org signals — never payloads"] },
        ].map(({ phase, label, active, items }, i, arr) => (
          <div key={phase} style={{ display: "flex", gap: 20 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0 }}>
              <div style={{
                width: 10, height: 10, borderRadius: "50%", marginTop: 18, flexShrink: 0,
                background: active ? C.yellow : C.border,
                boxShadow: active ? `0 0 10px ${C.yellowGlow}` : "none",
              }} />
              {i < arr.length - 1 && <div style={{ width: 1, flex: 1, background: C.border, marginTop: 4 }} />}
            </div>
            <div style={{ paddingBottom: 28, paddingTop: 12 }}>
              <Mono style={{ fontSize: 10, color: C.faint, textTransform: "uppercase", letterSpacing: "0.1em" }}>{phase}</Mono>
              <div style={{ fontSize: 14, fontWeight: 600, margin: "4px 0 10px", color: active ? C.text : C.muted }}>{label}</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {items.map(item => (
                  <div key={item} style={{ fontSize: 12, color: C.faint, display: "flex", gap: 8 }}>
                    <span style={{ color: active ? C.yellow : C.faint, flexShrink: 0 }}>→</span>{item}
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </section>

      <Divider />

      {/* ── FOOTER ── */}
      <footer style={{
        padding: "28px 28px",
        display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <svg width="20" height="20" viewBox="0 0 26 26" fill="none">
            <rect width="26" height="26" rx="6" fill={C.bg2} />
            <path d="M7 7h5c3.3 0 6 2.7 6 6s-2.7 6-6 6H7V7z" stroke={C.yellow} strokeWidth="1.8" fill="none" strokeLinejoin="round" />
            <rect x="10" y="10" width="4.5" height="4.5" rx="1" fill={C.yellow} />
          </svg>
          <Mono style={{ fontWeight: 700, fontSize: 13 }}>DevMind</Mono>
          <span style={{ fontSize: 12, color: C.faint }}>— governance layer for autonomous code agents</span>
        </div>
        <Mono style={{ fontSize: 11, color: C.faint }}>
          MIT ·{" "}
          <a href="https://github.com/mordecaiusm922-create/devmind" style={{ color: C.yellow, textDecoration: "none" }}>GitHub</a>
          {" "}· FastAPI · Groq · Vercel
        </Mono>
      </footer>
    </>
  );
}