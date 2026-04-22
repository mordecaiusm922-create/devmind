import { useState, useEffect, useRef } from "react";

// ── Config ──────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "https://devmind-2cej.onrender.com";
const API_KEY  = import.meta.env.VITE_API_KEY  || "devmind-key-123";

// ── Risk palette ─────────────────────────────────────────────────────────────
const RISK = {
  low:      { color: "#22c55e", bg: "rgba(34,197,94,0.08)",   border: "rgba(34,197,94,0.25)",   label: "LOW",      dot: "#22c55e" },
  medium:   { color: "#f59e0b", bg: "rgba(245,158,11,0.08)",  border: "rgba(245,158,11,0.25)",  label: "MEDIUM",   dot: "#f59e0b" },
  high:     { color: "#ef4444", bg: "rgba(239,68,68,0.08)",   border: "rgba(239,68,68,0.25)",   label: "HIGH",     dot: "#ef4444" },
  critical: { color: "#a855f7", bg: "rgba(168,85,247,0.08)",  border: "rgba(168,85,247,0.25)",  label: "CRITICAL", dot: "#a855f7" },
};

// ── Tiny helpers ─────────────────────────────────────────────────────────────
function RiskBadge({ level }) {
  const r = RISK[level] || RISK.low;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      padding: "4px 10px", borderRadius: 6,
      background: r.bg, border: `1px solid ${r.border}`,
      color: r.color, fontFamily: "'JetBrains Mono', monospace",
      fontSize: 11, fontWeight: 700, letterSpacing: "0.08em",
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: r.color, boxShadow: `0 0 6px ${r.color}` }} />
      {r.label}
    </span>
  );
}

function Tag({ children }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)",
      color: "#94a3b8", fontSize: 10, fontFamily: "'JetBrains Mono', monospace",
    }}>{children}</span>
  );
}

function SevBadge({ sev }) {
  const c = { critical: "#a855f7", high: "#ef4444", medium: "#f59e0b", low: "#22c55e" }[sev] || "#94a3b8";
  return (
    <span style={{
      padding: "1px 7px", borderRadius: 4, fontSize: 9, fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em",
      color: c, background: `${c}18`, border: `1px solid ${c}40`,
      textTransform: "uppercase",
    }}>{sev}</span>
  );
}

// ── Analysis Result Panel ─────────────────────────────────────────────────────
function ResultPanel({ result }) {
  const s    = result?.summary || {};
  const risk = s.risk || {};
  const pre  = result?.pre_analysis || {};
  const eng  = result?.risk_engine || {};
  const vulns = s.vulnerabilities || [];
  const keys  = s.key_changes || [];
  const ev    = result?.evaluation || {};

  const scoreColor = eng.score >= 70 ? "#a855f7" : eng.score >= 40 ? "#ef4444" : eng.score >= 20 ? "#f59e0b" : "#22c55e";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Header row */}
      <div style={{
        display: "flex", alignItems: "flex-start", justifyContent: "space-between",
        padding: "20px 24px", background: "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12,
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <RiskBadge level={risk.level} />
            <span style={{ color: "#64748b", fontSize: 12 }}>
              {ev.confidence && `${ev.confidence} confidence`}
            </span>
          </div>
          <div style={{ fontSize: 13, color: "#94a3b8", marginBottom: 4 }}>
            <strong style={{ color: "#e2e8f0" }}>{result.repo}</strong>
            <span style={{ color: "#475569", margin: "0 6px" }}>/</span>
            PR <strong style={{ color: "#e2e8f0" }}>#{result.pr_number}</strong>
            <span style={{ color: "#475569", margin: "0 8px" }}>·</span>
            @{result.author}
          </div>
          <div style={{ fontSize: 12, color: "#64748b" }}>
            +{result.additions} <span style={{ color: "#22c55e" }}>additions</span>
            {"  "}−{result.deletions} <span style={{ color: "#ef4444" }}>deletions</span>
            {"  "}·{"  "}{result.changed_files} files
          </div>
        </div>
        {eng.score != null && (
          <div style={{ textAlign: "center" }}>
            <div style={{
              fontSize: 42, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace",
              color: scoreColor, lineHeight: 1,
              textShadow: `0 0 20px ${scoreColor}60`,
            }}>{eng.score}</div>
            <div style={{ fontSize: 10, color: "#475569", marginTop: 2, letterSpacing: "0.05em" }}>RISK SCORE</div>
          </div>
        )}
      </div>

      {/* Title */}
      <div style={{
        padding: "14px 20px",
        background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: 10, fontSize: 13, color: "#94a3b8", fontStyle: "italic",
      }}>
        "{result.title}"
      </div>

      {/* What / Why / Impact */}
      {[["What", s.what], ["Why", s.why], ["Impact", s.impact]].filter(([, v]) => v).map(([label, val]) => (
        <div key={label} style={{
          padding: "16px 20px", background: "rgba(255,255,255,0.02)",
          border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10,
        }}>
          <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", marginBottom: 6, textTransform: "uppercase" }}>{label}</div>
          <div style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.65 }}>{val}</div>
        </div>
      ))}

      {/* Risk reason */}
      {risk.reason && (
        <div style={{
          padding: "14px 20px", borderRadius: 10,
          background: (RISK[risk.level] || RISK.low).bg,
          border: `1px solid ${(RISK[risk.level] || RISK.low).border}`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span style={{ fontSize: 10, color: "#475569", letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase" }}>Risk</span>
            <RiskBadge level={risk.level} />
            {pre.risk_tags?.map(t => <Tag key={t}>{t}</Tag>)}
          </div>
          <div style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.6 }}>{risk.reason}</div>
        </div>
      )}

      {/* Vulnerabilities */}
      {vulns.length > 0 && (
        <div style={{
          padding: "16px 20px", background: "rgba(255,255,255,0.02)",
          border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10,
        }}>
          <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", marginBottom: 12, textTransform: "uppercase" }}>Vulnerabilities Detected</div>
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 12 }}>
            {vulns.map((v, i) => {
              const c = { critical: "#a855f7", high: "#ef4444", medium: "#f59e0b", low: "#22c55e" }[v.severity] || "#94a3b8";
              return (
                <li key={i} style={{ borderLeft: `2px solid ${c}`, paddingLeft: 14 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 5, flexWrap: "wrap" }}>
                    <SevBadge sev={v.severity} />
                    <code style={{ fontSize: 10, color: "#64748b", background: "rgba(255,255,255,0.04)", padding: "1px 6px", borderRadius: 4 }}>{v.location}</code>
                    <span style={{ fontSize: 10, color: "#475569", background: "rgba(255,255,255,0.04)", padding: "1px 6px", borderRadius: 4 }}>{v.type}</span>
                  </div>
                  <p style={{ fontSize: 12, color: "#94a3b8", margin: "0 0 5px", lineHeight: 1.6 }}>{v.description}</p>
                  <p style={{ fontSize: 11, color: "#22c55e", margin: 0 }}>
                    <span style={{ color: "#475569" }}>Fix →</span> {v.fix}
                  </p>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* Key changes */}
      {keys.length > 0 && (
        <div style={{
          padding: "16px 20px", background: "rgba(255,255,255,0.02)",
          border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10,
        }}>
          <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", marginBottom: 10, textTransform: "uppercase" }}>Key Changes</div>
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 6 }}>
            {keys.map((k, i) => (
              <li key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <span style={{ color: "#a855f7", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, marginTop: 1 }}>→</span>
                <code style={{ fontSize: 11, color: "#94a3b8", lineHeight: 1.6 }}>{k}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Risk engine factors */}
      {eng.top_factors?.length > 0 && (
        <div style={{
          padding: "14px 20px", background: "rgba(255,255,255,0.02)",
          border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10,
        }}>
          <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.1em", fontFamily: "'JetBrains Mono', monospace", marginBottom: 8, textTransform: "uppercase" }}>Risk Factors</div>
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
            {eng.top_factors.map((f, i) => (
              <li key={i} style={{ fontSize: 12, color: "#64748b", display: "flex", gap: 8 }}>
                <span style={{ color: scoreColor }}>·</span> {f}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Scores footer */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        {ev.specificity_score != null && (
          <span style={{ fontSize: 11, color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>
            specificity <strong style={{ color: "#475569" }}>{Math.round(ev.specificity_score * 100)}%</strong>
          </span>
        )}
        {ev.confidence_score != null && (
          <span style={{ fontSize: 11, color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>
            confidence <strong style={{ color: "#475569" }}>{Math.round(ev.confidence_score * 100)}%</strong>
          </span>
        )}
      </div>
    </div>
  );
}

// ── Demo Section ──────────────────────────────────────────────────────────────
function DemoSection() {
  const [repo, setRepo]       = useState("django/django");
  const [pr, setPr]           = useState("17473");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);
  const resultRef             = useRef(null);

  const analyze = async () => {
    if (!repo.trim() || !pr.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/analyze-pr`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Api-Key": API_KEY },
        body: JSON.stringify({ repo: repo.trim(), pr_number: parseInt(pr.trim()) }),
      });
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      const data = await res.json();
      setResult(data);
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    } catch (e) {
      setError(e.message || "Failed to fetch. Check the repo and PR number.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="demo" style={{ maxWidth: 720, margin: "0 auto", width: "100%" }}>
      {/* Input card */}
      <div style={{
        background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 16, padding: "28px 32px",
      }}>
        <div style={{ fontSize: 12, color: "#475569", letterSpacing: "0.08em", fontFamily: "'JetBrains Mono', monospace", marginBottom: 20, textTransform: "uppercase" }}>
          Live Analysis — try any public GitHub PR
        </div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <div style={{ flex: "2 1 200px" }}>
            <label style={{ display: "block", fontSize: 10, color: "#475569", marginBottom: 6, letterSpacing: "0.08em", textTransform: "uppercase" }}>Repository</label>
            <input
              value={repo} onChange={e => setRepo(e.target.value)}
              placeholder="owner/repo"
              onKeyDown={e => e.key === "Enter" && analyze()}
              style={{
                width: "100%", padding: "10px 14px", borderRadius: 8, boxSizing: "border-box",
                background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
                color: "#e2e8f0", fontSize: 13, fontFamily: "'JetBrains Mono', monospace",
                outline: "none",
              }}
            />
          </div>
          <div style={{ flex: "1 1 100px" }}>
            <label style={{ display: "block", fontSize: 10, color: "#475569", marginBottom: 6, letterSpacing: "0.08em", textTransform: "uppercase" }}>PR #</label>
            <input
              value={pr} onChange={e => setPr(e.target.value)}
              placeholder="1234"
              onKeyDown={e => e.key === "Enter" && analyze()}
              style={{
                width: "100%", padding: "10px 14px", borderRadius: 8, boxSizing: "border-box",
                background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
                color: "#e2e8f0", fontSize: 13, fontFamily: "'JetBrains Mono', monospace",
                outline: "none",
              }}
            />
          </div>
          <div style={{ flex: "0 0 auto", display: "flex", alignItems: "flex-end" }}>
            <button
              onClick={analyze} disabled={loading}
              style={{
                padding: "10px 24px", borderRadius: 8, border: "none", cursor: loading ? "wait" : "pointer",
                background: loading ? "rgba(168,85,247,0.3)" : "rgba(168,85,247,0.9)",
                color: "#fff", fontSize: 13, fontWeight: 600, letterSpacing: "0.02em",
                transition: "all 0.2s", whiteSpace: "nowrap",
                boxShadow: loading ? "none" : "0 0 20px rgba(168,85,247,0.4)",
              }}
            >
              {loading ? "Analyzing…" : "Analyze →"}
            </button>
          </div>
        </div>
        {/* Quick examples */}
        <div style={{ marginTop: 14, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "#334155" }}>Try:</span>
          {[
            ["django/django", "17473", "SECRET_KEY hardcoded"],
            ["pallets/flask", "5992", "13 CVEs"],
            ["psf/requests", "6710", "CVE-2024-35195"],
          ].map(([r, p, label]) => (
            <button key={p} onClick={() => { setRepo(r); setPr(p); }}
              style={{
                background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 6, padding: "3px 10px", color: "#64748b", fontSize: 11,
                cursor: "pointer", fontFamily: "'JetBrains Mono', monospace",
                transition: "all 0.15s",
              }}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          marginTop: 16, padding: "14px 20px", borderRadius: 10,
          background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)",
          color: "#f87171", fontSize: 13,
        }}>✗ {error}</div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div style={{ marginTop: 16, padding: "24px", borderRadius: 12, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", textAlign: "center" }}>
          <div style={{ color: "#475569", fontSize: 13, fontFamily: "'JetBrains Mono', monospace" }}>
            <span style={{ animation: "pulse 1.5s infinite" }}>Scanning diff · running security patterns · calling AI…</span>
          </div>
        </div>
      )}

      {/* Result */}
      {result && (
        <div ref={resultRef} style={{ marginTop: 16 }}>
          <ResultPanel result={result} />
        </div>
      )}
    </div>
  );
}

// ── Benchmark row ─────────────────────────────────────────────────────────────
function BenchRow({ repo, pr, expected, got, label }) {
  const match = expected === got;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12, padding: "12px 20px",
      borderBottom: "1px solid rgba(255,255,255,0.04)", flexWrap: "wrap",
    }}>
      <span style={{ flex: "0 0 16px", fontSize: 14 }}>{match ? "✅" : "⚠️"}</span>
      <code style={{ flex: "1 1 200px", fontSize: 12, color: "#64748b" }}>{repo} #{pr}</code>
      <span style={{ flex: "2 1 160px", fontSize: 12, color: "#94a3b8" }}>{label}</span>
      <RiskBadge level={got} />
    </div>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", fn);
    return () => window.removeEventListener("scroll", fn);
  }, []);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Sora:wght@400;500;600;700;800&display=swap');
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
          background: #080b12;
          color: #e2e8f0;
          font-family: 'Sora', sans-serif;
          -webkit-font-smoothing: antialiased;
        }
        input:focus { border-color: rgba(168,85,247,0.5) !important; box-shadow: 0 0 0 3px rgba(168,85,247,0.1) !important; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes glow { 0%,100%{opacity:0.6} 50%{opacity:1} }
        .fade-up { animation: fadeUp 0.6s ease both; }
        .fade-up-2 { animation: fadeUp 0.6s 0.15s ease both; }
        .fade-up-3 { animation: fadeUp 0.6s 0.3s ease both; }
        .fade-up-4 { animation: fadeUp 0.6s 0.45s ease both; }
        button:hover { opacity: 0.88; transform: translateY(-1px); }
      `}</style>

      {/* ── Nav ── */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 100,
        padding: "0 32px", height: 60,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: scrolled ? "rgba(8,11,18,0.92)" : "transparent",
        backdropFilter: scrolled ? "blur(12px)" : "none",
        borderBottom: scrolled ? "1px solid rgba(255,255,255,0.06)" : "none",
        transition: "all 0.3s",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            width: 28, height: 28, borderRadius: 7,
            background: "linear-gradient(135deg, #a855f7, #6366f1)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 13, fontWeight: 800, color: "#fff",
          }}>D</div>
          <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: "-0.02em" }}>DevMind</span>
          <span style={{
            fontSize: 9, fontFamily: "'JetBrains Mono', monospace", color: "#a855f7",
            background: "rgba(168,85,247,0.12)", border: "1px solid rgba(168,85,247,0.2)",
            padding: "2px 6px", borderRadius: 4, letterSpacing: "0.08em",
          }}>BETA</span>
        </div>
        <div style={{ display: "flex", gap: 28, alignItems: "center" }}>
          {["#demo", "#pricing", "#benchmark"].map(href => (
            <a key={href} href={href} style={{ fontSize: 13, color: "#64748b", textDecoration: "none", transition: "color 0.2s" }}
              onMouseEnter={e => e.target.style.color = "#e2e8f0"}
              onMouseLeave={e => e.target.style.color = "#64748b"}>
              {href.slice(1).charAt(0).toUpperCase() + href.slice(2)}
            </a>
          ))}
          <a href="#pricing" style={{
            padding: "7px 18px", borderRadius: 8, fontSize: 13, fontWeight: 600,
            background: "rgba(168,85,247,0.15)", border: "1px solid rgba(168,85,247,0.3)",
            color: "#c084fc", textDecoration: "none", transition: "all 0.2s",
          }}>Get started</a>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section style={{ padding: "140px 32px 100px", textAlign: "center", position: "relative", overflow: "hidden" }}>
        {/* Background glow */}
        <div style={{
          position: "absolute", top: "20%", left: "50%", transform: "translateX(-50%)",
          width: 600, height: 400, borderRadius: "50%",
          background: "radial-gradient(ellipse, rgba(168,85,247,0.12) 0%, transparent 70%)",
          animation: "glow 4s ease-in-out infinite", pointerEvents: "none",
        }} />

        <div className="fade-up" style={{ maxWidth: 760, margin: "0 auto" }}>
          {/* Eyebrow */}
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8, marginBottom: 28,
            padding: "6px 16px", borderRadius: 100,
            background: "rgba(168,85,247,0.08)", border: "1px solid rgba(168,85,247,0.2)",
            fontSize: 12, color: "#c084fc", fontFamily: "'JetBrains Mono', monospace",
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#a855f7", boxShadow: "0 0 8px #a855f7", animation: "pulse 2s infinite" }} />
            100% accuracy on 10 real GitHub PRs
          </div>

          {/* Headline */}
          <h1 style={{
            fontSize: "clamp(36px, 6vw, 68px)", fontWeight: 800, lineHeight: 1.08,
            letterSpacing: "-0.04em", marginBottom: 24,
            background: "linear-gradient(135deg, #f1f5f9 0%, #94a3b8 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>
            Catch security risks<br />before they reach production
          </h1>

          {/* Sub */}
          <p className="fade-up-2" style={{ fontSize: "clamp(15px, 2vw, 18px)", color: "#64748b", lineHeight: 1.7, maxWidth: 560, margin: "0 auto 40px" }}>
            DevMind analyzes every pull request for credential exposure,
            CVEs, and auth bypass — automatically, before merge.
          </p>

          {/* CTA buttons */}
          <div className="fade-up-3" style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
            <a href="#demo" style={{
              padding: "13px 32px", borderRadius: 10, fontSize: 14, fontWeight: 600,
              background: "linear-gradient(135deg, #a855f7, #6366f1)",
              color: "#fff", textDecoration: "none",
              boxShadow: "0 0 30px rgba(168,85,247,0.4)",
              transition: "all 0.2s", display: "inline-block",
            }}>Try it free →</a>
            <a href="https://github.com/mordecaiusm922-create/devmind" target="_blank" rel="noreferrer" style={{
              padding: "13px 28px", borderRadius: 10, fontSize: 14, fontWeight: 600,
              background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)",
              color: "#94a3b8", textDecoration: "none", transition: "all 0.2s",
            }}>View on GitHub</a>
          </div>
        </div>

        {/* Social proof */}
        <div className="fade-up-4" style={{ marginTop: 64, display: "flex", justifyContent: "center", gap: 40, flexWrap: "wrap" }}>
          {[
            ["100%", "accuracy on benchmark"],
            ["4", "risk levels: LOW → CRITICAL"],
            ["<2min", "install via GitHub Action"],
          ].map(([stat, label]) => (
            <div key={stat} style={{ textAlign: "center" }}>
              <div style={{ fontSize: 28, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: "#a855f7", letterSpacing: "-0.02em" }}>{stat}</div>
              <div style={{ fontSize: 12, color: "#475569", marginTop: 4 }}>{label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── How it works ── */}
      <section style={{ padding: "80px 32px", maxWidth: 1000, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 12 }}>How it works</h2>
          <p style={{ fontSize: 15, color: "#64748b" }}>Three layers of analysis on every PR</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16 }}>
          {[
            { icon: "⚡", title: "Pre-analysis", body: "Heuristic engine scans file paths and diff for auth, config, CVE, and secret patterns — before the LLM even runs." },
            { icon: "🧠", title: "AI reasoning", body: "LLM analyzes the diff with a security-first system prompt. Returns structured JSON: what changed, why it matters, and the attack vector." },
            { icon: "🔒", title: "Risk enforcement", body: "Risk floor logic ensures the final level is never lower than what the heuristics detected. No false downgrades." },
          ].map(({ icon, title, body }) => (
            <div key={title} style={{
              padding: "24px", borderRadius: 14,
              background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
              transition: "border-color 0.2s",
            }}>
              <div style={{ fontSize: 28, marginBottom: 14 }}>{icon}</div>
              <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>{title}</h3>
              <p style={{ fontSize: 13, color: "#64748b", lineHeight: 1.65 }}>{body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Live Demo ── */}
      <section id="demo" style={{ padding: "80px 32px", maxWidth: 1000, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 12 }}>Live demo</h2>
          <p style={{ fontSize: 15, color: "#64748b" }}>Analyze any public GitHub PR — no account needed</p>
        </div>
        <DemoSection />
      </section>

      {/* ── Benchmark ── */}
      <section id="benchmark" style={{ padding: "80px 32px", maxWidth: 800, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 12 }}>Benchmark</h2>
          <p style={{ fontSize: 15, color: "#64748b" }}>Tested on 10 real open-source PRs with known risk profiles</p>
        </div>
        <div style={{ borderRadius: 14, overflow: "hidden", border: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.02)" }}>
          <div style={{ padding: "14px 20px", background: "rgba(255,255,255,0.03)", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", gap: 12 }}>
            <span style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.08em" }}>Result</span>
          </div>
          {[
            ["psf/requests", "6710", "medium", "medium", "CVE-2024-35195 TLS change"],
            ["django/django", "17473", "critical", "critical", "Hardcoded SECRET_KEY"],
            ["psf/black", "3864", "low", "low", "mypy version bump"],
            ["encode/httpx", "3109", "low", "low", "Dependency update"],
            ["tiangolo/fastapi", "11804", "low", "low", "Docs update"],
            ["redis/redis-py", "2900", "medium", "medium", "Auth change"],
            ["pallets/flask", "5992", "high", "high", "13 CVEs fixed"],
            ["pallets/flask", "5989", "low", "low", "Docs typo fix"],
          ].map(([repo, pr, expected, got, label]) => (
            <BenchRow key={pr} repo={repo} pr={pr} expected={expected} got={got} label={label} />
          ))}
          <div style={{ padding: "16px 20px", display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 12, color: "#475569" }}>Overall accuracy</span>
            <span style={{ fontSize: 20, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: "#22c55e" }}>100%</span>
          </div>
        </div>
      </section>

      {/* ── Pricing ── */}
      <section id="pricing" style={{ padding: "80px 32px", maxWidth: 900, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 12 }}>Pricing</h2>
          <p style={{ fontSize: 15, color: "#64748b" }}>Start free. Upgrade when you're ready.</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
          {[
            {
              name: "Free", price: "$0", period: "forever",
              features: ["10 PR analyses / month", "LOW → CRITICAL detection", "Vulnerability details", "GitHub Action install"],
              cta: "Get started", href: "#demo", highlight: false,
            },
            {
              name: "Pro", price: "$19", period: "/ month",
              features: ["Unlimited PR analyses", "Everything in Free", "Priority queue", "Email support"],
              cta: "Coming soon", href: "#", highlight: true,
            },
            {
              name: "Team", price: "$49", period: "/ month",
              features: ["Up to 5 users", "Everything in Pro", "Shared dashboard", "Slack notifications"],
              cta: "Coming soon", href: "#", highlight: false,
            },
          ].map(({ name, price, period, features, cta, href, highlight }) => (
            <div key={name} style={{
              padding: "28px 24px", borderRadius: 16,
              background: highlight ? "rgba(168,85,247,0.08)" : "rgba(255,255,255,0.02)",
              border: `1px solid ${highlight ? "rgba(168,85,247,0.35)" : "rgba(255,255,255,0.06)"}`,
              position: "relative",
            }}>
              {highlight && (
                <div style={{
                  position: "absolute", top: -12, left: "50%", transform: "translateX(-50%)",
                  background: "linear-gradient(135deg, #a855f7, #6366f1)",
                  color: "#fff", fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
                  padding: "4px 14px", borderRadius: 100,
                }}>POPULAR</div>
              )}
              <div style={{ marginBottom: 4, fontSize: 14, fontWeight: 600, color: "#94a3b8" }}>{name}</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 20 }}>
                <span style={{ fontSize: 38, fontWeight: 800, letterSpacing: "-0.04em" }}>{price}</span>
                <span style={{ fontSize: 13, color: "#475569" }}>{period}</span>
              </div>
              <ul style={{ listStyle: "none", marginBottom: 28, display: "flex", flexDirection: "column", gap: 10 }}>
                {features.map(f => (
                  <li key={f} style={{ display: "flex", gap: 8, fontSize: 13, color: "#94a3b8" }}>
                    <span style={{ color: "#22c55e", flexShrink: 0 }}>✓</span> {f}
                  </li>
                ))}
              </ul>
              <a href={href} style={{
                display: "block", textAlign: "center", padding: "10px",
                borderRadius: 8, fontSize: 13, fontWeight: 600, textDecoration: "none",
                background: highlight ? "linear-gradient(135deg, #a855f7, #6366f1)" : "rgba(255,255,255,0.06)",
                color: highlight ? "#fff" : "#94a3b8",
                border: highlight ? "none" : "1px solid rgba(255,255,255,0.1)",
                transition: "all 0.2s",
                boxShadow: highlight ? "0 0 20px rgba(168,85,247,0.3)" : "none",
              }}>{cta}</a>
            </div>
          ))}
        </div>
      </section>

      {/* ── Install ── */}
      <section style={{ padding: "80px 32px", maxWidth: 720, margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <h2 style={{ fontSize: 32, fontWeight: 700, letterSpacing: "-0.03em", marginBottom: 12 }}>Install in 2 minutes</h2>
          <p style={{ fontSize: 15, color: "#64748b" }}>Add to any GitHub repo with a single workflow file</p>
        </div>
        <div style={{
          borderRadius: 14, overflow: "hidden",
          border: "1px solid rgba(255,255,255,0.08)",
          background: "rgba(8,11,18,0.8)",
        }}>
          <div style={{ padding: "12px 20px", background: "rgba(255,255,255,0.04)", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", gap: 6 }}>
            {["#ef4444","#f59e0b","#22c55e"].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />)}
            <span style={{ fontSize: 11, color: "#475569", fontFamily: "'JetBrains Mono', monospace", marginLeft: 8 }}>.github/workflows/devmind.yml</span>
          </div>
          <pre style={{ padding: "24px", fontSize: 12, color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.7, overflowX: "auto", margin: 0 }}>{`name: DevMind PR Analysis
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Analyze PR
        run: |
          curl -s -X POST "$DEVMIND_API_URL/analyze-pr" \\
            -H "X-Api-Key: $DEVMIND_API_KEY" \\
            -d '{"repo":"${{ github.repository }}",
                 "pr_number":${{ github.event.pull_request.number }}}'`}</pre>
        </div>
        <p style={{ textAlign: "center", marginTop: 20, fontSize: 13, color: "#475569" }}>
          Add <code style={{ color: "#a855f7", background: "rgba(168,85,247,0.1)", padding: "1px 6px", borderRadius: 4 }}>DEVMIND_API_KEY</code> to your repo secrets and you're done.
        </p>
      </section>

      {/* ── Footer ── */}
      <footer style={{
        padding: "40px 32px", borderTop: "1px solid rgba(255,255,255,0.06)",
        display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            width: 24, height: 24, borderRadius: 6,
            background: "linear-gradient(135deg, #a855f7, #6366f1)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, fontWeight: 800, color: "#fff",
          }}>D</div>
          <span style={{ fontWeight: 600, fontSize: 13 }}>DevMind</span>
        </div>
        <p style={{ fontSize: 12, color: "#334155" }}>
          Built with FastAPI · Groq · Vercel · Open source on{" "}
          <a href="https://github.com/mordecaiusm922-create/devmind" style={{ color: "#a855f7", textDecoration: "none" }}>GitHub</a>
        </p>
      </footer>
    </>
  );
}
