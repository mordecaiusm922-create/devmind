import { useState } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY  = import.meta.env.VITE_API_KEY  || "dev-key-insecure";

// ── Risk palette ──────────────────────────────────────────────────────────────
const RISK = {
  low:    { color: "#00c7a3", bg: "rgba(0,199,163,0.08)",  border: "rgba(0,199,163,0.2)",  label: "LOW"    },
  medium: { color: "#f59e0b", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.2)", label: "MEDIUM" },
  high:   { color: "#ef4444", bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.2)",  label: "HIGH"   },
};

const CONF = {
  high:   { color: "#00c7a3", label: "High confidence"   },
  medium: { color: "#f59e0b", label: "Medium confidence" },
  low:    { color: "#ef4444", label: "Low confidence"    },
};

// ── Tiny components ────────────────────────────────────────────────────────────
function Badge({ text, color, bg, border }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 8px", borderRadius: 4,
      border: `1px solid ${border}`,
      background: bg, color, fontFamily: "var(--mono)",
      fontSize: 11, fontWeight: 600, letterSpacing: "0.08em",
    }}>{text}</span>
  );
}

function Field({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--muted)",
                    textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.65 }}>{value}</div>
    </div>
  );
}

function Card({ children, style }) {
  return (
    <div style={{
      background: "var(--surface)", border: "1px solid var(--border)",
      borderRadius: 8, padding: "20px 22px", ...style,
    }}>
      {children}
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div style={{
      fontFamily: "var(--mono)", fontSize: 10, color: "var(--muted)",
      textTransform: "uppercase", letterSpacing: "0.14em",
      marginBottom: 12, display: "flex", alignItems: "center", gap: 8,
    }}>
      <span style={{ width: 16, height: 1, background: "var(--border2)", display: "inline-block" }} />
      {children}
    </div>
  );
}

// ── Main app ───────────────────────────────────────────────────────────────────
export default function App() {
  const [repo,     setRepo]     = useState("");
  const [prNum,    setPrNum]    = useState("");
  const [loading,  setLoading]  = useState(false);
  const [result,   setResult]   = useState(null);
  const [error,    setError]    = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    if (!repo.trim() || !prNum) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/analyze-pr`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": API_KEY,
        },
        body: JSON.stringify({ repo: repo.trim(), pr_number: parseInt(prNum) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Error ${res.status}`);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Derived
  const riskObj   = result?.summary?.risk || {};
  const riskLevel = (typeof riskObj === "object" ? riskObj.level : "low") || "low";
  const riskReason= typeof riskObj === "object" ? riskObj.reason : "";
  const riskStyle = RISK[riskLevel] || RISK.low;
  const confLevel = result?.evaluation?.confidence || "medium";
  const confStyle = CONF[confLevel] || CONF.medium;
  const ev        = result?.evaluation || {};
  const pre       = result?.pre_analysis || {};
  const summary   = result?.summary || {};

  return (
    <div style={{ maxWidth: 760, margin: "0 auto", padding: "48px 24px 80px" }}>
      {/* Header */}
      <div style={{ marginBottom: 40 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 13, color: "var(--accent)",
                         fontWeight: 600, letterSpacing: "0.04em" }}>▸ DEVMIND</span>
          <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--muted)",
                         border: "1px solid var(--border)", borderRadius: 3,
                         padding: "1px 6px" }}>v1.0</span>
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 500, color: "var(--text)",
                     letterSpacing: "-0.02em", lineHeight: 1.2 }}>
          PR Analysis
        </h1>
        <p style={{ color: "var(--muted)", marginTop: 6, fontSize: 13 }}>
          Instant risk assessment and technical summary for any GitHub pull request.
        </p>
      </div>

      {/* Input form */}
      <Card style={{ marginBottom: 24 }}>
        <form onSubmit={handleSubmit}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input
              value={repo}
              onChange={e => setRepo(e.target.value)}
              placeholder="owner/repo"
              spellCheck={false}
              style={inputStyle}
            />
            <input
              value={prNum}
              onChange={e => setPrNum(e.target.value)}
              placeholder="PR #"
              type="number"
              min="1"
              style={{ ...inputStyle, width: 90, flex: "none" }}
            />
            <button
              type="submit"
              disabled={loading || !repo || !prNum}
              style={btnStyle(loading || !repo || !prNum)}
            >
              {loading ? (
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <Spinner /> Analyzing…
                </span>
              ) : "Analyze →"}
            </button>
          </div>
        </form>
      </Card>

      {/* Error */}
      {error && (
        <div style={{
          background: "rgba(239,68,68,0.07)", border: "1px solid rgba(239,68,68,0.2)",
          borderRadius: 8, padding: "12px 16px", marginBottom: 16,
          fontFamily: "var(--mono)", fontSize: 12, color: "#ef4444",
        }}>
          ✗ {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

          {/* Meta bar */}
          <Card style={{ padding: "14px 22px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
              <div>
                <span style={metaLabelStyle}>Repo</span>
                <span style={metaValueStyle}>{result.repo}</span>
              </div>
              <div style={metaDivider} />
              <div>
                <span style={metaLabelStyle}>PR</span>
                <span style={metaValueStyle}>#{result.pr_number}</span>
              </div>
              <div style={metaDivider} />
              <div>
                <span style={metaLabelStyle}>Author</span>
                <span style={metaValueStyle}>@{result.author}</span>
              </div>
              <div style={metaDivider} />
              <div style={{ display: "flex", gap: 6 }}>
                <span style={{ ...metaValueStyle, color: "#00c7a3" }}>+{result.additions}</span>
                <span style={{ ...metaValueStyle, color: "#ef4444" }}>−{result.deletions}</span>
              </div>
              <div style={metaDivider} />
              <Badge text={riskStyle.label} color={riskStyle.color} bg={riskStyle.bg} border={riskStyle.border} />
              <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 7, height: 7, borderRadius: "50%",
                               background: confStyle.color, display: "inline-block" }} />
                <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                               color: confStyle.color }}>{confStyle.label}</span>
              </div>
            </div>
          </Card>

          {/* PR title */}
          <div style={{ paddingLeft: 2 }}>
            <h2 style={{ fontSize: 17, fontWeight: 500, color: "var(--text)",
                         letterSpacing: "-0.01em" }}>{result.title}</h2>
          </div>

          {/* Flag / hallucination warnings */}
          {ev.is_flagged && (
            <div style={warnBannerStyle}>
              <span style={{ color: "var(--warn)", marginRight: 6 }}>⚠</span>
              {ev.flag_reason}
            </div>
          )}
          {summary.hallucination_warning?.length > 0 && (
            <div style={warnBannerStyle}>
              <span style={{ color: "var(--warn)", marginRight: 6 }}>⚠</span>
              Possible hallucinations: {summary.hallucination_warning.join(", ")}
            </div>
          )}

          {/* Two-column: summary + risk */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Card>
              <SectionLabel>What</SectionLabel>
              <Field value={summary.what} />
              <SectionLabel>Why</SectionLabel>
              <Field value={summary.why} />
            </Card>

            <Card>
              <SectionLabel>Risk</SectionLabel>
              <div style={{ marginBottom: 12 }}>
                <Badge text={riskStyle.label} color={riskStyle.color}
                       bg={riskStyle.bg} border={riskStyle.border} />
                {pre.risk_tags?.length > 0 && (
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                                 color: "var(--muted)", marginLeft: 8 }}>
                    {pre.risk_tags.join(" · ")}
                  </span>
                )}
              </div>
              <p style={{ fontSize: 12, color: "#b0b0bc", lineHeight: 1.65 }}>{riskReason}</p>
              {pre.trivially_touched?.length > 0 && (
                <p style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--muted)",
                            marginTop: 8 }}>
                  ↓ dampened: {pre.trivially_touched.join(", ")}
                </p>
              )}
            </Card>
          </div>

          {/* Impact + review focus */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Card>
              <SectionLabel>Impact</SectionLabel>
              <Field value={summary.impact} />
            </Card>
            <Card>
              <SectionLabel>Review focus</SectionLabel>
              <Field value={summary.review_focus} />
            </Card>
          </div>

          {/* Key changes */}
          {(summary.key_changes || []).length > 0 && (
            <Card>
              <SectionLabel>Key changes</SectionLabel>
              <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: 8 }}>
                {summary.key_changes.map((change, i) => (
                  <li key={i} style={{ display: "flex", gap: 10, fontSize: 12, color: "#b0b0bc" }}>
                    <span style={{ color: "var(--accent)", fontFamily: "var(--mono)",
                                   flexShrink: 0 }}>→</span>
                    {change}
                  </li>
                ))}
              </ul>
            </Card>
          )}
{/* Evidence */}
          {(summary.evidence || []).length > 0 && (
            <Card>
              <SectionLabel>Evidence</SectionLabel>
              <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: 10 }}>
                {summary.evidence.map((ev, i) => (
                  <li key={i} style={{ fontSize: 12, color: "#b0b0bc" }}>
                    <span style={{ fontFamily: "var(--mono)", color: "var(--accent)", fontSize: 11 }}>
                      {ev.location}
                    </span>
                    <span style={{ margin: "0 8px", color: "var(--muted)" }}>—</span>
                    {ev.claim}
                    {ev.snippet && (
                      <div style={{
                        fontFamily: "var(--mono)", fontSize: 11,
                        background: "var(--surface2)", border: "1px solid var(--border)",
                        borderRadius: 4, padding: "4px 8px", marginTop: 6,
                        color: "#7dd3a8"
                      }}>
                        {ev.snippet}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </Card>
          )}
          {/* Footer: scores */}
          <div style={{ display: "flex", gap: 16, paddingTop: 4, paddingLeft: 2 }}>
            <span style={scoreStyle}>
              specificity <strong>{Math.round(ev.specificity_score * 100)}%</strong>
            </span>
            <span style={scoreStyle}>
              confidence score <strong>{(ev.confidence_score || 0).toFixed(2)}</strong>
            </span>
            {(ev.generic_phrases_found || []).length > 0 && (
              <span style={{ ...scoreStyle, color: "#f59e0b" }}>
                {ev.generic_phrases_found.length} generic phrase{ev.generic_phrases_found.length > 1 ? "s" : ""}
              </span>
            )}
            {summary.analysed_in_chunks && (
              <span style={scoreStyle}>⬡ {summary.analysed_in_chunks} chunks</span>
            )}
          </div>

        </div>
      )}
    </div>
  );
}

// ── Spinner ────────────────────────────────────────────────────────────────────
function Spinner() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none"
         style={{ animation: "spin 0.7s linear infinite" }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.5"
              strokeDasharray="20" strokeDashoffset="10" strokeLinecap="round"/>
    </svg>
  );
}

// ── Style constants ────────────────────────────────────────────────────────────
const inputStyle = {
  flex: 1, minWidth: 180,
  background: "var(--surface2)", border: "1px solid var(--border)",
  borderRadius: 6, padding: "8px 12px", color: "var(--text)",
  fontFamily: "var(--mono)", fontSize: 13,
  transition: "border-color 0.15s",
  outline: "none",
};

const btnStyle = (disabled) => ({
  background: disabled ? "var(--surface2)" : "var(--accent)",
  color:      disabled ? "var(--muted)"    : "#0c0c0e",
  border:     disabled ? "1px solid var(--border)" : "1px solid transparent",
  borderRadius: 6, padding: "8px 20px",
  fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600,
  cursor: disabled ? "default" : "pointer",
  transition: "all 0.15s", whiteSpace: "nowrap",
});

const metaLabelStyle = {
  fontFamily: "var(--mono)", fontSize: 10, color: "var(--muted)",
  textTransform: "uppercase", letterSpacing: "0.1em", marginRight: 5,
};

const metaValueStyle = {
  fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 500,
};

const metaDivider = {
  width: 1, height: 18, background: "var(--border)", flexShrink: 0,
};

const warnBannerStyle = {
  background: "rgba(245,158,11,0.07)", border: "1px solid rgba(245,158,11,0.2)",
  borderRadius: 6, padding: "10px 14px",
  fontFamily: "var(--mono)", fontSize: 11, color: "#c8924a", lineHeight: 1.5,
};

const scoreStyle = {
  fontFamily: "var(--mono)", fontSize: 10, color: "var(--muted)",
};
