from __future__ import annotations
import urllib.request
import json
from dataclasses import dataclass, field

@dataclass
class CVEFinding:
    package: str
    version: str
    cve_id: str
    severity: str
    description: str
    score: float = 0.0
    fix_version: str = ""

@dataclass 
class CVEResult:
    findings: list[CVEFinding] = field(default_factory=list)
    has_critical: bool = False
    has_high: bool = False
    block_merge: bool = False
    checked_packages: list[str] = field(default_factory=list)

def _parse_deps(files: list[dict]) -> dict[str, str]:
    packages = {}
    for f in files:
        fname = f.get("filename", "").lower()
        content = f.get("content", "") or f.get("patch", "") or ""
        if "requirements" in fname and fname.endswith(".txt"):
            for line in content.splitlines():
                line = line.strip()
                if "==" in line and not line.startswith("#"):
                    pkg, ver = line.split("==", 1)
                    packages[pkg.strip().lower()] = ver.strip()
        elif fname == "package.json":
            try:
                data = json.loads(content)
                for pkg, ver in {**data.get("dependencies",{}), **data.get("devDependencies",{})}.items():
                    packages[pkg.lower()] = ver.lstrip("^~")
            except Exception:
                pass
    return packages

def _get_severity(vuln: dict) -> tuple[str, float]:
    """Extrae severidad de cualquier campo donde OSV la ponga."""
    # 1. Campo severity con CVSS
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "0")
        try:
            score = float(score_str)
            if score >= 9.0: return "critical", score
            elif score >= 7.0: return "high", score
            elif score >= 4.0: return "medium", score
            else: return "low", score
        except Exception:
            pass
    
    # 2. database_specific (GitHub Advisory)
    db = vuln.get("database_specific", {})
    gh_sev = db.get("severity", "").lower()
    if gh_sev == "critical": return "critical", 9.5
    elif gh_sev == "high": return "high", 7.5
    elif gh_sev == "moderate": return "medium", 5.5
    elif gh_sev == "low": return "low", 2.0

    # 3. Por keywords en el summary
    summary = (vuln.get("summary", "") + vuln.get("details", "")).lower()
    if any(k in summary for k in ["arbitrary code", "remote code", "rce", "sql injection", "authentication bypass"]):
        return "critical", 9.0
    if any(k in summary for k in ["denial of service", "information disclosure", "privilege escalation"]):
        return "high", 7.5

    return "medium", 5.0

def check_cves(files: list[dict]) -> CVEResult:
    packages = _parse_deps(files)
    result = CVEResult(checked_packages=list(packages.keys()))
    if not packages:
        return result

    for pkg, version in list(packages.items())[:10]:
        try:
            payload = json.dumps({
                "package": {"name": pkg, "ecosystem": "PyPI"},
                "version": version
            }).encode()
            req = urllib.request.Request(
                "https://api.osv.dev/v1/query",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())

            for vuln in data.get("vulns", [])[:3]:
                cve_id = vuln.get("id", "")
                # Preferir CVE id sobre GHSA
                for alias in vuln.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

                summary = vuln.get("summary", vuln.get("details", ""))[:200]
                severity, score = _get_severity(vuln)

                fix_ver = ""
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                fix_ver = evt["fixed"]
                                break

                finding = CVEFinding(
                    package=pkg,
                    version=version,
                    cve_id=cve_id,
                    severity=severity,
                    description=summary,
                    score=score,
                    fix_version=fix_ver
                )
                result.findings.append(finding)
                if severity == "critical":
                    result.has_critical = True
                    result.block_merge = True
                elif severity == "high":
                    result.has_high = True
        except Exception:
            continue

    return result
