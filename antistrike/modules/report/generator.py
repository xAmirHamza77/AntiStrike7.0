"""Report generator — findings, SARIF, and executive summaries."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from antistrike.core.config import RUNS_DIR


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportGenerator:
    """Generates assessment reports in multiple formats."""

    def generate_executive_summary(
        self,
        target: str,
        findings: list[dict[str, Any]],
        scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        severity_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = (
            severity_counts.get("critical", 0) * 10
            + severity_counts.get("high", 0) * 7
            + severity_counts.get("medium", 0) * 4
            + severity_counts.get("low", 0) * 1
        )

        posture = "critical" if risk_score > 50 else "high" if risk_score > 25 else "medium" if risk_score > 10 else "low"

        return {
            "title": f"Antistrike 7.0 Assessment Report",
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": scope,
            "summary": {
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
                "risk_score": risk_score,
                "security_posture": posture,
            },
            "top_findings": sorted(
                findings,
                key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info").lower(), 5),
            )[:10],
            "recommendations": self._generate_recommendations(findings),
        }

    def generate_sarif(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        rules = []
        results = []
        for i, f in enumerate(findings):
            rule_id = f"AS7-{f.get('attack_type', 'unknown').upper()}-{i+1:03d}"
            rules.append({
                "id": rule_id,
                "name": f.get("title", "Unknown"),
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("evidence", "")},
                "defaultConfiguration": {
                    "level": self._sarif_level(f.get("severity", "info")),
                },
            })
            results.append({
                "ruleId": rule_id,
                "level": self._sarif_level(f.get("severity", "info")),
                "message": {"text": f.get("title", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("location", "")},
                    },
                }],
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Antistrike",
                        "version": "7.0.0",
                        "informationUri": "https://antistrike.dev",
                        "rules": rules,
                    },
                },
                "results": results,
            }],
        }

    def save_report(
        self,
        target: str,
        findings: list[dict[str, Any]],
        formats: list[str] | None = None,
    ) -> dict[str, Any]:
        formats = formats or ["json", "sarif", "executive"]
        safe_target = target.replace("/", "_").replace(":", "_")
        report_dir = RUNS_DIR / safe_target / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        saved = []

        if "executive" in formats:
            summary = self.generate_executive_summary(target, findings)
            path = report_dir / f"executive_{ts}.json"
            with open(path, "w") as f:
                json.dump(summary, f, indent=2)
            saved.append(str(path))

        if "sarif" in formats:
            sarif = self.generate_sarif(findings)
            path = report_dir / f"findings_{ts}.sarif.json"
            with open(path, "w") as f:
                json.dump(sarif, f, indent=2)
            saved.append(str(path))

        if "json" in formats:
            path = report_dir / f"findings_{ts}.json"
            with open(path, "w") as f:
                json.dump(findings, f, indent=2)
            saved.append(str(path))

        return {"saved_files": saved, "report_dir": str(report_dir)}

    def _sarif_level(self, severity: str) -> str:
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        return mapping.get(severity.lower(), "note")

    def _generate_recommendations(self, findings: list[dict[str, Any]]) -> list[str]:
        recs = set()
        types = {f.get("attack_type", "") for f in findings}
        rec_map = {
            "sqli": "Implement parameterized queries and input validation for all database interactions",
            "xss": "Apply context-aware output encoding and Content Security Policy headers",
            "ssrf": "Validate and whitelist outbound URLs; block access to internal networks",
            "lfi": "Avoid user-controlled file paths; implement strict path canonicalization",
            "ssti": "Never pass user input to template engines; use sandboxed rendering",
            "cors": "Restrict Access-Control-Allow-Origin to trusted domains only",
            "jwt": "Use strong signing algorithms; validate all claims; rotate keys regularly",
            "idor": "Implement object-level authorization checks on every request",
            "cmdi": "Avoid shell execution; use safe APIs with input sanitization",
            "open_redirect": "Validate redirect URLs against an allowlist of trusted destinations",
        }
        for t in types:
            if t in rec_map:
                recs.add(rec_map[t])
        if not recs:
            recs.add("Continue regular security assessments and dependency updates")
        return sorted(recs)


reporter = ReportGenerator()