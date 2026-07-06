"""Attack orchestrator — intelligent scan planning and execution."""

from __future__ import annotations

from typing import Any

from antistrike.core.authorization import AttackProfile, ScanDepth, auth_gate
from antistrike.core.engine import engine
from antistrike.modules.attacks.scanner import BuiltinScanner
from antistrike.tools.registry import TOOL_REGISTRY, get_tool

# Depth → which attack types to run
DEPTH_ATTACK_MAP: dict[str, list[str]] = {
    "quick": ["sqli", "xss", "open_redirect", "cors"],
    "standard": ["sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect", "cors", "cmdi"],
    "deep": [
        "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect", "cors",
        "cmdi", "nosql", "xxe", "prototype_pollution", "host_header",
    ],
    "exhaustive": list({
        t for spec in TOOL_REGISTRY for t in spec.attack_types
    }),
}

# Profile → preferred tools
PROFILE_TOOLS: dict[str, list[str]] = {
    "web": ["dir_brute", "vuln_scan", "sqli_scan", "xss_scan", "param_discover", "web_crawl"],
    "api": ["api_fuzz", "graphql_scan", "jwt_analyze", "param_discover", "oauth_scan"],
    "network": ["port_scan", "service_enum", "smb_enum", "snmp_enum"],
    "cloud": ["aws_audit", "container_scan", "k8s_hunt", "iac_scan", "s3_enum"],
    "mobile": ["apk_analyze", "mobile_api"],
    "binary": ["binary_analyze", "rop_chain", "firmware_scan"],
    "full_spectrum": [
        "subdomain_enum", "port_scan", "dir_brute", "vuln_scan",
        "sqli_scan", "xss_scan", "ssrf_scan", "api_fuzz",
        "secret_scan", "sast_scan",
    ],
}

PRIORITY_WEIGHTS: dict[str, int] = {
    "rce": 10, "sqli": 9, "ssrf": 8, "idor": 8, "xss": 7,
    "lfi": 7, "xxe": 6, "deserialization": 6, "csrf": 5,
    "open_redirect": 4, "cors": 3, "info_disclosure": 2,
}


class AttackOrchestrator:
    """Plans and executes multi-phase attack campaigns."""

    def run_builtin_scan(
        self,
        target: str,
        depth: str = "standard",
        attack_types: list[str] | None = None,
    ) -> dict[str, Any]:
        auth = auth_gate.validate_target(target)
        if not auth.get("authorized"):
            return {"success": False, "error": auth.get("error")}

        job = engine.create_job(target, "builtin_scan")
        job.status = "running"

        types = attack_types or DEPTH_ATTACK_MAP.get(depth, DEPTH_ATTACK_MAP["standard"])
        scanner = BuiltinScanner(target)
        try:
            result = scanner.scan(types)
            job.findings = result["findings"]
            job.status = "completed"
            job.result = result
            return {"success": True, "job_id": job.job_id, **result}
        except Exception as e:
            job.status = "failed"
            job.result = {"error": str(e)}
            return {"success": False, "error": str(e)}
        finally:
            scanner.close()

    def run_tool_scan(
        self,
        target: str,
        tool_name: str,
        extra_args: str = "",
    ) -> dict[str, Any]:
        auth = auth_gate.validate_target(target)
        if not auth.get("authorized"):
            return {"success": False, "error": auth.get("error")}

        spec = get_tool(tool_name)
        if not spec:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        job = engine.create_job(target, tool_name)
        job.status = "running"

        if spec.builtin:
            return self.run_builtin_scan(target, attack_types=spec.attack_types)

        if not spec.is_available():
            job.status = "failed"
            return {
                "success": False,
                "error": f"Tool binary '{spec.binary}' not found on PATH",
                "install_hint": f"Install {spec.binary} to enable this module",
            }

        command = self._build_tool_command(spec.name, spec.binary or "", target, extra_args)
        result = engine.execute_with_recovery(command)
        job.status = "completed" if result.success else "failed"
        job.result = result.to_dict()
        return {"success": result.success, "job_id": job.job_id, **result.to_dict()}

    def run_profile_scan(
        self,
        target: str,
        profile: str = "web",
        depth: str = "standard",
    ) -> dict[str, Any]:
        auth = auth_gate.validate_target(target)
        if not auth.get("authorized"):
            return {"success": False, "error": auth.get("error")}

        tools = PROFILE_TOOLS.get(profile, PROFILE_TOOLS["web"])
        results = []
        builtin_types = DEPTH_ATTACK_MAP.get(depth, DEPTH_ATTACK_MAP["standard"])

        builtin_result = self.run_builtin_scan(target, depth=depth, attack_types=builtin_types)
        results.append({"module": "builtin_scanner", **builtin_result})

        for tool_name in tools:
            spec = get_tool(tool_name)
            if spec and spec.is_available():
                tool_result = self.run_tool_scan(target, tool_name)
                results.append({"module": tool_name, **tool_result})

        all_findings = []
        for r in results:
            if r.get("findings"):
                all_findings.extend(r["findings"])

        return {
            "success": True,
            "target": target,
            "profile": profile,
            "depth": depth,
            "modules_run": len(results),
            "findings": all_findings,
            "total_findings": len(all_findings),
            "module_results": results,
        }

    def create_attack_chain(self, target: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Suggest vulnerability chains from discovered findings."""
        chains = []
        types_found = {f.get("attack_type", "") for f in findings}

        chain_rules = [
            ({"ssrf"}, {"lfi", "rce"}, "SSRF → Internal Service Access → RCE"),
            ({"xss"}, {"csrf", "session"}, "XSS → Session Hijacking → Account Takeover"),
            ({"sqli"}, {"idor"}, "SQLi → Data Extraction → Credential Reuse"),
            ({"lfi"}, {"rce"}, "LFI → Log Poisoning → RCE"),
            ({"idor"}, {"privilege_escalation"}, "IDOR → Privilege Escalation → Admin Access"),
            ({"open_redirect"}, {"phishing"}, "Open Redirect → Phishing → Credential Theft"),
            ({"cors"}, {"xss"}, "CORS Misconfig → Cross-Origin Data Theft"),
            ({"jwt"}, {"auth_bypass"}, "JWT Weakness → Authentication Bypass"),
            ({"ssrf"}, {"cloud"}, "SSRF → Cloud Metadata → Credential Exposure"),
        ]

        for triggers, followups, description in chain_rules:
            if types_found & triggers:
                chains.append({
                    "description": description,
                    "triggered_by": list(types_found & triggers),
                    "potential_followups": list(followups),
                    "priority": max(PRIORITY_WEIGHTS.get(t, 5) for t in triggers),
                })

        chains.sort(key=lambda c: c["priority"], reverse=True)
        return {"target": target, "chains": chains, "total": len(chains)}

    def _build_tool_command(
        self, tool_name: str, binary: str, target: str, extra_args: str
    ) -> str:
        builders = {
            "port_scan": f"nmap -sV -sC -T4 {target} {extra_args}",
            "fast_port_scan": f"rustscan -a {target} -- -sV {extra_args}",
            "dir_brute": f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 {extra_args}",
            "vuln_scan": f"nuclei -u {target} -severity critical,high,medium {extra_args}",
            "sqli_scan": f"sqlmap -u {target} --batch --level=3 --risk=2 {extra_args}",
            "xss_scan": f"dalfox url {target} {extra_args}",
            "subdomain_enum": f"subfinder -d {target} -silent {extra_args}",
            "web_crawl": f"katana -u {target} -d 3 -jc {extra_args}",
            "param_discover": f"arjun -u {target} {extra_args}",
            "secret_scan": f"gitleaks detect --source {target} {extra_args}",
            "sast_scan": f"semgrep --config auto {target} {extra_args}",
            "aws_audit": f"prowler aws {extra_args}",
            "container_scan": f"trivy fs {target} {extra_args}",
            "k8s_hunt": f"kube-hunter --remote {target} {extra_args}",
            "brute_force": f"hydra -L users.txt -P passwords.txt {target} http-post-form {extra_args}",
            "jwt_analyze": f"jwt_tool {target} {extra_args}",
        }
        return builders.get(tool_name, f"{binary} {target} {extra_args}".strip())


orchestrator = AttackOrchestrator()