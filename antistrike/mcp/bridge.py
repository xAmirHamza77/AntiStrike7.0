"""MCP bridge — exposes Antistrike 7.0 tools to AI assistants."""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from antistrike import __version__

DEFAULT_SERVER = "http://127.0.0.1:7700"

mcp = FastMCP("antistrike")


class AntistrikeClient:
    """HTTP client for Antistrike API."""

    def __init__(self, base_url: str = DEFAULT_SERVER, timeout: int = 600) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def get(self, path: str) -> dict[str, Any]:
        resp = self._client.get(f"{self.base_url}{path}")
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.post(f"{self.base_url}{path}", json=data)
        resp.raise_for_status()
        return resp.json()

    def health(self) -> bool:
        try:
            result = self.get("/api/health")
            return result.get("status") == "operational"
        except Exception:
            return False


client: AntistrikeClient | None = None


def _ensure_client() -> AntistrikeClient:
    global client
    if client is None:
        client = AntistrikeClient()
    return client


# ── Authorization ──────────────────────────────────────────

@mcp.tool()
def register_scope(
    target: str,
    authorized_by: str,
    in_scope: list[str] | None = None,
    depth: str = "standard",
    allowed_profiles: list[str] | None = None,
) -> str:
    """Register authorized testing scope before any attacks. REQUIRED before scanning."""
    c = _ensure_client()
    result = c.post("/api/auth/scope", {
        "target": target,
        "authorized_by": authorized_by,
        "in_scope": in_scope or [target],
        "depth": depth,
        "allowed_profiles": allowed_profiles or ["full_spectrum"],
    })
    return json.dumps(result, indent=2)


@mcp.tool()
def validate_authorization(target: str) -> str:
    """Check if a target has confirmed authorization."""
    c = _ensure_client()
    return json.dumps(c.get(f"/api/auth/validate/{target}"), indent=2)


# ── Scanning ─────────────────────────────────────────────

@mcp.tool()
def run_vulnerability_scan(
    target: str,
    depth: str = "standard",
    attack_types: list[str] | None = None,
) -> str:
    """Run built-in vulnerability scan. Depths: quick, standard, deep, exhaustive."""
    c = _ensure_client()
    result = c.post("/api/attacks/scan", {
        "target": target,
        "depth": depth,
        "attack_types": attack_types or [],
    })
    return json.dumps(result, indent=2)


@mcp.tool()
def run_tool_module(target: str, tool: str, extra_args: str = "") -> str:
    """Execute a specific attack module (e.g. port_scan, sqli_scan, vuln_scan)."""
    c = _ensure_client()
    result = c.post("/api/attacks/tool", {
        "target": target,
        "tool": tool,
        "extra_args": extra_args,
    })
    return json.dumps(result, indent=2)


@mcp.tool()
def run_profile_assessment(
    target: str,
    profile: str = "web",
    depth: str = "standard",
) -> str:
    """Run full profile assessment. Profiles: web, api, network, cloud, mobile, binary, full_spectrum."""
    c = _ensure_client()
    result = c.post("/api/attacks/profile", {
        "target": target,
        "profile": profile,
        "depth": depth,
    })
    return json.dumps(result, indent=2)


@mcp.tool()
def create_attack_chain(target: str, findings_json: str = "[]") -> str:
    """Analyze findings and suggest vulnerability chaining opportunities."""
    c = _ensure_client()
    findings = json.loads(findings_json)
    result = c.post("/api/attacks/chain", {"target": target, "findings": findings})
    return json.dumps(result, indent=2)


# ── Tools & Payloads ───────────────────────────────────────

@mcp.tool()
def list_modules(category: str = "") -> str:
    """List all available attack modules and their status."""
    c = _ensure_client()
    path = "/api/tools/"
    if category:
        path += f"?category={category}"
    return json.dumps(c.get(path), indent=2)


@mcp.tool()
def list_attack_types() -> str:
    """List all supported attack/vulnerability types."""
    c = _ensure_client()
    return json.dumps(c.get("/api/tools/attack-types"), indent=2)


@mcp.tool()
def get_payloads(attack_type: str) -> str:
    """Get payload library for an attack type (sqli, xss, ssrf, lfi, ssti, etc.)."""
    c = _ensure_client()
    return json.dumps(c.get(f"/api/tools/payloads/{attack_type}"), indent=2)


# ── Agents ───────────────────────────────────────────────

@mcp.tool()
def spawn_agent_team(target: str, roles: list[str] | None = None) -> str:
    """Spawn multi-agent testing team. Roles: recon, web_attacker, api_specialist, network_scanner, cloud_auditor."""
    c = _ensure_client()
    result = c.post("/api/agents/spawn", {
        "target": target,
        "roles": roles or [],
    })
    return json.dumps(result, indent=2)


@mcp.tool()
def view_agent_graph() -> str:
    """View current agent coordination graph."""
    c = _ensure_client()
    return json.dumps(c.get("/api/agents/graph"), indent=2)


# ── Reporting ────────────────────────────────────────────

@mcp.tool()
def generate_report(target: str, findings_json: str = "[]", formats: list[str] | None = None) -> str:
    """Generate assessment report. Formats: json, sarif, executive."""
    c = _ensure_client()
    findings = json.loads(findings_json)
    result = c.post("/api/attacks/report", {
        "target": target,
        "findings": findings,
        "formats": formats or ["json", "sarif", "executive"],
    })
    return json.dumps(result, indent=2)


# ── System ───────────────────────────────────────────────

@mcp.tool()
def server_health() -> str:
    """Check Antistrike server health and version."""
    c = _ensure_client()
    return json.dumps(c.get("/api/health"), indent=2)


@mcp.tool()
def server_stats() -> str:
    """Get system stats, module availability, and payload counts."""
    c = _ensure_client()
    return json.dumps(c.get("/api/stats"), indent=2)


@mcp.tool()
def execute_command(command: str, timeout: int = 300) -> str:
    """Execute a shell command through the Antistrike engine (authorized targets only)."""
    c = _ensure_client()
    result = c.post("/api/command", {"command": command, "timeout": timeout})
    return json.dumps(result, indent=2)


@mcp.tool()
def list_jobs() -> str:
    """List all scan jobs and their status."""
    c = _ensure_client()
    return json.dumps(c.get("/api/jobs"), indent=2)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Antistrike 7.0 MCP Bridge")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="Antistrike API URL")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    global client
    client = AntistrikeClient(args.server)

    if not client.health():
        print(f"Warning: Antistrike server not reachable at {args.server}", file=sys.stderr)
        print("Start the server first: antistrike-server", file=sys.stderr)
    else:
        health = client.get("/api/health")
        print(f"Connected to Antistrike {health.get('version', '?')} [{health.get('codename', '')}]", file=sys.stderr)

    mcp.run()


if __name__ == "__main__":
    main()