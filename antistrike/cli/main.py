"""Antistrike 7.0 CLI — command-line interface."""

from __future__ import annotations

import json
import sys

import click

from antistrike import __version__
from antistrike.core.authorization import AttackProfile, EngagementScope, ScanDepth, auth_gate
from antistrike.core.theme import ui
from antistrike.modules.attacks.orchestrator import orchestrator
from antistrike.modules.report.generator import reporter
from antistrike.tools.registry import list_tools


@click.group()
@click.version_option(__version__, prog_name="Antistrike")
def main():
    """Antistrike 7.0 — Advanced Offensive Security Platform"""
    pass


@main.command()
def banner():
    """Display Antistrike banner."""
    ui.banner()


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=7700, type=int)
def serve(host: str, port: int):
    """Start the Antistrike API server."""
    ui.banner()
    ui.progress(f"Starting server on {host}:{port}")
    from antistrike.server.app import run_server
    import antistrike.core.config as cfg
    cfg.get_settings().server.host = host
    cfg.get_settings().server.port = port
    run_server()


@main.command()
@click.argument("target")
@click.option("--authorizer", "-a", required=True, help="Person authorizing the test")
@click.option("--depth", "-d", default="standard", type=click.Choice(["quick", "standard", "deep", "exhaustive"]))
@click.option("--profile", "-p", multiple=True, default=["full_spectrum"])
def authorize(target: str, authorizer: str, depth: str, profile: tuple):
    """Register authorized testing scope."""
    ui.banner()
    scope = EngagementScope(
        target=target,
        authorized_by=authorizer,
        depth=ScanDepth(depth),
        allowed_profiles=[AttackProfile(p) for p in profile],
    )
    result = auth_gate.register_scope(scope)
    if result.get("valid"):
        ui.success(f"Scope registered for {target}")
        ui.status_card("Authorizer", authorizer)
        ui.status_card("Depth", depth)
        ui.status_card("Profiles", ", ".join(profile))
    else:
        ui.error(result.get("error", "Failed"))
        sys.exit(1)


@main.command()
@click.argument("target")
@click.option("--depth", "-d", default="standard", type=click.Choice(["quick", "standard", "deep", "exhaustive"]))
@click.option("--types", "-t", multiple=True, help="Specific attack types")
def scan(target: str, depth: str, types: tuple):
    """Run vulnerability scan on authorized target."""
    ui.banner()
    ui.section("Vulnerability Scan", f"Target: {target} | Depth: {depth}")
    ui.progress("Initializing built-in scanner...")

    result = orchestrator.run_builtin_scan(
        target, depth=depth, attack_types=list(types) if types else None
    )

    if not result.get("success"):
        ui.error(result.get("error", "Scan failed"))
        sys.exit(1)

    findings = result.get("findings", [])
    ui.success(f"Scan complete — {len(findings)} findings")

    for f in findings:
        ui.finding_card(
            f.get("title", "Unknown"),
            f.get("severity", "info"),
            f.get("location", ""),
            f.get("evidence", ""),
        )


@main.command()
@click.argument("target")
@click.option("--profile", "-p", default="web", type=click.Choice([
    "web", "api", "network", "cloud", "mobile", "binary", "full_spectrum"
]))
@click.option("--depth", "-d", default="standard", type=click.Choice(["quick", "standard", "deep", "exhaustive"]))
def assess(target: str, profile: str, depth: str):
    """Run full profile assessment."""
    ui.banner()
    ui.section("Profile Assessment", f"{profile.upper()} | {depth}")
    ui.progress(f"Running {profile} assessment on {target}...")

    result = orchestrator.run_profile_scan(target, profile, depth)

    if not result.get("success"):
        ui.error(result.get("error", "Assessment failed"))
        sys.exit(1)

    ui.success(f"Assessment complete — {result.get('total_findings', 0)} findings across {result.get('modules_run', 0)} modules")
    for f in result.get("findings", []):
        ui.finding_card(f.get("title", ""), f.get("severity", "info"), f.get("location", ""))


@main.command()
@click.option("--category", "-c", default=None)
def modules(category: str | None):
    """List available attack modules."""
    ui.banner()
    tools = list_tools(category=category)
    ui.tool_table(tools)
    available = sum(1 for t in tools if t["available"])
    ui.status_card("Available", f"{available}/{len(tools)}")


@main.command()
@click.argument("target")
@click.option("--format", "-f", multiple=True, default=["json", "executive"])
def report(target: str, format: tuple):
    """Generate report from latest scan findings."""
    ui.banner()
    ui.progress(f"Generating report for {target}...")
    result = reporter.save_report(target, [], list(format))
    for path in result.get("saved_files", []):
        ui.success(f"Saved: {path}")


@main.command()
def tui():
    """Launch interactive TUI dashboard."""
    from antistrike.cli.tui.app import run_tui
    run_tui()


@main.command()
def stats():
    """Show system statistics."""
    from antistrike.core.engine import engine
    from antistrike.payloads.library import get_payload_count
    from antistrike.tools.registry import TOOL_REGISTRY

    ui.banner()
    sys_stats = engine.get_system_stats()
    ui.section("System Status")
    ui.status_card("CPU", f"{sys_stats['cpu_percent']}%")
    ui.status_card("Memory", f"{sys_stats['memory_percent']}%")
    ui.status_card("Active Jobs", str(sys_stats["active_jobs"]))
    ui.status_card("Modules", f"{len(TOOL_REGISTRY)} registered")
    ui.status_card("Payloads", f"{sum(get_payload_count().values())} total")


if __name__ == "__main__":
    main()