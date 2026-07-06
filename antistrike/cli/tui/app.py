"""Antistrike 7.0 TUI — interactive terminal dashboard."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from antistrike import __version__
from antistrike.core.authorization import EngagementScope, ScanDepth, auth_gate
from antistrike.modules.attacks.orchestrator import orchestrator
from antistrike.tools.registry import list_tools


class StatusBar(Static):
    """Top status bar with system info."""

    def on_mount(self) -> None:
        self.update(f"  [bold #00D4FF]Antistrike 7.0[/] [dim]Obsidian[/]  │  v{__version__}  │  Ready")


class ModulePanel(Static):
    """Displays available modules."""

    def on_mount(self) -> None:
        tools = list_tools()
        available = sum(1 for t in tools if t["available"])
        lines = [f"[bold #00D4FF]Modules[/]  {available}/{len(tools)} available\n"]
        for t in tools[:20]:
            status = "[#00E676]●[/]" if t["available"] else "[#6B7280]○[/]"
            lines.append(f"  {status} {t['name']} [dim]{t['category']}[/]")
        if len(tools) > 20:
            lines.append(f"  [dim]... and {len(tools) - 20} more[/]")
        self.update("\n".join(lines))


class AntistrikeTUI(App):
    """Interactive terminal UI for Antistrike 7.0."""

    TITLE = "Antistrike 7.0"
    CSS = """
    Screen {
        background: #0A0E17;
    }
    Header {
        background: #111827;
        color: #00D4FF;
    }
    Footer {
        background: #111827;
    }
    #status-bar {
        background: #111827;
        color: #E5E7EB;
        height: 3;
        padding: 0 1;
        border-bottom: solid #1F2937;
    }
    #main-area {
        height: 1fr;
    }
    .panel {
        background: #111827;
        border: solid #1F2937;
        padding: 1;
        margin: 0 1;
    }
    #log-panel {
        height: 1fr;
        background: #0A0E17;
        border: solid #1F2937;
        margin: 1;
    }
    #control-panel {
        height: auto;
        padding: 1;
        background: #111827;
        border: solid #1F2937;
        margin: 0 1;
    }
    Input {
        margin: 0 0 1 0;
    }
    Button {
        margin: 0 1 0 0;
    }
    #scan-btn {
        background: #00D4FF;
        color: #0A0E17;
    }
    #auth-btn {
        background: #7B61FF;
        color: #E5E7EB;
    }
    TabbedContent {
        margin: 1;
    }
    TabPane {
        padding: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "quick_scan", "Scan"),
        Binding("a", "focus_target", "Target"),
        Binding("r", "refresh_modules", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatusBar(id="status-bar")
        with Vertical(id="main-area"):
            with TabbedContent():
                with TabPane("Control", id="tab-control"):
                    with Vertical(id="control-panel"):
                        yield Label("[bold #00D4FF]Target Configuration[/]")
                        yield Input(placeholder="https://target.example.com", id="target-input")
                        yield Select(
                            [("Quick", "quick"), ("Standard", "standard"), ("Deep", "deep"), ("Exhaustive", "exhaustive")],
                            id="depth-select",
                            value="standard",
                        )
                        with Horizontal():
                            yield Button("Authorize", id="auth-btn", variant="primary")
                            yield Button("Scan", id="scan-btn", variant="success")
                            yield Button("Full Assessment", id="assess-btn")
                    yield RichLog(id="log-panel", highlight=True, markup=True)
                with TabPane("Modules", id="tab-modules"):
                    yield ModulePanel(classes="panel")
                with TabPane("Findings", id="tab-findings"):
                    yield ScrollableContainer(Static("No findings yet. Run a scan first.", id="findings-content", classes="panel"))
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#log-panel", RichLog)
        log.write("[bold #00D4FF]Antistrike 7.0 Obsidian Edition[/]")
        log.write("[dim]Register authorization, then run scans.[/]")
        log.write("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        log = self.query_one("#log-panel", RichLog)
        target = self.query_one("#target-input", Input).value.strip()
        depth = self.query_one("#depth-select", Select).value

        if not target:
            log.write("[#FF5252]✗ Target URL required[/]")
            return

        if event.button.id == "auth-btn":
            scope = EngagementScope(target=target, authorized_by="tui-operator", depth=ScanDepth(str(depth)))
            result = auth_gate.register_scope(scope)
            if result.get("valid"):
                log.write(f"[#00E676]✓ Authorized: {target}[/]")
            else:
                log.write(f"[#FF5252]✗ {result.get('error')}[/]")

        elif event.button.id == "scan-btn":
            log.write(f"[#00D4FF]▸ Scanning {target} (depth: {depth})...[/]")
            result = orchestrator.run_builtin_scan(target, depth=str(depth))
            if result.get("success"):
                findings = result.get("findings", [])
                log.write(f"[#00E676]✓ Complete — {len(findings)} findings[/]")
                for f in findings:
                    sev = f.get("severity", "info")
                    color = {"critical": "#FF1744", "high": "#FF5252", "medium": "#FFAB40"}.get(sev, "#40C4FF")
                    log.write(f"  [{color}]{sev.upper()}[/] {f.get('title')} @ {f.get('location')}")
                self._update_findings(findings)
            else:
                log.write(f"[#FF5252]✗ {result.get('error')}[/]")

        elif event.button.id == "assess-btn":
            log.write(f"[#FFB020]▸ Full web assessment on {target}...[/]")
            result = orchestrator.run_profile_scan(target, "web", str(depth))
            if result.get("success"):
                log.write(f"[#00E676]✓ Assessment complete — {result.get('total_findings', 0)} findings[/]")
                self._update_findings(result.get("findings", []))
            else:
                log.write(f"[#FF5252]✗ {result.get('error')}[/]")

    def _update_findings(self, findings: list) -> None:
        content = self.query_one("#findings-content", Static)
        if not findings:
            content.update("No findings.")
            return
        lines = [f"[bold #00D4FF]Findings ({len(findings)})[/]\n"]
        for f in findings:
            sev = f.get("severity", "info")
            lines.append(f"[bold]{f.get('title')}[/] [{sev}]")
            lines.append(f"  Location: {f.get('location')}")
            if f.get("payload"):
                lines.append(f"  Payload: [dim]{f['payload']}[/]")
            lines.append("")
        content.update("\n".join(lines))

    def action_quick_scan(self) -> None:
        self.query_one("#scan-btn", Button).press()

    def action_focus_target(self) -> None:
        self.query_one("#target-input", Input).focus()

    def action_refresh_modules(self) -> None:
        panel = self.query_one(ModulePanel)
        panel.on_mount()


def run_tui() -> None:
    app = AntistrikeTUI()
    app.run()