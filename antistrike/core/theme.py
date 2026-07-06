"""Obsidian visual theme — unique Antistrike 7.0 design language."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Obsidian palette — electric cyan + amber accents (distinct from other tools)
COLORS = {
    "primary": "#00D4FF",      # Electric cyan
    "secondary": "#FFB020",    # Amber gold
    "accent": "#7B61FF",       # Violet
    "success": "#00E676",      # Mint green
    "warning": "#FFAB40",      # Orange
    "danger": "#FF5252",       # Coral red
    "info": "#40C4FF",         # Sky blue
    "muted": "#6B7280",        # Gray
    "bg_dark": "#0A0E17",      # Deep obsidian
    "bg_panel": "#111827",     # Panel background
    "text": "#E5E7EB",         # Light gray text
    "border": "#1F2937",       # Border
}

SEVERITY_COLORS = {
    "critical": "#FF1744",
    "high": "#FF5252",
    "medium": "#FFAB40",
    "low": "#40C4FF",
    "info": "#6B7280",
}

BANNER = r"""
    ___          __  _ _____ __ _  ___ ___ _____ _    ___ _____ 
   / _ \ /\ /\  / _\| |_   _/ _| |/ / __|_   _| |  / __|_   _|
  / /_\// / \ \/ /  | | | | |_| ' <| _|  | | | |__\__ \ | |  
 / /_\\ \_/\_/ /   | | | |  _| . <|___| | | |____|___/ | |  
 \____/ \__,_/_/    |_| |_| |_| \_|     |_|      |___/  |_|  
                                                             
              [bold #00D4FF]v7.0[/] [dim]Obsidian Edition[/]
         [dim]Advanced Offensive Security Platform[/]
"""


class ObsidianUI:
    """Terminal UI renderer with Antistrike design language."""

    def __init__(self) -> None:
        self.console = Console()

    def banner(self) -> None:
        self.console.print(BANNER, style="bold")

    def section(self, title: str, subtitle: str = "") -> None:
        text = Text(title, style=f"bold {COLORS['primary']}")
        if subtitle:
            text.append(f"\n{subtitle}", style="dim")
        self.console.print(
            Panel(text, border_style=COLORS["border"], padding=(0, 2))
        )

    def status_card(self, label: str, value: str, status: str = "info") -> None:
        color = COLORS.get(status, COLORS["info"])
        self.console.print(
            f"  [{color}]●[/] [bold]{label}:[/] {value}"
        )

    def severity_badge(self, severity: str) -> str:
        color = SEVERITY_COLORS.get(severity.lower(), COLORS["muted"])
        return f"[{color}]{severity.upper()}[/]"

    def finding_card(
        self,
        title: str,
        severity: str,
        location: str,
        description: str = "",
    ) -> None:
        content = Text()
        content.append(f"{title}\n", style="bold")
        content.append(f"Severity: ", style="dim")
        content.append(f"{severity.upper()}\n", style=SEVERITY_COLORS.get(severity.lower(), ""))
        content.append(f"Location: {location}\n", style=COLORS["primary"])
        if description:
            content.append(f"\n{description}", style="dim")
        self.console.print(
            Panel(content, border_style=SEVERITY_COLORS.get(severity.lower(), COLORS["border"]),
                  title="[bold]Finding[/]", title_align="left")
        )

    def tool_table(self, tools: list[dict[str, str]]) -> None:
        table = Table(
            title="Available Modules",
            border_style=COLORS["border"],
            header_style=f"bold {COLORS['primary']}",
        )
        table.add_column("Module", style=COLORS["primary"])
        table.add_column("Category", style=COLORS["secondary"])
        table.add_column("Status")
        for tool in tools:
            status = tool.get("status", "ready")
            status_style = COLORS["success"] if status == "ready" else COLORS["warning"]
            table.add_row(
                tool.get("name", ""),
                tool.get("category", ""),
                f"[{status_style}]{status}[/]",
            )
        self.console.print(table)

    def progress(self, message: str) -> None:
        self.console.print(f"  [{COLORS['accent']}]▸[/] {message}")

    def success(self, message: str) -> None:
        self.console.print(f"  [{COLORS['success']}]✓[/] {message}")

    def error(self, message: str) -> None:
        self.console.print(f"  [{COLORS['danger']}]✗[/] {message}")

    def warning(self, message: str) -> None:
        self.console.print(f"  [{COLORS['warning']}]![/] {message}")


ui = ObsidianUI()