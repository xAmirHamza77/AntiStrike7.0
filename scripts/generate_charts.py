#!/usr/bin/env python3
"""Generate Antistrike 7.0 chart and diagram assets from live project data."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from antistrike.payloads.library import get_payload_count
from antistrike.tools.registry import TOOL_REGISTRY, ATTACK_TYPES

ASSETS = Path(__file__).resolve().parents[1] / "assets"
CHARTS = ASSETS / "charts"
DIAGRAMS = ASSETS / "diagrams"

COLORS = {
    "cyan": "#00D4FF",
    "amber": "#FFB020",
    "violet": "#7B61FF",
    "green": "#00E676",
    "orange": "#FFAB40",
    "red": "#FF5252",
    "bg": "#0A0E17",
    "panel": "#111827",
    "border": "#1F2937",
    "text": "#E5E7EB",
    "muted": "#6B7280",
}

CHART_COLORS = [
    "#00D4FF", "#FFB020", "#7B61FF", "#00E676", "#FFAB40",
    "#FF5252", "#40C4FF", "#FF6B9D", "#A78BFA", "#34D399",
    "#FBBF24", "#F87171", "#60A5FA", "#C084FC", "#4ADE80", "#FB923C",
]


def svg_header(w: int, h: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'font-family="Inter, system-ui, sans-serif">'
        f'<rect width="{w}" height="{h}" fill="{COLORS["bg"]}"/>'
    )


def modules_by_category_chart() -> str:
    cats = Counter(t.category for t in TOOL_REGISTRY)
    sorted_cats = sorted(cats.items(), key=lambda x: -x[1])
    w, h = 900, 520
    margin, bar_h, gap = 180, 28, 8
    max_val = max(cats.values())

    parts = [svg_header(w, h)]
    parts.append(f'<text x="40" y="40" fill="{COLORS["cyan"]}" font-size="22" font-weight="700">Attack Modules by Category</text>')
    parts.append(f'<text x="40" y="65" fill="{COLORS["muted"]}" font-size="13">99 total modules across 16 categories</text>')

    for i, (cat, count) in enumerate(sorted_cats):
        y = 100 + i * (bar_h + gap)
        bar_w = (count / max_val) * 580
        color = CHART_COLORS[i % len(CHART_COLORS)]
        parts.append(f'<text x="40" y="{y + 20}" fill="{COLORS["text"]}" font-size="13" text-anchor="start">{cat}</text>')
        parts.append(f'<rect x="{margin}" y="{y}" width="{bar_w}" height="{bar_h}" rx="4" fill="{color}" opacity="0.85"/>')
        parts.append(f'<text x="{margin + bar_w + 12}" y="{y + 20}" fill="{COLORS["text"]}" font-size="14" font-weight="600">{count}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def payload_breakdown_chart() -> str:
    payloads = get_payload_count()
    sorted_p = sorted(payloads.items(), key=lambda x: -x[1])
    w, h = 900, 480
    margin, bar_h, gap = 200, 24, 6
    max_val = max(payloads.values())

    parts = [svg_header(w, h)]
    parts.append(f'<text x="40" y="40" fill="{COLORS["amber"]}" font-size="22" font-weight="700">Payload Library Breakdown</text>')
    parts.append(f'<text x="40" y="65" fill="{COLORS["muted"]}" font-size="13">{sum(payloads.values())} payloads across {len(payloads)} attack types</text>')

    for i, (ptype, count) in enumerate(sorted_p):
        y = 95 + i * (bar_h + gap)
        bar_w = (count / max_val) * 520
        color = CHART_COLORS[(i + 3) % len(CHART_COLORS)]
        parts.append(f'<text x="40" y="{y + 17}" fill="{COLORS["text"]}" font-size="12">{ptype}</text>')
        parts.append(f'<rect x="{margin}" y="{y}" width="{bar_w}" height="{bar_h}" rx="3" fill="{color}" opacity="0.8"/>')
        parts.append(f'<text x="{margin + bar_w + 10}" y="{y + 17}" fill="{COLORS["text"]}" font-size="13" font-weight="600">{count}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def platform_overview_chart() -> str:
    builtin = sum(1 for t in TOOL_REGISTRY if t.builtin)
    external = len(TOOL_REGISTRY) - builtin
    available = sum(1 for t in TOOL_REGISTRY if t.is_available())
    payload_total = sum(get_payload_count().values())

    stats = [
        ("Attack Modules", len(TOOL_REGISTRY), COLORS["cyan"]),
        ("Vulnerability Classes", len(ATTACK_TYPES), COLORS["violet"]),
        ("Built-in Scanners", builtin, COLORS["green"]),
        ("External Tool Wrappers", external, COLORS["amber"]),
        ("Available Now", available, COLORS["green"]),
        ("Curated Payloads", payload_total, COLORS["orange"]),
        ("Scan Depths", 4, COLORS["cyan"]),
        ("Attack Profiles", 7, COLORS["violet"]),
        ("MCP Tools", 16, COLORS["amber"]),
    ]

    w, h = 900, 500
    cols, card_w, card_h = 3, 260, 110
    parts = [svg_header(w, h)]
    parts.append(f'<text x="40" y="40" fill="{COLORS["cyan"]}" font-size="22" font-weight="700">Platform Overview</text>')
    parts.append(f'<text x="40" y="65" fill="{COLORS["muted"]}" font-size="13">Antistrike 7.0 Obsidian Edition — key metrics</text>')

    for i, (label, value, color) in enumerate(stats):
        col, row = i % cols, i // cols
        x = 40 + col * (card_w + 20)
        y = 90 + row * (card_h + 16)
        parts.append(f'<rect x="{x}" y="{y}" width="{card_w}" height="{card_h}" rx="8" fill="{COLORS["panel"]}" stroke="{COLORS["border"]}"/>')
        parts.append(f'<rect x="{x}" y="{y}" width="{card_w}" height="3" rx="1" fill="{color}"/>')
        parts.append(f'<text x="{x + 16}" y="{y + 35}" fill="{COLORS["muted"]}" font-size="12">{label}</text>')
        parts.append(f'<text x="{x + 16}" y="{y + 72}" fill="{color}" font-size="36" font-weight="700">{value}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def module_type_donut() -> str:
    builtin = sum(1 for t in TOOL_REGISTRY if t.builtin)
    external = len(TOOL_REGISTRY) - builtin
    total = builtin + external
    w, h = 500, 400
    cx, cy, r = 200, 210, 120
    stroke = 50

    builtin_pct = builtin / total
    builtin_dash = builtin_pct * 2 * 3.14159 * r
    circ = 2 * 3.14159 * r

    parts = [svg_header(w, h)]
    parts.append(f'<text x="30" y="35" fill="{COLORS["violet"]}" font-size="20" font-weight="700">Module Types</text>')

    parts.append(
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COLORS["border"]}" stroke-width="{stroke}"/>'
    )
    parts.append(
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COLORS["cyan"]}" stroke-width="{stroke}" '
        f'stroke-dasharray="{builtin_dash} {circ - builtin_dash}" stroke-dashoffset="{circ * 0.25}" '
        f'transform="rotate(-90 {cx} {cy})"/>'
    )
    parts.append(f'<text x="{cx}" y="{cy - 5}" fill="{COLORS["text"]}" font-size="32" font-weight="700" text-anchor="middle">{total}</text>')
    parts.append(f'<text x="{cx}" y="{cy + 18}" fill="{COLORS["muted"]}" font-size="12" text-anchor="middle">modules</text>')

    parts.append(f'<rect x="340" y="140" width="14" height="14" rx="2" fill="{COLORS["cyan"]}"/>')
    parts.append(f'<text x="362" y="152" fill="{COLORS["text"]}" font-size="13">Built-in ({builtin})</text>')
    parts.append(f'<rect x="340" y="170" width="14" height="14" rx="2" fill="{COLORS["border"]}"/>')
    parts.append(f'<text x="362" y="182" fill="{COLORS["text"]}" font-size="13">External ({external})</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def scan_depth_chart() -> str:
    depths = [
        ("Quick", 4, "Surface scan — SQLi, XSS, CORS, redirects"),
        ("Standard", 8, "Balanced — adds SSRF, LFI, SSTI, CMDi"),
        ("Deep", 12, "Thorough — NoSQL, XXE, prototype pollution"),
        ("Exhaustive", 73, "Full spectrum — all attack classes"),
    ]
    w, h = 900, 340
    max_val = 73

    parts = [svg_header(w, h)]
    parts.append(f'<text x="40" y="40" fill="{COLORS["green"]}" font-size="22" font-weight="700">Scan Depth Coverage</text>')
    parts.append(f'<text x="40" y="65" fill="{COLORS["muted"]}" font-size="13">Attack types tested at each depth level</text>')

    for i, (name, count, desc) in enumerate(depths):
        y = 100 + i * 55
        bar_w = (count / max_val) * 500
        color = [COLORS["muted"], COLORS["cyan"], COLORS["amber"], COLORS["violet"]][i]
        parts.append(f'<text x="40" y="{y + 18}" fill="{COLORS["text"]}" font-size="14" font-weight="600">{name}</text>')
        parts.append(f'<rect x="140" y="{y}" width="{bar_w}" height="28" rx="4" fill="{color}" opacity="0.85"/>')
        parts.append(f'<text x="{150 + bar_w}" y="{y + 20}" fill="{color}" font-size="14" font-weight="700">{count}</text>')
        parts.append(f'<text x="140" y="{y + 42}" fill="{COLORS["muted"]}" font-size="11">{desc}</text>')

    parts.append("</svg>")
    return "\n".join(parts)


def architecture_diagram() -> str:
    w, h = 1000, 620
    parts = [svg_header(w, h)]
    parts.append(f'<text x="40" y="35" fill="{COLORS["cyan"]}" font-size="22" font-weight="700">System Architecture</text>')

    def box(x, y, bw, bh, title, sub, color):
        parts.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="8" fill="{COLORS["panel"]}" stroke="{color}" stroke-width="1.5"/>')
        parts.append(f'<text x="{x + bw/2}" y="{y + 28}" fill="{color}" font-size="13" font-weight="600" text-anchor="middle">{title}</text>')
        parts.append(f'<text x="{x + bw/2}" y="{y + 46}" fill="{COLORS["muted"]}" font-size="10" text-anchor="middle">{sub}</text>')

    def arrow(x1, y1, x2, y2):
        parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{COLORS["muted"]}" stroke-width="1.5" marker-end="url(#arrow)"/>')

    parts.append('<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 Z" fill="#6B7280"/></marker></defs>')

    # Top interfaces
    box(60, 70, 180, 60, "Web Dashboard", ":7700/dashboard", COLORS["cyan"])
    box(280, 70, 180, 60, "CLI / TUI", "Terminal control", COLORS["cyan"])
    box(500, 70, 180, 60, "MCP Bridge", "16 AI tools", COLORS["amber"])
    box(720, 70, 180, 60, "REST API", "FastAPI :7700", COLORS["violet"])

    arrow(150, 130, 150, 175)
    arrow(370, 130, 370, 175)
    arrow(590, 130, 590, 175)
    arrow(810, 130, 590, 175)

    # Engine
    box(200, 180, 600, 120, "Antistrike Engine", "", COLORS["cyan"])
    engine_items = ["Authorization Gate", "Attack Orchestrator", "Built-in Scanner", "Agent Coordinator", "Tool Registry", "Payload Library", "Report Generator"]
    for i, item in enumerate(engine_items):
        col = i % 4
        row = i // 4
        ix = 220 + col * 145
        iy = 215 + row * 30
        parts.append(f'<text x="{ix}" y="{iy}" fill="{COLORS["text"]}" font-size="10">• {item}</text>')

    arrow(500, 300, 500, 350)

    # Bottom layer
    box(120, 360, 200, 60, "External CLI Tools", "nmap, nuclei, sqlmap...", COLORS["amber"])
    box(400, 360, 200, 60, "Payload Engine", "88 curated payloads", COLORS["green"])
    box(680, 360, 200, 60, "Report Output", "SARIF, JSON, Executive", COLORS["violet"])

    arrow(320, 390, 400, 390)
    arrow(600, 390, 680, 390)

    # Side outputs
    box(60, 470, 200, 55, "Findings Store", "./runs/", COLORS["green"])
    box(300, 470, 200, 55, "Agent Graph", "Multi-agent teams", COLORS["violet"])
    box(540, 470, 200, 55, "Audit Log", "Scope tracking", COLORS["amber"])
    box(780, 470, 180, 55, "Skills Library", "Attack playbooks", COLORS["cyan"])

    parts.append("</svg>")
    return "\n".join(parts)


def attack_profiles_chart() -> str:
    profiles = [
        ("Web", 6, COLORS["cyan"]),
        ("API", 5, COLORS["violet"]),
        ("Network", 4, COLORS["amber"]),
        ("Cloud", 5, COLORS["green"]),
        ("Mobile", 2, COLORS["orange"]),
        ("Binary", 3, COLORS["red"]),
        ("Full Spectrum", 10, COLORS["cyan"]),
    ]
    w, h = 700, 400
    cx, cy, max_r = 350, 220, 140

    parts = [svg_header(w, h)]
    parts.append(f'<text x="30" y="35" fill="{COLORS["amber"]}" font-size="20" font-weight="700">Attack Profiles</text>')
    parts.append(f'<text x="30" y="58" fill="{COLORS["muted"]}" font-size="12">Modules activated per assessment profile</text>')

    n = len(profiles)
    for i, (name, count, color) in enumerate(profiles):
        angle = (2 * 3.14159 * i / n) - 3.14159 / 2
        r = (count / 10) * max_r
        x = cx + r * 0.85 * __import__("math").cos(angle)
        y = cy + r * 0.85 * __import__("math").sin(angle)
        lx = cx + (max_r + 40) * __import__("math").cos(angle)
        ly = cy + (max_r + 40) * __import__("math").sin(angle)
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="{color}" stroke-width="2" opacity="0.6"/>')
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{color}"/>')
        parts.append(f'<text x="{lx:.1f}" y="{ly:.1f}" fill="{COLORS["text"]}" font-size="11" text-anchor="middle">{name} ({count})</text>')

    parts.append(f'<circle cx="{cx}" cy="{cy}" r="4" fill="{COLORS["text"]}"/>')
    parts.append("</svg>")
    return "\n".join(parts)


def write_stats_json() -> None:
    cats = Counter(t.category for t in TOOL_REGISTRY)
    data = {
        "version": "7.0.0",
        "modules_total": len(TOOL_REGISTRY),
        "modules_builtin": sum(1 for t in TOOL_REGISTRY if t.builtin),
        "modules_available": sum(1 for t in TOOL_REGISTRY if t.is_available()),
        "attack_types": len(ATTACK_TYPES),
        "payloads_total": sum(get_payload_count().values()),
        "categories": dict(cats),
        "payloads": get_payload_count(),
    }
    (ASSETS / "stats.json").write_text(json.dumps(data, indent=2))


def main() -> None:
    CHARTS.mkdir(parents=True, exist_ok=True)
    DIAGRAMS.mkdir(parents=True, exist_ok=True)

    charts = {
        "modules-by-category.svg": modules_by_category_chart(),
        "payload-breakdown.svg": payload_breakdown_chart(),
        "platform-overview.svg": platform_overview_chart(),
        "module-types.svg": module_type_donut(),
        "scan-depth-coverage.svg": scan_depth_chart(),
        "attack-profiles.svg": attack_profiles_chart(),
    }
    for name, content in charts.items():
        (CHARTS / name).write_text(content)
        print(f"  ✓ charts/{name}")

    (DIAGRAMS / "architecture.svg").write_text(architecture_diagram())
    print("  ✓ diagrams/architecture.svg")

    write_stats_json()
    print("  ✓ stats.json")


if __name__ == "__main__":
    print("Generating Antistrike 7.0 assets...")
    main()
    print("Done.")