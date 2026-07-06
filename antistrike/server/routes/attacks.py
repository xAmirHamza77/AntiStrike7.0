"""Attack execution endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from antistrike.modules.attacks.orchestrator import orchestrator
from antistrike.modules.report.generator import reporter

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    depth: str = "standard"
    attack_types: list[str] = []


class ToolScanRequest(BaseModel):
    target: str
    tool: str
    extra_args: str = ""


class ProfileScanRequest(BaseModel):
    target: str
    profile: str = "web"
    depth: str = "standard"


class ReportRequest(BaseModel):
    target: str
    findings: list[dict] = []
    formats: list[str] = ["json", "sarif", "executive"]


class ChainRequest(BaseModel):
    target: str
    findings: list[dict] = []


@router.post("/scan")
async def builtin_scan(req: ScanRequest):
    return orchestrator.run_builtin_scan(
        req.target,
        depth=req.depth,
        attack_types=req.attack_types or None,
    )


@router.post("/tool")
async def tool_scan(req: ToolScanRequest):
    return orchestrator.run_tool_scan(req.target, req.tool, req.extra_args)


@router.post("/profile")
async def profile_scan(req: ProfileScanRequest):
    return orchestrator.run_profile_scan(req.target, req.profile, req.depth)


@router.post("/chain")
async def attack_chain(req: ChainRequest):
    return orchestrator.create_attack_chain(req.target, req.findings)


@router.post("/report")
async def generate_report(req: ReportRequest):
    return reporter.save_report(req.target, req.findings, req.formats)