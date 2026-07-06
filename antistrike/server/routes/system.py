"""System health and status endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from antistrike import __version__
from antistrike.core.engine import engine
from antistrike.payloads.library import get_payload_count, list_attack_types
from antistrike.tools.registry import ATTACK_TYPES, TOOL_REGISTRY, list_categories

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "operational",
        "version": __version__,
        "codename": "Obsidian",
    }


@router.get("/stats")
async def stats():
    available = sum(1 for t in TOOL_REGISTRY if t.is_available())
    return {
        "system": engine.get_system_stats(),
        "modules": {
            "total": len(TOOL_REGISTRY),
            "available": available,
            "builtin": sum(1 for t in TOOL_REGISTRY if t.builtin),
            "categories": len(list_categories()),
            "attack_types": len(ATTACK_TYPES),
        },
        "payloads": {
            "attack_types": len(list_attack_types()),
            "total_payloads": sum(get_payload_count().values()),
            "breakdown": get_payload_count(),
        },
    }


@router.get("/jobs")
async def list_jobs():
    return {"jobs": engine.list_jobs()}


@router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = engine.get_job(job_id)
    if not job:
        return {"error": "Job not found"}
    return {
        "job_id": job.job_id,
        "target": job.target,
        "module": job.module,
        "status": job.status,
        "findings": job.findings,
        "result": job.result,
    }


@router.post("/command")
async def execute_command(body: dict):
    command = body.get("command", "")
    if not command:
        return {"success": False, "error": "Command required"}
    timeout = body.get("timeout")
    use_cache = body.get("use_cache", True)
    result = engine.execute(command, timeout=timeout, use_cache=use_cache)
    return result.to_dict()