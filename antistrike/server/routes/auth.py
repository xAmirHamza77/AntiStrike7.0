"""Authorization scope management."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from antistrike.core.authorization import AttackProfile, EngagementScope, ScanDepth, auth_gate

router = APIRouter()


class ScopeRequest(BaseModel):
    target: str
    authorized_by: str
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    allowed_profiles: list[str] = []
    depth: str = "standard"
    rules_of_engagement: list[str] = []
    no_dos: bool = True
    no_destructive: bool = True


@router.post("/scope")
async def register_scope(req: ScopeRequest):
    scope = EngagementScope(
        target=req.target,
        authorized_by=req.authorized_by,
        in_scope=req.in_scope,
        out_of_scope=req.out_of_scope,
        allowed_profiles=[AttackProfile(p) for p in req.allowed_profiles] if req.allowed_profiles else [],
        depth=ScanDepth(req.depth),
        rules_of_engagement=req.rules_of_engagement,
        no_dos=req.no_dos,
        no_destructive=req.no_destructive,
    )
    return auth_gate.register_scope(scope)


@router.get("/validate/{target:path}")
async def validate_target(target: str):
    return auth_gate.validate_target(target)


@router.get("/audit")
async def audit_log():
    return {"entries": auth_gate.get_audit_log()}