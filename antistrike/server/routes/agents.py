"""Multi-agent coordination endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from antistrike.agents.coordinator import AgentRole, coordinator

router = APIRouter()


class SpawnTeamRequest(BaseModel):
    target: str
    roles: list[str] = []


class MessageRequest(BaseModel):
    from_id: str
    to_id: str
    content: str


@router.post("/spawn")
async def spawn_team(req: SpawnTeamRequest):
    roles = [AgentRole(r) for r in req.roles] if req.roles else None
    return coordinator.spawn_team(req.target, roles)


@router.get("/graph")
async def agent_graph():
    return coordinator.get_graph()


@router.get("/")
async def list_agents():
    return {"agents": coordinator.list_agents()}


@router.post("/message")
async def send_message(req: MessageRequest):
    return coordinator.send_message(req.from_id, req.to_id, req.content)