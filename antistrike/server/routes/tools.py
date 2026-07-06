"""Tool registry and module management."""

from __future__ import annotations

from fastapi import APIRouter

from antistrike.payloads.library import get_payloads, list_attack_types
from antistrike.tools.registry import ATTACK_TYPES, list_categories, list_tools

router = APIRouter()


@router.get("/")
async def all_tools(category: str | None = None, attack_type: str | None = None):
    return {"tools": list_tools(category, attack_type)}


@router.get("/categories")
async def categories():
    return {"categories": list_categories()}


@router.get("/attack-types")
async def attack_types():
    return {"attack_types": ATTACK_TYPES}


@router.get("/payloads/{attack_type}")
async def payloads(attack_type: str):
    return {"attack_type": attack_type, "payloads": get_payloads(attack_type)}


@router.get("/payload-types")
async def payload_types():
    return {"types": list_attack_types()}