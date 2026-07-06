"""Authorization gate — ensures all testing is properly scoped."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from antistrike.core.config import RUNS_DIR


class ScanDepth(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


class AttackProfile(str, Enum):
    WEB = "web"
    API = "api"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    BINARY = "binary"
    IOT = "iot"
    WIRELESS = "wireless"
    SOCIAL = "social"
    FULL_SPECTRUM = "full_spectrum"


@dataclass
class EngagementScope:
    """Defines authorized testing boundaries."""

    target: str
    authorized_by: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    allowed_profiles: list[AttackProfile] = field(default_factory=list)
    depth: ScanDepth = ScanDepth.STANDARD
    rules_of_engagement: list[str] = field(default_factory=list)
    no_dos: bool = True
    no_destructive: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "authorized_by": self.authorized_by,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "allowed_profiles": [p.value for p in self.allowed_profiles],
            "depth": self.depth.value,
            "rules_of_engagement": self.rules_of_engagement,
            "no_dos": self.no_dos,
            "no_destructive": self.no_destructive,
            "created_at": self.created_at,
            "confirmed": self.confirmed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementScope:
        return cls(
            target=data["target"],
            authorized_by=data["authorized_by"],
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            allowed_profiles=[AttackProfile(p) for p in data.get("allowed_profiles", [])],
            depth=ScanDepth(data.get("depth", "standard")),
            rules_of_engagement=data.get("rules_of_engagement", []),
            no_dos=data.get("no_dos", True),
            no_destructive=data.get("no_destructive", True),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            confirmed=data.get("confirmed", False),
        )


class AuthorizationGate:
    """Validates and tracks authorized engagements."""

    def __init__(self) -> None:
        self._active_scopes: dict[str, EngagementScope] = {}
        self._audit_log: list[dict[str, Any]] = []

    def register_scope(self, scope: EngagementScope) -> dict[str, Any]:
        if not scope.target or not scope.authorized_by:
            return {"valid": False, "error": "Target and authorizer required"}
        if not scope.in_scope:
            scope.in_scope = [scope.target]
        if not scope.allowed_profiles:
            scope.allowed_profiles = [AttackProfile.FULL_SPECTRUM]
        scope.confirmed = True
        self._active_scopes[scope.target] = scope
        self._log("scope_registered", scope.target, scope.to_dict())
        self._persist_scope(scope)
        return {"valid": True, "scope": scope.to_dict()}

    def validate_target(self, target: str) -> dict[str, Any]:
        for key, scope in self._active_scopes.items():
            if target.startswith(key) or key in target:
                if scope.confirmed:
                    return {"authorized": True, "scope": scope.to_dict()}
        return {
            "authorized": False,
            "error": "No confirmed authorization for this target. Register scope first.",
        }

    def is_attack_allowed(self, target: str, profile: AttackProfile) -> bool:
        validation = self.validate_target(target)
        if not validation.get("authorized"):
            return False
        scope_data = validation["scope"]
        allowed = scope_data.get("allowed_profiles", [])
        return AttackProfile.FULL_SPECTRUM.value in allowed or profile.value in allowed

    def _log(self, action: str, target: str, details: dict[str, Any] | None = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "details": details or {},
        }
        self._audit_log.append(entry)

    def _persist_scope(self, scope: EngagementScope) -> None:
        scope_dir = RUNS_DIR / scope.target.replace("/", "_").replace(":", "_")
        scope_dir.mkdir(parents=True, exist_ok=True)
        with open(scope_dir / "scope.json", "w") as f:
            json.dump(scope.to_dict(), f, indent=2)

    def get_audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)


auth_gate = AuthorizationGate()