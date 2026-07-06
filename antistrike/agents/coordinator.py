"""Multi-agent coordinator — specialist agents for parallel testing."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    WEB_ATTACKER = "web_attacker"
    API_SPECIALIST = "api_specialist"
    NETWORK_SCANNER = "network_scanner"
    CLOUD_AUDITOR = "cloud_auditor"
    EXPLOIT_DEVELOPER = "exploit_developer"
    REPORT_WRITER = "report_writer"


@dataclass
class AgentNode:
    agent_id: str
    role: AgentRole
    target: str
    status: str = "idle"
    parent_id: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, str]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "target": self.target,
            "status": self.status,
            "parent_id": self.parent_id,
            "findings_count": len(self.findings),
            "messages_count": len(self.messages),
            "created_at": self.created_at,
        }


ROLE_MODULES: dict[AgentRole, list[str]] = {
    AgentRole.RECON: ["subdomain_enum", "tech_detect", "whois_lookup", "osint_harvest"],
    AgentRole.WEB_ATTACKER: ["sqli_scan", "xss_scan", "lfi_scan", "ssrf_scan", "ssti_scan", "dir_brute"],
    AgentRole.API_SPECIALIST: ["api_fuzz", "graphql_scan", "jwt_analyze", "oauth_scan", "param_discover"],
    AgentRole.NETWORK_SCANNER: ["port_scan", "service_enum", "smb_enum", "snmp_enum"],
    AgentRole.CLOUD_AUDITOR: ["aws_audit", "container_scan", "k8s_hunt", "iac_scan", "s3_enum"],
    AgentRole.EXPLOIT_DEVELOPER: ["cmdi_scan", "deserial_scan", "race_scan", "biz_logic"],
    AgentRole.REPORT_WRITER: ["report_gen", "sarif_export"],
}


class AgentCoordinator:
    """Manages multi-agent testing graph."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentNode] = {}
        self._message_bus: list[dict[str, Any]] = []

    def spawn_agent(
        self,
        role: AgentRole,
        target: str,
        parent_id: str | None = None,
    ) -> AgentNode:
        agent = AgentNode(
            agent_id=str(uuid.uuid4())[:8],
            role=role,
            target=target,
            parent_id=parent_id,
        )
        self._agents[agent.agent_id] = agent
        return agent

    def spawn_team(self, target: str, roles: list[AgentRole] | None = None) -> dict[str, Any]:
        orchestrator = self.spawn_agent(AgentRole.ORCHESTRATOR, target)
        orchestrator.status = "active"

        selected_roles = roles or [
            AgentRole.RECON,
            AgentRole.WEB_ATTACKER,
            AgentRole.API_SPECIALIST,
            AgentRole.NETWORK_SCANNER,
        ]

        children = []
        for role in selected_roles:
            child = self.spawn_agent(role, target, parent_id=orchestrator.agent_id)
            child.status = "ready"
            children.append(child)

        return {
            "orchestrator": orchestrator.to_dict(),
            "agents": [c.to_dict() for c in children],
            "total_agents": len(children) + 1,
            "modules_per_agent": {r.value: ROLE_MODULES.get(r, []) for r in selected_roles},
        }

    def send_message(self, from_id: str, to_id: str, content: str) -> dict[str, Any]:
        if to_id not in self._agents:
            return {"success": False, "error": "Agent not found"}
        msg = {
            "from": from_id,
            "to": to_id,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._agents[to_id].messages.append(msg)
        self._message_bus.append(msg)
        return {"success": True, "message": msg}

    def get_graph(self) -> dict[str, Any]:
        nodes = [a.to_dict() for a in self._agents.values()]
        edges = [
            {"from": a.parent_id, "to": a.agent_id}
            for a in self._agents.values()
            if a.parent_id
        ]
        return {"nodes": nodes, "edges": edges, "total_messages": len(self._message_bus)}

    def get_agent(self, agent_id: str) -> AgentNode | None:
        return self._agents.get(agent_id)

    def list_agents(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._agents.values()]


coordinator = AgentCoordinator()