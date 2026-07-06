"""Core execution engine — command orchestration, caching, and recovery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from antistrike.core.config import RUNS_DIR, get_settings


@dataclass
class CommandResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    duration_ms: float
    command: str
    cached: bool = False
    recovery_attempts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration_ms": self.duration_ms,
            "command": self.command,
            "cached": self.cached,
            "recovery_attempts": self.recovery_attempts,
        }


@dataclass
class JobState:
    job_id: str
    target: str
    module: str
    status: str = "pending"
    started_at: str = ""
    completed_at: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)


class ResultCache:
    """LRU cache for command results."""

    def __init__(self, max_size: int = 500, ttl: int = 3600) -> None:
        self._cache: dict[str, tuple[float, CommandResult]] = {}
        self._max_size = max_size
        self._ttl = ttl

    def _key(self, command: str) -> str:
        return hashlib.sha256(command.encode()).hexdigest()[:16]

    def get(self, command: str) -> CommandResult | None:
        key = self._key(command)
        if key in self._cache:
            ts, result = self._cache[key]
            if time.time() - ts < self._ttl:
                result.cached = True
                return result
            del self._cache[key]
        return None

    def put(self, command: str, result: CommandResult) -> None:
        if len(self._cache) >= self._max_size:
            oldest = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest]
        self._cache[self._key(command)] = (time.time(), result)


class ExecutionEngine:
    """Orchestrates tool execution with caching, recovery, and job tracking."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.cache = ResultCache(ttl=self.settings.scan.cache_ttl)
        self._executor = ThreadPoolExecutor(max_workers=self.settings.scan.max_concurrent_jobs)
        self._jobs: dict[str, JobState] = {}
        self._processes: dict[int, dict[str, Any]] = {}

    def tool_available(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def execute(
        self,
        command: str,
        timeout: int | None = None,
        use_cache: bool = True,
        cwd: str | None = None,
    ) -> CommandResult:
        if use_cache:
            cached = self.cache.get(command)
            if cached:
                return cached

        timeout = timeout or self.settings.scan.command_timeout
        start = time.time()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            result = CommandResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                return_code=proc.returncode,
                duration_ms=(time.time() - start) * 1000,
                command=command,
            )
        except subprocess.TimeoutExpired:
            result = CommandResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                duration_ms=(time.time() - start) * 1000,
                command=command,
            )
        except Exception as e:
            result = CommandResult(
                success=False,
                stdout="",
                stderr=str(e),
                return_code=-1,
                duration_ms=(time.time() - start) * 1000,
                command=command,
            )

        if use_cache and result.success:
            self.cache.put(command, result)
        return result

    def execute_with_recovery(
        self,
        command: str,
        alternatives: list[str] | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        result = self.execute(command, timeout=timeout)
        if result.success:
            return result

        for alt in alternatives or []:
            result.recovery_attempts += 1
            alt_result = self.execute(alt, timeout=timeout, use_cache=False)
            if alt_result.success:
                alt_result.recovery_attempts = result.recovery_attempts
                return alt_result

        return result

    def create_job(self, target: str, module: str) -> JobState:
        job_id = hashlib.sha256(
            f"{target}:{module}:{time.time()}".encode()
        ).hexdigest()[:12]
        job = JobState(
            job_id=job_id,
            target=target,
            module=module,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._jobs[job_id] = job
        return job

    def update_job(self, job_id: str, **kwargs: Any) -> JobState | None:
        if job_id not in self._jobs:
            return None
        job = self._jobs[job_id]
        for key, value in kwargs.items():
            if hasattr(job, key):
                setattr(job, key, value)
        return job

    def get_job(self, job_id: str) -> JobState | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return [
            {
                "job_id": j.job_id,
                "target": j.target,
                "module": j.module,
                "status": j.status,
                "started_at": j.started_at,
                "findings_count": len(j.findings),
            }
            for j in self._jobs.values()
        ]

    def get_system_stats(self) -> dict[str, Any]:
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "active_jobs": sum(1 for j in self._jobs.values() if j.status == "running"),
            "total_jobs": len(self._jobs),
            "cache_size": len(self.cache._cache),
        }

    def build_command(self, tool: str, args: list[str] | None = None, flags: dict[str, str] | None = None) -> str:
        parts = [shlex.quote(tool)]
        if flags:
            for key, value in flags.items():
                if value:
                    parts.append(f"{key} {shlex.quote(str(value))}")
                else:
                    parts.append(key)
        if args:
            parts.extend(shlex.quote(a) for a in args)
        return " ".join(parts)


engine = ExecutionEngine()