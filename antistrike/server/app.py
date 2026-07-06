"""Antistrike 7.0 API server — FastAPI backend."""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from antistrike import __version__
from antistrike.core.config import PROJECT_ROOT, ensure_dirs, get_settings
from antistrike.server.routes import attacks, agents, auth, system, tools

ensure_dirs()
settings = get_settings()

app = FastAPI(
    title="Antistrike 7.0",
    description="Advanced AI-powered penetration testing platform",
    version=__version__,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.cors_origins + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router, prefix="/api", tags=["System"])
app.include_router(auth.router, prefix="/api/auth", tags=["Authorization"])
app.include_router(tools.router, prefix="/api/tools", tags=["Tools"])
app.include_router(attacks.router, prefix="/api/attacks", tags=["Attacks"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])

dashboard_path = PROJECT_ROOT / "antistrike" / "web" / "dashboard"
assets_path = PROJECT_ROOT / "assets"
if dashboard_path.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")
if assets_path.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_path)), name="assets")


@app.get("/")
async def root():
    return {
        "name": "Antistrike",
        "version": __version__,
        "codename": "Obsidian",
        "dashboard": "/dashboard",
        "docs": "/api/docs",
    }


def run_server() -> None:
    uvicorn.run(
        "antistrike.server.app:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=False,
    )


if __name__ == "__main__":
    run_server()