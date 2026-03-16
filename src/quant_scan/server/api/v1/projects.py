"""Project endpoints — manage scan projects."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field

from quant_scan.server.api.v1 import router

_project_store: dict[str, dict[str, Any]] = {}


class ProjectCreate(BaseModel):
    """Request body for creating a project."""

    name: str
    description: str = ""
    organization: str = ""
    targets: list[str] = Field(default_factory=list)


class Project(BaseModel):
    """Project response model."""

    id: str
    name: str
    description: str = ""
    organization: str = ""
    targets: list[str] = Field(default_factory=list)
    created_at: str = ""
    scan_count: int = 0


@router.post("/projects", response_model=Project)
async def create_project(request: ProjectCreate):
    """Create a new project."""
    project_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    project = {
        "id": project_id,
        "name": request.name,
        "description": request.description,
        "organization": request.organization,
        "targets": request.targets,
        "created_at": now,
        "scan_count": 0,
    }
    _project_store[project_id] = project
    return Project(**project)


@router.get("/projects", response_model=list[Project])
async def list_projects():
    """List all projects."""
    return [Project(**p) for p in _project_store.values()]


@router.get("/projects/{project_id}", response_model=Project)
async def get_project(project_id: str):
    """Get a project by ID."""
    if project_id not in _project_store:
        raise HTTPException(status_code=404, detail="Project not found")
    return Project(**_project_store[project_id])


@router.delete("/projects/{project_id}")
async def delete_project(project_id: str):
    """Delete a project."""
    if project_id not in _project_store:
        raise HTTPException(status_code=404, detail="Project not found")
    del _project_store[project_id]
    return {"detail": "Project deleted"}
