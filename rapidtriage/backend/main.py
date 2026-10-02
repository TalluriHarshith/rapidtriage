"""
RapidTriage Backend Application Entrypoint
FastAPI application aggregating all forensic REST API routers.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from rapidtriage.backend.config import APP_NAME, VERSION
from rapidtriage.backend.database.db import init_db
from rapidtriage.backend.api.cases import router as cases_router
from rapidtriage.backend.api.evidence import router as evidence_router
from rapidtriage.backend.api.timeline import router as timeline_router
from rapidtriage.backend.api.findings import router as findings_router
from rapidtriage.backend.api.integrity import router as integrity_router
from rapidtriage.backend.api.reports import router as reports_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and seed initial demo case if not present
    init_db()
    yield

app = FastAPI(
    title=f"{APP_NAME} Forensic API",
    version=VERSION,
    description="Backend API for RapidTriage portable endpoint forensic triage and incident timeline tool.",
    lifespan=lifespan
)

# CORS middleware for local frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers under /api
app.include_router(cases_router, prefix="/api")
app.include_router(evidence_router, prefix="/api")
app.include_router(timeline_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(integrity_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

@app.get("/api/health")
def health_check():
    """Service health and readiness check."""
    return {
        "status": "online",
        "app": APP_NAME,
        "version": VERSION,
        "database": "SQLite Connected",
        "triageEngine": "Operational"
    }
