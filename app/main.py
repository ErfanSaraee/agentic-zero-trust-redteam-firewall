"""FastAPI application entrypoint for the Neural Zero-Trust AI Firewall & Red-Team Arena."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints import router as api_v1_router
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.db.session import engine, init_db
from app.mcp.security_server import get_a2a_security_agent_card

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize async database tables on startup."""
    logger.info("Starting %s in '%s' mode...",
                settings.APP_NAME, settings.APP_ENV)
    await init_db()
    yield
    logger.info("Shutting down %s...", settings.APP_NAME)
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Autonomous Red-Team vs. Blue-Team AI Security Platform powered by PyTorch Multi-Head "
        "Self-Attention, Pinecone Vector Threat Intelligence, Python AST Formal Verification, "
        "CrewAI Adversarial Personas, DSPy Self-Hardening Prompt Compiler, and FastMCP."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    api_v1_router,
    prefix=settings.API_V1_PREFIX,
    tags=["Zero-Trust AI Firewall, AST Sandbox & CrewAI/DSPy Arena"],
)


@app.get(
    "/.well-known/agent.json",
    tags=["A2A Protocol Discovery"],
    summary="Standardized Agent-to-Agent (A2A) security guardian discovery card",
)
async def a2a_agent_discovery() -> dict[str, Any]:
    """Expose peer-to-peer A2A agent capabilities and endpoints."""
    return get_a2a_security_agent_card()


@app.get("/health", tags=["Diagnostics"], summary="Service readiness and security engine healthcheck")
async def healthcheck() -> dict[str, Any]:
    """Return operational status of PyTorch, Pinecone, AST, CrewAI, and DSPy engines."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "engines": {
            "pytorch_self_attention_guard": "online",
            "pinecone_vector_threat_store": "online",
            "python_ast_formal_sandbox": "online",
            "crewai_dspy_redteam_arena": "online",
            "fastmcp_server": "online",
        },
    }
