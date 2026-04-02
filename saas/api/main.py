"""CascadeGuard SaaS API — FastAPI application entry point."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .middleware.error_handler import error_handler_middleware
from .middleware.tenant_context import TenantContextMiddleware
from .routers import health


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle hook."""
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="CascadeGuard",
        description="Container image lifecycle management platform",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )

    # --- CORS ---
    allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Custom middleware (applied bottom-up, so error handler wraps everything) ---
    app.add_middleware(TenantContextMiddleware)
    app.middleware("http")(error_handler_middleware)

    # --- Routers ---
    app.include_router(health.router)

    return app


app = create_app()
