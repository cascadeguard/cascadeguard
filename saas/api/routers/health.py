"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness check")
async def health():
    return {"status": "ok"}


@router.get("/health/ready", summary="Readiness check")
async def readiness():
    """Checks that the service and its dependencies are ready.

    Will verify database connectivity once the DB layer is wired in.
    """
    return {"status": "ready"}
