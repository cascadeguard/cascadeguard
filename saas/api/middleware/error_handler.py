"""Global error handling middleware — returns consistent JSON error responses."""

import logging
import traceback

from fastapi import Request, status
from fastapi.responses import JSONResponse

logger = logging.getLogger("cascadeguard.api")


class APIError(Exception):
    """Application-level error with HTTP status and machine-readable code."""

    def __init__(self, status_code: int, code: str, detail: str):
        self.status_code = status_code
        self.code = code
        self.detail = detail


async def error_handler_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except APIError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "detail": exc.detail,
                }
            },
        )
    except Exception:
        logger.error("Unhandled exception:\n%s", traceback.format_exc())
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "internal_error",
                    "detail": "An unexpected error occurred.",
                }
            },
        )
