"""Tenant context middleware — extracts org_id from the authenticated request.

For now, reads X-Org-Id header. Will be replaced by auth-token-derived
tenant context once Clerk integration is in place.
"""

import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# Paths that don't require tenant context
TENANT_EXEMPT_PREFIXES = ("/health", "/docs", "/redoc", "/api/v1/openapi.json")


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if any(request.url.path.startswith(p) for p in TENANT_EXEMPT_PREFIXES):
            return await call_next(request)

        org_id_header = request.headers.get("X-Org-Id")
        if org_id_header:
            try:
                request.state.org_id = uuid.UUID(org_id_header)
            except ValueError:
                request.state.org_id = None
        else:
            request.state.org_id = None

        return await call_next(request)
