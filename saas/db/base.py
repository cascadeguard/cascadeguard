"""SQLAlchemy base model and tenant isolation mixin."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, MetaData, event
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Session

# Use a consistent naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=convention)


class TimestampMixin:
    """Adds created_at and updated_at columns."""

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class TenantMixin:
    """Mixin that adds org_id for row-level tenant isolation.

    Every tenant-scoped table includes this mixin. Queries should always
    filter by org_id to enforce isolation.
    """

    org_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )


def set_tenant_filter(session: Session, org_id: uuid.UUID):
    """Helper to tag a session with the current tenant for query filtering."""
    session.info["tenant_id"] = org_id
