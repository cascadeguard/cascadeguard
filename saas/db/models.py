"""SQLAlchemy ORM models for the CascadeGuard SaaS platform.

Schema follows the design in CAS-3 plan Section 6, with row-level
tenant isolation via org_id on every tenant-scoped table.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from .base import Base, TenantMixin, TimestampMixin

TZ_DATETIME = DateTime(timezone=True)
_utcnow = lambda: datetime.now(timezone.utc)


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    plan = Column(String(50), default="free", nullable=False)
    stripe_customer_id = Column(String(255))
    github_installation_id = Column(BigInteger)

    # Relationships
    images = relationship("Image", back_populates="organization", cascade="all, delete-orphan")
    analysis_jobs = relationship("AnalysisJob", back_populates="organization", cascade="all, delete-orphan")
    rebuilds = relationship("Rebuild", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="organization", cascade="all, delete-orphan")


class Image(TenantMixin, TimestampMixin, Base):
    __tablename__ = "images"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_images_org_id_name"),
        CheckConstraint(
            "type IN ('managed', 'base', 'external')",
            name="ck_images_type",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    type = Column(String(20), nullable=False)
    registry = Column(String(500), nullable=False)
    repository = Column(String(500), nullable=False)
    tag_pattern = Column(String(255))
    source_provider = Column(String(50))
    source_repo = Column(String(500))
    source_branch = Column(String(255))
    source_dockerfile = Column(String(500))
    auto_rebuild = Column(Boolean, default=True, nullable=False)
    rebuild_delay_days = Column(Integer, default=7)

    # Relationships
    organization = relationship("Organization", back_populates="images")
    state = relationship("ImageState", back_populates="image", uselist=False, cascade="all, delete-orphan")
    analysis_jobs = relationship("AnalysisJob", back_populates="image", cascade="all, delete-orphan")
    rebuilds = relationship("Rebuild", back_populates="image", cascade="all, delete-orphan")

    # Dependencies where this image depends on a base
    base_dependencies = relationship(
        "ImageDependency",
        foreign_keys="ImageDependency.image_id",
        back_populates="image",
        cascade="all, delete-orphan",
    )
    # Dependencies where this image is a base for others
    dependent_images = relationship(
        "ImageDependency",
        foreign_keys="ImageDependency.base_image_id",
        back_populates="base_image",
        cascade="all, delete-orphan",
    )


class ImageState(Base):
    __tablename__ = "image_states"

    image_id = Column(
        UUID(as_uuid=True),
        ForeignKey("images.id", ondelete="CASCADE"),
        primary_key=True,
    )
    current_digest = Column(String(255))
    current_version = Column(String(255))
    last_checked_at = Column(TZ_DATETIME)
    last_built_at = Column(TZ_DATETIME)
    rebuild_eligible_at = Column(TZ_DATETIME)
    status = Column(String(50), default="pending", nullable=False)

    # Relationships
    image = relationship("Image", back_populates="state")


class ImageDependency(Base):
    __tablename__ = "image_dependencies"

    image_id = Column(
        UUID(as_uuid=True),
        ForeignKey("images.id", ondelete="CASCADE"),
        primary_key=True,
    )
    base_image_id = Column(
        UUID(as_uuid=True),
        ForeignKey("images.id", ondelete="CASCADE"),
        primary_key=True,
    )
    discovered_at = Column(TZ_DATETIME, default=_utcnow, nullable=False)

    # Relationships
    image = relationship("Image", foreign_keys=[image_id], back_populates="base_dependencies")
    base_image = relationship("Image", foreign_keys=[base_image_id], back_populates="dependent_images")


class AnalysisJob(TenantMixin, Base):
    __tablename__ = "analysis_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    image_id = Column(
        UUID(as_uuid=True),
        ForeignKey("images.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = Column(String(50), default="queued", nullable=False)
    discovered_base_images = Column(JSONB)
    logs = Column(Text)
    started_at = Column(TZ_DATETIME)
    completed_at = Column(TZ_DATETIME)
    created_at = Column(TZ_DATETIME, default=_utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="analysis_jobs")
    image = relationship("Image", back_populates="analysis_jobs")


class Rebuild(TenantMixin, Base):
    __tablename__ = "rebuilds"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    image_id = Column(
        UUID(as_uuid=True),
        ForeignKey("images.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    trigger_base_image_id = Column(
        UUID(as_uuid=True),
        ForeignKey("images.id", ondelete="SET NULL"),
    )
    status = Column(String(50), default="pending", nullable=False)
    approved_by = Column(UUID(as_uuid=True))
    workflow_run_id = Column(BigInteger)
    created_at = Column(TZ_DATETIME, default=_utcnow, nullable=False)
    completed_at = Column(TZ_DATETIME)

    # Relationships
    organization = relationship("Organization", back_populates="rebuilds")
    image = relationship("Image", back_populates="rebuilds")
    trigger_base_image = relationship("Image", foreign_keys=[trigger_base_image_id])


class ApiKey(TenantMixin, TimestampMixin, Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False)
    key_prefix = Column(String(10), nullable=False)
    role = Column(String(50), default="developer", nullable=False)
    last_used_at = Column(TZ_DATETIME)
    expires_at = Column(TZ_DATETIME)
    revoked_at = Column(TZ_DATETIME)

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
