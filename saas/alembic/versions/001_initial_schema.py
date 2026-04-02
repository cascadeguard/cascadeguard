"""Initial schema — organizations, images, states, dependencies, jobs, rebuilds, api_keys.

Revision ID: 001
Revises: None
Create Date: 2026-04-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("plan", sa.String(50), server_default="free", nullable=False),
        sa.Column("stripe_customer_id", sa.String(255)),
        sa.Column("github_installation_id", sa.BigInteger),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "images",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("registry", sa.String(500), nullable=False),
        sa.Column("repository", sa.String(500), nullable=False),
        sa.Column("tag_pattern", sa.String(255)),
        sa.Column("source_provider", sa.String(50)),
        sa.Column("source_repo", sa.String(500)),
        sa.Column("source_branch", sa.String(255)),
        sa.Column("source_dockerfile", sa.String(500)),
        sa.Column("auto_rebuild", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("rebuild_delay_days", sa.Integer, server_default=sa.text("7")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_images_org_id_name"),
        sa.CheckConstraint("type IN ('managed', 'base', 'external')", name="ck_images_type"),
    )
    op.create_index("ix_images_org_id", "images", ["org_id"])

    op.create_table(
        "image_states",
        sa.Column("image_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("images.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("current_digest", sa.String(255)),
        sa.Column("current_version", sa.String(255)),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("last_built_at", sa.DateTime(timezone=True)),
        sa.Column("rebuild_eligible_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(50), server_default="pending", nullable=False),
    )

    op.create_table(
        "image_dependencies",
        sa.Column("image_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("base_image_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("image_id", "base_image_id"),
    )

    op.create_table(
        "analysis_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("image_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(50), server_default="queued", nullable=False),
        sa.Column("discovered_base_images", postgresql.JSONB),
        sa.Column("logs", sa.Text),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_analysis_jobs_org_id", "analysis_jobs", ["org_id"])
    op.create_index("ix_analysis_jobs_image_id", "analysis_jobs", ["image_id"])

    op.create_table(
        "rebuilds",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("image_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("trigger_base_image_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("images.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(50), server_default="pending", nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True)),
        sa.Column("workflow_run_id", sa.BigInteger),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_rebuilds_org_id", "rebuilds", ["org_id"])
    op.create_index("ix_rebuilds_image_id", "rebuilds", ["image_id"])

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False),
        sa.Column("key_prefix", sa.String(10), nullable=False),
        sa.Column("role", sa.String(50), server_default="developer", nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("rebuilds")
    op.drop_table("analysis_jobs")
    op.drop_table("image_dependencies")
    op.drop_table("image_states")
    op.drop_table("images")
    op.drop_table("organizations")
