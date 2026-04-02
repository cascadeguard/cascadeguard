"""Database storage backend for ImageFactoryTool (SaaS mode).

This module is part of the proprietary SaaS layer and should NOT be
distributed with the open-source CascadeGuard release.  It imports
the StorageBackend ABC from the OSS ``app/storage`` module and
implements it against PostgreSQL via SQLAlchemy.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import logging

# Ensure the app/ directory is importable so we can use the shared ABC.
_app_dir = str(Path(__file__).resolve().parent.parent / "app")
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from storage import StorageBackend  # noqa: E402

from .db.models import (  # noqa: E402
    AnalysisJob,
    Image,
    ImageDependency,
    ImageState,
)

logger = logging.getLogger(__name__)


class DatabaseBackend(StorageBackend):
    """Read/write state via SQLAlchemy session (SaaS multi-tenant mode).

    Requires a bound SQLAlchemy ``Session`` and an ``org_id`` (UUID) that
    scopes all queries to a single tenant.
    """

    def __init__(self, session, org_id: uuid.UUID):
        self._session = session
        self._org_id = org_id

    # -- helpers ------------------------------------------------------------

    def _get_image(self, name: str):
        return (
            self._session.query(Image)
            .filter_by(org_id=self._org_id, name=name)
            .first()
        )

    def _get_or_create_image(self, name: str, defaults: Dict):
        img = self._get_image(name)
        if img is None:
            img = Image(
                org_id=self._org_id,
                name=name,
                type=defaults.get("type", "managed"),
                registry=defaults.get("registry", "docker.io"),
                repository=defaults.get("repository", name),
                tag_pattern=defaults.get("tag_pattern"),
                source_provider=defaults.get("source_provider"),
                source_repo=defaults.get("source_repo"),
                source_branch=defaults.get("source_branch"),
                source_dockerfile=defaults.get("source_dockerfile"),
                auto_rebuild=defaults.get("auto_rebuild", True),
                rebuild_delay_days=defaults.get("rebuild_delay_days", 7),
            )
            self._session.add(img)
            self._session.flush()
        return img

    # -- StorageBackend implementation --------------------------------------

    def load_images(self) -> List[Dict]:
        """Load enrolled images from the database.

        Returns dicts shaped like images.yaml entries so that
        ImageFactoryTool.process() can consume them unchanged.
        """
        rows = (
            self._session.query(Image)
            .filter_by(org_id=self._org_id)
            .filter(Image.type.in_(["managed", "external"]))
            .all()
        )
        result = []
        for img in rows:
            entry: Dict = {
                "name": img.name,
                "registry": img.registry,
                "repository": img.repository,
            }
            if img.source_repo:
                entry["source"] = {
                    "provider": img.source_provider or "github",
                    "repo": img.source_repo,
                    "branch": img.source_branch or "main",
                }
                if img.source_dockerfile:
                    entry["source"]["dockerfile"] = img.source_dockerfile
            if img.tag_pattern:
                entry["allowTags"] = img.tag_pattern
            entry["autoRebuild"] = img.auto_rebuild
            entry["rebuildDelay"] = f"{img.rebuild_delay_days or 7}d"
            result.append(entry)
        logger.info(f"Loaded {len(result)} images from database (org {self._org_id})")
        return result

    def load_image_state(self, name: str) -> Optional[Dict]:
        img = self._get_image(name)
        if img is None or img.state is None:
            return None
        st = img.state
        return {
            "name": img.name,
            "currentDigest": st.current_digest,
            "currentVersion": st.current_version,
            "lastBuilt": st.last_built_at.isoformat() if st.last_built_at else None,
            "enrolledAt": img.created_at.isoformat() if img.created_at else None,
            "rebuildEligibleAt": st.rebuild_eligible_at.isoformat() if st.rebuild_eligible_at else None,
        }

    def save_image_state(self, state: Dict) -> None:
        name = state["name"]

        # Determine image type
        is_external = state.get("discoveryStatus") == "external"
        enrollment = state.get("enrollment", {})
        source = enrollment.get("source", {})

        defaults = {
            "type": "external" if is_external else "managed",
            "registry": enrollment.get("registry", "docker.io"),
            "repository": enrollment.get("repository", name),
            "source_provider": source.get("provider"),
            "source_repo": source.get("repo"),
            "source_branch": source.get("branch"),
            "source_dockerfile": source.get("dockerfile"),
            "auto_rebuild": enrollment.get("autoRebuild", True),
            "tag_pattern": state.get("allowTags"),
        }
        # Parse rebuildDelay like "7d" → 7
        rd = enrollment.get("rebuildDelay", "7d")
        if isinstance(rd, str) and rd.endswith("d"):
            try:
                defaults["rebuild_delay_days"] = int(rd[:-1])
            except ValueError:
                defaults["rebuild_delay_days"] = 7
        elif isinstance(rd, int):
            defaults["rebuild_delay_days"] = rd

        img = self._get_or_create_image(name, defaults)

        # Upsert ImageState
        now = datetime.now(timezone.utc)
        if img.state is None:
            img.state = ImageState(
                image_id=img.id,
                status=state.get("discoveryStatus", "pending"),
                current_digest=state.get("currentDigest"),
                current_version=state.get("currentVersion"),
                last_built_at=None,
                last_checked_at=now,
            )
        else:
            img.state.last_checked_at = now
            if state.get("currentDigest"):
                img.state.current_digest = state["currentDigest"]
            if state.get("currentVersion"):
                img.state.current_version = state["currentVersion"]

        self._session.flush()

    def load_base_image_state(self, name: str) -> Optional[Dict]:
        img = (
            self._session.query(Image)
            .filter_by(org_id=self._org_id, name=name, type="base")
            .first()
        )
        if img is None:
            return None
        st = img.state
        return {
            "name": img.name,
            "fullImage": f"{img.registry}/{img.repository}:{img.tag_pattern or 'latest'}",
            "registry": img.registry,
            "repository": img.repository,
            "tag": img.tag_pattern or "latest",
            "currentDigest": st.current_digest if st else None,
            "lastUpdated": st.last_checked_at.isoformat() if st and st.last_checked_at else None,
            "previousDigest": None,
            "firstDiscovered": img.created_at.isoformat() if img.created_at else None,
            "lastChecked": st.last_checked_at.isoformat() if st and st.last_checked_at else None,
            "rebuildEligibleAt": {"default": st.rebuild_eligible_at.isoformat() if st and st.rebuild_eligible_at else None},
            "metadata": {},
            "updateHistory": [],
        }

    def save_base_image_state(self, state: Dict) -> None:
        name = state["name"]
        defaults = {
            "type": "base",
            "registry": state.get("registry", "docker.io"),
            "repository": state.get("repository", name),
            "tag_pattern": state.get("tag"),
        }
        img = self._get_or_create_image(name, defaults)

        now = datetime.now(timezone.utc)
        if img.state is None:
            img.state = ImageState(
                image_id=img.id,
                status="tracking",
                current_digest=state.get("currentDigest"),
                last_checked_at=now,
            )
        else:
            img.state.last_checked_at = now
            if state.get("currentDigest"):
                img.state.current_digest = state["currentDigest"]

        self._session.flush()

    def save_dependency(self, image_name: str, base_image_name: str) -> None:
        img = self._get_image(image_name)
        base = self._get_image(base_image_name)
        if img is None or base is None:
            logger.warning(f"Cannot save dependency {image_name} -> {base_image_name}: image(s) not found")
            return

        existing = (
            self._session.query(ImageDependency)
            .filter_by(image_id=img.id, base_image_id=base.id)
            .first()
        )
        if existing is None:
            dep = ImageDependency(
                image_id=img.id,
                base_image_id=base.id,
            )
            self._session.add(dep)
            self._session.flush()
