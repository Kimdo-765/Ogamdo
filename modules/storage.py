"""Dependency-light storage primitives shared by API and worker runtimes.

Keep this module limited to the standard library: worker containers mount the
``modules`` package, but intentionally do not mount the FastAPI ``api`` package.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path


DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"
UPLOADS_DIR = DATA_DIR / "uploads"


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def extract_if_archive(path: Path) -> Path:
    """Extract an archive beside ``path``; otherwise return its parent directory.

    Delegates to `modules.ingest_placement.safe_extract`, which enforces the
    size, entry-count, ratio, traversal and symlink limits this function used
    to have none of: a 499 KB zip reached 524 MB through the bare
    `extractall` that lived here, and the three `/analyze` routes that call it
    had no protection at all. Raises `UnsafeArchive` when the archive asks for
    something an ingest must not do; callers turn that into a 400 rather than
    a half-extracted job directory.

    Detection is by MAGIC now, not by suffix — a challenge that names its zip
    `flag.png` is a normal challenge, and the old `.zip` check missed it.

    The import is deferred because `ingest_placement` imports this module.
    """
    from modules.ingest_placement import is_archive, safe_extract

    if is_archive(path):
        out = path.parent / "extracted"
        safe_extract(path, out)
        return out
    return path.parent


__all__ = [
    "DATA_DIR",
    "JOBS_DIR",
    "UPLOADS_DIR",
    "extract_if_archive",
    "new_job_id",
]
