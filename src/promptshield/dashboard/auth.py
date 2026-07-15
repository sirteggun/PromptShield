"""Authentication for HTML dashboard routes and dashboard JSON APIs."""

from __future__ import annotations

import logging
import os

from fastapi import Header, HTTPException, Query, Request, status

logger = logging.getLogger(__name__)
_warned = False


def dashboard_key() -> str | None:
    """Return configured dashboard key, or None if open access."""
    raw = os.environ.get("PROMPTSHIELD_DASHBOARD_KEY", "").strip()
    return raw or None


def warn_if_open() -> None:
    """Log a one-time warning when dashboard auth is disabled."""
    global _warned
    if dashboard_key() is None and not _warned:
        logger.warning(
            "PROMPTSHIELD_DASHBOARD_KEY not set — dashboard is publicly "
            "accessible (development only)."
        )
        _warned = True


async def require_dashboard_access(
    request: Request,
    x_dashboard_key: str | None = Header(default=None, alias="X-Dashboard-Key"),
    key: str | None = Query(default=None, description="Dashboard key (query)"),
) -> None:
    """Enforce dashboard access via header or ``?key=``.

    If ``PROMPTSHIELD_DASHBOARD_KEY`` is unset, access is allowed (with warning).
    """
    expected = dashboard_key()
    if expected is None:
        warn_if_open()
        return
    provided = x_dashboard_key or key or request.cookies.get("ps_dashboard_key")
    if not provided or provided != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing dashboard key "
            "(X-Dashboard-Key header or ?key= query parameter)",
        )
