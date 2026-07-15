"""FastAPI application factory for PromptShield Enterprise API."""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from promptshield.api.admin_routes import router as admin_router
from promptshield.api.auth import validate_startup_auth
from promptshield.api.dashboard_routes import router as dashboard_api_router
from promptshield.api.routes import router
from promptshield.dashboard.auth import warn_if_open
from promptshield.dashboard.pages import router as dashboard_pages_router
from promptshield.service import _package_version

logger = logging.getLogger("promptshield.api")


def _configure_json_logging() -> None:
    """Configure structured JSON logging when python-json-logger is available."""
    root = logging.getLogger()
    if root.handlers:
        # Avoid double-config in reload / tests
        return
    try:
        from pythonjsonlogger.json import JsonFormatter
    except ImportError:
        try:
            from pythonjsonlogger.jsonlogger import JsonFormatter  # type: ignore
        except ImportError:
            logging.basicConfig(
                level=logging.INFO,
                format="%(levelname)s %(name)s: %(message)s",
            )
            return

    handler = logging.StreamHandler()
    formatter = JsonFormatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s %(request_id)s"
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(logging.INFO)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Propagate or generate ``X-Request-ID`` on every response."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


def _cors_origins() -> list[str]:
    raw = os.environ.get(
        "PROMPTSHIELD_CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173",
    )
    return [o.strip() for o in raw.split(",") if o.strip()]


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    _configure_json_logging()
    validate_startup_auth()
    warn_if_open()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "PromptShield Enterprise API starting version=%s env=%s",
            _package_version(),
            os.environ.get("PROMPTSHIELD_ENV", "development"),
        )
        # Ensure schema exists when persistence is enabled
        if os.environ.get("PROMPTSHIELD_PERSISTENCE", "1").strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }:
            try:
                from promptshield.persistence.database import init_db
                from promptshield.persistence.tenancy import seed_default_tenancy

                init_db()
                seed_default_tenancy()
            except Exception:
                logger.exception("Failed to initialize persistence / tenancy seed")
        yield

    app = FastAPI(
        title="PromptShield Enterprise API",
        version=_package_version(),
        description=(
            "REST API for LLM prompt firewall: detection, risk scoring, "
            "policy decisions, sanitization, and explainability."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestIdMiddleware)
    app.include_router(router)
    app.include_router(admin_router)
    app.include_router(dashboard_api_router)
    app.include_router(dashboard_pages_router)

    return app


# ASGI entrypoint: ``uvicorn promptshield.api.app:app``
app = create_app()
