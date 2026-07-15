"""Lightweight HTTP client for the PromptShield Enterprise API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin


class PromptShieldClientError(RuntimeError):
    """Raised when the API returns an error response."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")


class PromptShieldClient:
    """Minimal urllib-based client (no extra HTTP dependencies).

    Args:
        base_url: API root, e.g. ``http://localhost:8000``.
        api_key: Optional value for ``X-API-Key``.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = urljoin(self.base_url, path.lstrip("/"))
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers=self._headers(),
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                if not body:
                    return {}
                parsed: object = json.loads(body)
                if not isinstance(parsed, dict):
                    return {"data": parsed}
                return {str(k): v for k, v in parsed.items()}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise PromptShieldClientError(exc.code, err_body) from exc

    def analyze(
        self,
        prompt: str,
        *,
        sanitize: bool = False,
        explain: bool = False,
    ) -> dict[str, Any]:
        """``POST /api/v1/analyze``."""
        return self._request(
            "POST",
            "/api/v1/analyze",
            {
                "prompt": prompt,
                "sanitize": sanitize,
                "explain": explain,
            },
        )

    def sanitize(self, prompt: str) -> dict[str, Any]:
        """``POST /api/v1/sanitize``."""
        return self._request("POST", "/api/v1/sanitize", {"prompt": prompt})

    def health(self) -> dict[str, Any]:
        """``GET /api/v1/health``."""
        return self._request("GET", "/api/v1/health")
