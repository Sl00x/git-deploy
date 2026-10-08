"""Normalised JSON errors: {"error": {"code", "message", "details", "correlation_id"}}."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("udeploy.api")


class APIError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(
        self, message: str, *, details: Any = None, status_code: int | None = None, code: str | None = None
    ):
        super().__init__(message)
        self.message = message
        self.details = details
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code


class NotFound(APIError):
    status_code = 404
    code = "not_found"


class Unauthorized(APIError):
    status_code = 401
    code = "unauthorized"


class Forbidden(APIError):
    status_code = 403
    code = "forbidden"


class Conflict(APIError):
    status_code = 409
    code = "conflict"


class PolicyViolation(APIError):
    status_code = 422
    code = "policy_violation"


class PayloadTooLarge(APIError):
    status_code = 413
    code = "payload_too_large"


class RateLimited(APIError):
    status_code = 429
    code = "rate_limited"


def _body(request: Request, code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "correlation_id": getattr(request.state, "correlation_id", None),
        }
    }


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api_error(request: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(_body(request, exc.code, exc.message, exc.details), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        return JSONResponse(_body(request, "validation_error", "request validation failed", details), 422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(_body(request, "http_error", str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never echo exception text: it may contain secrets or internal details.
        log.exception(
            "unhandled error", extra={"correlation_id": getattr(request.state, "correlation_id", None)}
        )
        return JSONResponse(_body(request, "internal_error", "internal server error"), status_code=500)
