"""API errors with German messages (docs/api.md → Conventions)."""

from __future__ import annotations

NOT_READY = "Der Dateiserver ist noch nicht eingerichtet."
CHECK_INPUT = "Bitte Eingaben prüfen."


class ApiError(Exception):
    def __init__(self, status: int, message: str, fields: dict | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.fields = fields

    def body(self) -> dict:
        out: dict = {"error": self.message}
        if self.fields:
            out["fields"] = self.fields
        return out


def invalid(fields: dict) -> ApiError:
    return ApiError(422, CHECK_INPUT, fields)


def not_found(message: str = "Nicht gefunden.") -> ApiError:
    return ApiError(404, message)


def conflict(message: str) -> ApiError:
    return ApiError(409, message)


def forbidden(message: str) -> ApiError:
    return ApiError(403, message)


class Fields(dict):
    """Collects field errors; the first error per field wins."""

    def add(self, field: str, message: str | None) -> None:
        if message and field not in self:
            self[field] = message

    def raise_if_any(self) -> None:
        if self:
            raise invalid(dict(self))
