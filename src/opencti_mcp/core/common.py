import logging

from time import monotonic
from typing import Any, Callable
from uuid import uuid4

log = logging.getLogger(__name__)

class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

def validate_page(
    limit: int,
    cursor: str | None,
) -> None:
    if not 1 <= limit <= 100:
        raise ToolError(
            "INVALID_ARGUMENT",
            "limit должен быть от 1 до 100",
        )

    if cursor is not None and (
        not cursor or len(cursor) > 2048
    ):
        raise ToolError(
            "INVALID_ARGUMENT",
            "Некорректный cursor",
        )

def text_arg(
    value: str,
    name: str,
    max_length: int = 2048,
) -> str:
    value = value.strip()

    if not value or len(value) > max_length:
        raise ToolError(
            "INVALID_ARGUMENT",
            f"Некорректный параметр {name}",
        )

    return value

def filter_group(*filters: dict) -> dict:
    return {
        "mode": "and",
        "filters": list(filters),
        "filterGroups": [],
    }

def eq(key: str, values: list[str]) -> dict:
    return {
        "key": [key],
        "values": values,
        "operator": "eq",
        "mode": "or",
    }

def gte(key: str, value: str) -> dict:
    return {
        "key": [key],
        "values": [value],
        "operator": "gte",
        "mode": "or",
    }

def unpack_page(raw: Any) -> tuple[list[dict], dict]:
    if isinstance(raw, list):
        return raw, {
            "has_next_page": False,
            "next_cursor": None,
        }

    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("entities"), list)
    ):
        raise ToolError(
            "UPSTREAM_BAD_RESPONSE",
            "Неожиданный формат ответа OpenCTI",
        )

    info = raw.get("pagination") or {}
    more = bool(info.get("hasNextPage", False))

    return raw["entities"], {
        "has_next_page": more,
        "next_cursor": (
            info.get("endCursor") if more else None
        ),
    }

def summary(entity: dict) -> dict:
    def labels(key: str, field: str) -> list[str]:
        return [
            item[field]
            for item in (entity.get(key) or [])
            if isinstance(item, dict) and item.get(field)
        ]

    return {
        "id": entity.get("id"),
        "standard_id": entity.get("standard_id"),
        "entity_type": entity.get("entity_type"),
        "name": (
            entity.get("name")
            or entity.get("observable_value")
            or entity.get("value")
        ),
        "description": (
            entity.get("description") or ""
        )[:4000],
        "pattern": entity.get("pattern"),
        "observable_value": (
            entity.get("observable_value")
            or entity.get("value")
        ),
        "confidence": entity.get("confidence"),
        "created_at": entity.get("created_at"),
        "updated_at": entity.get("updated_at"),
        "valid_until": entity.get("valid_until"),
        "revoked": entity.get("revoked"),
        "labels": labels("objectLabel", "value"),
        "markings": labels(
            "objectMarking",
            "definition",
        ),
    }

def execute(
    operation: Callable[[], dict],
    request_id: str | None = None,
) -> dict:
    started = monotonic()

    if request_id is None:
        request_id = str(uuid4())

    if len(request_id) > 100:
        request_id = request_id[:100]

    try:
        payload = operation()

        result = {
            "success": True,
            "data": payload.get("data"),
            "pagination": payload.get("pagination"),
            "error": None,
        }

    except ToolError as error:
        result = {
            "success": False,
            "data": None,
            "pagination": None,
            "error": {
                "code": error.code,
                "message": error.message,
            },
        }

    except Exception as error:
        # Не возвращаем модели traceback,
        # токены и внутренние запросы OpenCTI.
        log.error(
            "OpenCTI operation failed "
            "request_id=%s exception=%s",
            request_id,
            type(error).__name__,
        )

        result = {
            "success": False,
            "data": None,
            "pagination": None,
            "error": {
                "code": "OPENCTI_ERROR",
                "message": "Ошибка обращения к OpenCTI",
            },
        }

    result["meta"] = {
        "request_id": request_id,
        "source": "opencti",
        "duration_ms": round(
            (monotonic() - started) * 1000
        ),
    }

    return result
