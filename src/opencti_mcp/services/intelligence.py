from datetime import UTC, datetime, timedelta

from opencti_mcp.core.common import (
    ToolError,
    eq,
    filter_group,
    gte,
    summary,
    text_arg,
    unpack_page,
    validate_page,
)

ALLOWED_TYPES = {
    "Indicator",
    "Report",
    "Malware",
    "Campaign",
    "Intrusion-Set",
    "Threat-Actor-Group",
    "Threat-Actor-Individual",
    "Attack-Pattern",
    "Infrastructure",
    "Tool",
    "Vulnerability",
    "Incident",
    "Course-Of-Action",
    "Observed-Data",
    "Identity",
    "Note",
}

OBSERVABLE_TYPES = {
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Url",
    "Email-Addr",
}

class IntelligenceService:
    def __init__(self, factory):
        self.factory = factory

    def search_entities(
        self,
        query: str,
        entity_types: list[str] | None,
        limit: int,
        cursor: str | None,
    ) -> dict:
        validate_page(limit, cursor)

        query = text_arg(query, "query", 256)

        if entity_types and (
            len(entity_types) > 20
            or set(entity_types) - ALLOWED_TYPES
        ):
            raise ToolError(
                "INVALID_ARGUMENT",
                "Неизвестный или недопустимый entity_type",
            )

        c = self.factory.create()

        raw = c.stix_core_object.list(
            types=entity_types or None,
            search=query,
            first=limit,
            after=cursor,
            withPagination=True,
            getAll=False,
        )

        items, page = unpack_page(raw)

        return {
            "data": {
                "items": [summary(x) for x in items],
            },
            "pagination": page,
        }

    def get_entity(self, entity_id: str) -> dict:
        entity_id = text_arg(
            entity_id,
            "entity_id",
            200,
        )

        c = self.factory.create()

        entity = c.stix_core_object.read(
            id=entity_id,
        )

        if entity is None:
            entity = c.stix_cyber_observable.read(
                id=entity_id,
            )

        if entity is None:
            raise ToolError(
                "NOT_FOUND",
                "Сущность не найдена или недоступна",
            )

        return {
            "data": summary(entity),
        }

    def _find_observable(
        self,
        c,
        value: str,
        observable_type: str,
    ) -> dict:
        if observable_type not in OBSERVABLE_TYPES:
            raise ToolError(
                "INVALID_ARGUMENT",
                "Неподдерживаемый тип Observable",
            )

        value = text_arg(value, "value", 2048)

        raw = c.stix_cyber_observable.list(
            types=[observable_type],
            filters=filter_group(
                eq("value", [value]),
            ),
            first=20,
            withPagination=True,
            getAll=False,
        )

        items, pagination = unpack_page(raw)

        exact = [
            summary(x)
            for x in items
            if str(
                x.get("observable_value")
                or x.get("value")
                or ""
            ).casefold() == value.casefold()
        ]

        return {
            "value": value,
            "observable_type": observable_type,
            "matched": bool(exact),
            "items": exact,
            "has_more_matches": pagination[
                "has_next_page"
            ],
        }

    def lookup_observable(
        self,
        value: str,
        observable_type: str,
    ) -> dict:
        c = self.factory.create()

        return {
            "data": self._find_observable(
                c,
                value,
                observable_type,
            ),
        }

    def bulk_lookup_iocs(
        self,
        items: list[dict],
    ) -> dict:
        if not 1 <= len(items) <= 100:
            raise ToolError(
                "INVALID_ARGUMENT",
                "Количество IoC должно быть от 1 до 100",
            )

        c = self.factory.create()
        results = []

        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise ToolError(
                    "INVALID_ARGUMENT",
                    f"Некорректный элемент #{i}",
                )

            try:
                results.append(
                    self._find_observable(
                        c,
                        item["value"],
                        item["observable_type"],
                    )
                )

            except (KeyError, TypeError, ToolError):
                results.append({
                    "value": item.get("value"),
                    "observable_type": item.get(
                        "observable_type"
                    ),
                    "matched": None,
                    "error": "INVALID_ITEM",
                })

        return {
            "data": {
                "items": results,
            },
        }

    def search_indicators(
        self,
        query: str,
        limit: int,
        cursor: str | None,
    ) -> dict:
        validate_page(limit, cursor)

        c = self.factory.create()

        raw = c.indicator.list(
            search=text_arg(
                query,
                "query",
                256,
            ),
            first=limit,
            after=cursor,
            withPagination=True,
            getAll=False,
        )

        items, page = unpack_page(raw)

        return {
            "data": {
                "items": [summary(x) for x in items],
            },
            "pagination": page,
        }

    def get_recent_intelligence(
        self,
        hours: int,
        limit: int,
        cursor: str | None,
    ) -> dict:
        validate_page(limit, cursor)

        if not 1 <= hours <= 720:
            raise ToolError(
                "INVALID_ARGUMENT",
                "hours должен быть от 1 до 720",
            )

        since = (
            datetime.now(UTC)
            - timedelta(hours=hours)
        ).isoformat().replace("+00:00", "Z")

        c = self.factory.create()

        raw = c.stix_core_object.list(
            types=[
                "Report",
                "Indicator",
                "Malware",
                "Campaign",
                "Intrusion-Set",
                "Threat-Actor-Group",
            ],
            filters=filter_group(
                gte("created_at", since),
            ),
            orderBy="created_at",
            orderMode="desc",
            first=limit,
            after=cursor,
            withPagination=True,
            getAll=False,
        )

        items, page = unpack_page(raw)

        return {
            "data": {
                "since": since,
                "items": [
                    summary(x) for x in items
                ],
            },
            "pagination": page,
        }
