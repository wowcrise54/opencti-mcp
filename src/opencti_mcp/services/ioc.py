import csv
import io
import json
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from opencti_mcp.core.common import ToolError, eq, filter_group, gte, text_arg, unpack_page, validate_page


def _date(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is not None:
            return parsed
    except ValueError:
        pass
    raise ToolError("INVALID_DATE", "Expected an ISO 8601 datetime with a timezone")


def _active(item: dict, now: datetime) -> bool:
    start = _date(item.get("valid_from"))
    end = _date(item.get("valid_until"))
    return not item.get("revoked") and (start is None or start <= now) and (end is None or now < end)


def _record(item: dict, kind: str, active: bool | None) -> dict:
    return {
        "id": item["id"],
        "standard_id": item.get("standard_id"),
        "kind": kind,
        "observable_type": item.get("x_opencti_main_observable_type") or item.get("entity_type"),
        "value": item.get("observable_value"),
        "pattern": item.get("pattern"),
        "score": item.get("x_opencti_score"),
        "confidence": item.get("confidence"),
        "labels": [label["value"] for label in item.get("objectLabel") or []],
        "markings": [marking["definition"] for marking in item.get("objectMarking") or []],
        "valid_until": item.get("valid_until"),
        "revoked": item.get("revoked"),
        "activity": "not_applicable" if active is None else "active" if active else "inactive",
    }


def _csv(items: list[dict]) -> str:
    output = io.StringIO(newline="")
    fields = tuple(_record({"id": None}, "indicator", None))
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for item in items:
        row = {}
        for key, value in item.items():
            if isinstance(value, list):
                value = json.dumps(value, ensure_ascii=False)
            if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                value = "'" + value
            row[key] = value
        writer.writerow(row)
    return output.getvalue()


class IoCService:
    def __init__(self, factory):
        self.factory = factory

    @staticmethod
    def _label_filter(client, labels: list[str]) -> dict:
        if not 1 <= len(labels) <= 20:
            raise ToolError("INVALID_ARGUMENT", "Supply between 1 and 20 labels")
        ids = []
        for name in dict.fromkeys(text_arg(label, "label", 80) for label in labels):
            label = client.label.read(filters=filter_group(eq("value", [name])))
            if not label:
                raise ToolError("LABEL_NOT_FOUND", "A requested label was not found")
            ids.append(label["id"])
        return eq("objectLabel", ids)

    @staticmethod
    def _page(
        client, kind, filters, observable_types, min_score, min_confidence, active_only, limit, cursor,
    ):
        for bound in (min_score, min_confidence):
            if bound is not None and not 0 <= bound <= 100:
                raise ToolError("INVALID_ARGUMENT", "Score and confidence must be between 0 and 100")
        if observable_types and len(observable_types) > 20:
            raise ToolError("INVALID_ARGUMENT", "Supply at most 20 observable types")

        handler = client.indicator if kind == "indicator" else client.stix_cyber_observable
        items, page = unpack_page(handler.list(
            filters=filter_group(*filters), first=limit, after=cursor,
            withPagination=True, getAll=False,
        ))
        now = datetime.now(UTC)
        records = []
        for item in items:
            active = _active(item, now) if kind == "indicator" else None
            record = _record(item, kind, active)
            if observable_types and record["observable_type"] not in observable_types:
                continue
            if min_score is not None and (record["score"] is None or record["score"] < min_score):
                continue
            if min_confidence is not None and (
                record["confidence"] is None or record["confidence"] < min_confidence
            ):
                continue
            if active_only and active is False:
                continue
            records.append(record)
        return records, page

    def by_label(
        self, label, object_kinds, observable_types, min_score, min_confidence, active_only, limit, cursor,
    ) -> dict:
        validate_page(limit, cursor)
        kinds = list(dict.fromkeys(object_kinds or ["indicator", "observable"]))
        kind, upstream = kinds[0], None
        if cursor is not None:
            kind, sep, upstream = cursor.partition(":")
            if not sep or kind not in kinds:
                raise ToolError("INVALID_ARGUMENT", "Invalid IoC cursor")
        client = self.factory.create()
        records, page = self._page(
            client, kind, [self._label_filter(client, [label])], observable_types,
            min_score, min_confidence, active_only, limit, upstream or None,
        )
        if page["next_cursor"]:
            page["next_cursor"] = f"{kind}:{page['next_cursor']}"
        elif kinds.index(kind) + 1 < len(kinds):
            page = {"has_next_page": True, "next_cursor": f"{kinds[kinds.index(kind) + 1]}:"}
        return {"data": {"items": records}, "pagination": page}

    def export(
        self, format, labels, observable_types, min_score, active_only, created_after, limit, cursor,
    ) -> dict:
        validate_page(limit, cursor)
        start = _date(created_after)
        client = self.factory.create()
        filters = [self._label_filter(client, labels)] if labels else []
        if start:
            filters.append(gte("created_at", start.isoformat()))
        records, page = self._page(
            client, "indicator", filters, observable_types, min_score, None, active_only, limit, cursor,
        )
        count = len(records)
        if format == "csv":
            content, mime = _csv(records), "text/csv"
        elif format == "stix2":
            objects = []
            seen = set()
            for item in records:
                matches = client.indicator.list(
                    filters=filter_group(eq("id", [item["id"]])), first=1, toStix=True,
                )
                raw = matches[0].get("toStix") if matches else None
                if isinstance(raw, str):
                    raw = json.loads(raw)
                if not isinstance(raw, dict) or raw.get("type") != "indicator" or not raw.get("id"):
                    raise ToolError("UPSTREAM_BAD_RESPONSE", "OpenCTI did not return a STIX indicator")
                if raw["id"] not in seen:
                    objects.append(raw)
                    seen.add(raw["id"])
            count = len(objects)
            content = json.dumps({"type": "bundle", "id": f"bundle--{uuid4()}", "objects": objects},
                                 ensure_ascii=False)
            mime = "application/stix+json"
        else:
            content, mime = json.dumps(records, ensure_ascii=False), "application/json"
        encoded = content.encode("utf-8")
        if len(encoded) > 2_000_000:
            raise ToolError("EXPORT_TOO_LARGE", "Retry with a smaller page size")
        return {"data": {"export": {
            "format": format, "content": content, "mime_type": mime,
            "count": count,
            "sha256": sha256(encoded).hexdigest(), "truncated": page["has_next_page"],
        }}, "pagination": page}

    def prepare_feed(self, labels, format, limit, cursor) -> dict:
        if not labels:
            raise ToolError("INVALID_ARGUMENT", "Supply at least one feed label")
        return self.export(format, labels, None, None, True, None, limit, cursor)
